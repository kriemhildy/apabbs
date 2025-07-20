//! Shared test helpers for integration tests.
// The "dead code" is used in other test files but not in this one.

use apabbs::{
    AppState,
    post::{
        Post, PostStatus, media,
        submission::{self, PostSubmission},
    },
    user::{Account, AccountRole, Credentials, User},
};
use axum::{Router, body::Body, http::Response};
use http_body_util::BodyExt;
use sha256;
use sqlx::PgConnection;
use std::{error::Error, path::Path};
use uuid::Uuid;

/// The local IP address (IPv6 loopback).
#[allow(dead_code)]
pub const LOCAL_IP: &str = "::1";
/// Test IP address for scrubbing.
#[allow(dead_code)]
pub const SCRUB_IP: &str = "192.0.2.0";
/// Test IP address for flooding bans.
#[allow(dead_code)]
pub const FLOOD_BAN_IP: &str = "192.0.2.1";
/// Test IP address for manual bans.
#[allow(dead_code)]
pub const MANUAL_BAN_IP: &str = "192.0.2.2";
/// Test IP address for spam bans.
#[allow(dead_code)]
pub const SPAM_BAN_IP: &str = "192.0.2.3";
/// The content type for form submissions.
#[allow(dead_code)]
pub const APPLICATION_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
/// Directory containing test media files.
pub const TEST_MEDIA_DIR: &str = "tests/media";

/// Initialize tracing, app state, and router for integration tests.
pub async fn init_test() -> (Router, AppState) {
    use apabbs::{init_app_state, init_tracing_for_test, router::init_router};

    init_tracing_for_test();
    let state = init_app_state().await;
    let router = init_router(state.clone(), false);
    (router, state)
}

/// Generate test credentials for a user.
#[allow(dead_code)]
pub fn test_credentials(user: &User) -> Credentials {
    Credentials {
        session_token: user.session_token,
        username: Uuid::new_v4().simple().to_string()[..16].to_string(),
        password: String::from("test_passw0rd"),
        confirm_password: Some(String::from("test_passw0rd")),
        year: Some("on".to_string()),
    }
}

/// Create a test user with a random session token and local IP hash.
#[allow(dead_code)]
pub fn test_user(account: Option<Account>) -> User {
    User {
        account,
        session_token: Uuid::new_v4(),
        ip_hash: local_ip_hash(),
        ..User::default()
    }
}

/// Compute the hash of the local test IP using the app secret key.
pub fn local_ip_hash() -> String {
    sha256::digest(apabbs::secret_key() + LOCAL_IP)
}

/// Create a test user account in the database with the given role.
#[allow(dead_code)]
pub async fn create_test_account(
    tx: &mut PgConnection,
    role: AccountRole,
) -> Result<User, Box<dyn Error + Send + Sync>> {
    let user = test_user(None);
    let credentials = test_credentials(&user);
    let account = credentials.register(tx, &local_ip_hash()).await?;

    let account = if role != AccountRole::Pending {
        sqlx::query("UPDATE accounts SET role = $1 WHERE id = $2")
            .bind(role)
            .bind(account.id)
            .execute(&mut *tx)
            .await
            .expect("update account role");
        Account::select_by_username(tx, &account.username)
            .await?
            .unwrap()
    } else {
        account
    };

    Ok(User {
        account: Some(account),
        session_token: user.session_token,
        ..user
    })
}

/// Delete a test account from the database by account id.
#[allow(dead_code)]
pub async fn delete_test_account(tx: &mut PgConnection, account: &Account) {
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(account.id)
        .execute(tx)
        .await
        .expect("delete account");
}

/// Create a test post in the database for a user, with optional media and status.
#[allow(dead_code)]
pub async fn create_test_post(
    tx: &mut PgConnection,
    user: &User,
    media_filename: Option<&str>,
    status: PostStatus,
) -> Post {
    use PostStatus::*;

    let media_bytes = match media_filename {
        Some(media_filename) => {
            let path = Path::new(TEST_MEDIA_DIR).join(media_filename);
            Some(tokio::fs::read(path).await.unwrap())
        }
        None => None,
    };

    let post_submission = PostSubmission {
        session_token: user.session_token,
        body: String::from("<&test body"),
        media_filename: media_filename.map(|s| s.to_string()),
        media_bytes,
    };

    let key = submission::generate_key(tx).await.unwrap();
    let post = post_submission.insert(tx, user, &key).await.unwrap();

    if let Some(bytes) = post_submission.media_bytes {
        match status {
            Pending => {
                if let Err(msg) = media::encryption::encrypt_uploaded_file(&post, bytes).await {
                    tracing::error!("{msg}");
                    std::process::exit(1);
                }
            }
            Approved | Delisted => {
                let published_media_path = post.published_media_path();
                if let Err(msg) = media::write_media_file(&published_media_path, bytes).await {
                    tracing::error!("{msg}");
                    std::process::exit(1);
                }
            }
            _ => {
                tracing::error!("Unhandled post status: {:?}", status);
                std::process::exit(1);
            }
        }
    }

    if status == Pending {
        return post;
    }

    post.update_status(tx, status).await.unwrap();
    Post::select_by_key(tx, &post.key).await.unwrap().unwrap()
}

/// Check if a response adds or removes a cookie.
pub fn response_has_cookie(response: &Response<Body>, cookie: &str, removed: bool) -> bool {
    response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .any(|h| {
            let s = h.to_str().unwrap();
            s.contains(cookie) && (removed == s.contains("Max-Age=0"))
        })
}

/// Check if a response adds a cookie.
#[allow(dead_code)]
pub fn response_adds_cookie(response: &Response<Body>, cookie: &str) -> bool {
    response_has_cookie(response, cookie, false)
}

/// Check if a response removes a cookie.
#[allow(dead_code)]
pub fn response_removes_cookie(response: &Response<Body>, cookie: &str) -> bool {
    response_has_cookie(response, cookie, true)
}

/// Extract the response body as a string.
#[allow(dead_code)]
pub async fn response_body_str(response: Response<Body>) -> String {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(body.to_vec()).unwrap()
}

/// Select the latest post by session token.
#[allow(dead_code)]
pub async fn select_latest_post_by_session_token(
    tx: &mut PgConnection,
    session_token: &Uuid,
) -> Option<Post> {
    sqlx::query_as("SELECT * FROM posts WHERE session_token = $1 ORDER BY id DESC LIMIT 1")
        .bind(session_token)
        .fetch_optional(tx)
        .await
        .expect("select latest post by session token")
}

/// Select the latest post by account id.
#[allow(dead_code)]
pub async fn select_latest_post_by_account_id(
    tx: &mut PgConnection,
    account_id: i32,
) -> Option<Post> {
    sqlx::query_as("SELECT * FROM posts WHERE account_id = $1 ORDER BY id DESC LIMIT 1")
        .bind(account_id)
        .fetch_optional(tx)
        .await
        .expect("select latest post by account id")
}

/// Delete a test ban from the database by IP hash.
#[allow(dead_code)]
pub async fn delete_test_ban(tx: &mut PgConnection, ip_hash: &str) {
    sqlx::query("DELETE FROM bans WHERE ip_hash = $1")
        .bind(ip_hash)
        .execute(tx)
        .await
        .expect("delete test ban");
}

/// Create a test spam word.
#[allow(dead_code)]
pub async fn create_test_spam_word(tx: &mut PgConnection, word: &str) {
    sqlx::query("INSERT INTO spam_words (word) VALUES ($1)")
        .bind(word)
        .execute(tx)
        .await
        .expect("insert test spam word");
}

/// Delete a test spam word.
#[allow(dead_code)]
pub async fn delete_test_spam_word(tx: &mut PgConnection, word: &str) {
    sqlx::query("DELETE FROM spam_words WHERE word = $1")
        .bind(word)
        .execute(tx)
        .await
        .expect("delete test spam word");
}
