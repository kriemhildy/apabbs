//! Shared test helpers for integration tests.

use apabbs::{
    AppState,
    post::{Post, PostStatus, submission::PostSubmission},
    user::{Account, AccountRole, Credentials, User},
};
use axum::{Router, body::Body, http::Response};
use http_body_util::BodyExt;
use sha256;
use sqlx::PgConnection;
use std::path::Path;
use uuid::Uuid;

pub const LOCAL_IP: &str = "::1";
pub const BAN_IP: &str = "192.0.2.0";
pub const APPLICATION_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
pub const TEST_MEDIA_DIR: &str = "tests/media";

pub async fn init_test() -> (Router, AppState) {
    use apabbs::{app_state, init_tracing_for_test, router::router};

    init_tracing_for_test();
    let state = app_state().await;
    let router = router(state.clone(), false);
    (router, state)
}

pub fn test_credentials(user: &User) -> Credentials {
    Credentials {
        session_token: user.session_token,
        username: Uuid::new_v4().simple().to_string()[..16].to_string(),
        password: String::from("test_passw0rd"),
        confirm_password: Some(String::from("test_passw0rd")),
        year: Some("on".to_string()),
    }
}

pub fn test_user(account: Option<Account>) -> User {
    User {
        account,
        session_token: Uuid::new_v4(),
        ip_hash: local_ip_hash(),
        ..User::default()
    }
}

pub fn local_ip_hash() -> String {
    sha256::digest(apabbs::secret_key() + LOCAL_IP)
}

pub async fn create_test_account(tx: &mut PgConnection, role: AccountRole) -> User {
    let user = test_user(None);
    let credentials = test_credentials(&user);
    let account = credentials
        .register(tx, &local_ip_hash())
        .await
        .expect("query succeeds");

    let account = if role != AccountRole::Novice {
        sqlx::query("UPDATE accounts SET role = $1 WHERE id = $2")
            .bind(role)
            .bind(account.id)
            .execute(&mut *tx)
            .await
            .expect("sets account as role");
        Account::select_by_username(tx, &account.username)
            .await
            .expect("query succeeds")
            .unwrap()
    } else {
        account
    };

    User {
        account: Some(account),
        session_token: user.session_token,
        ..user
    }
}

pub async fn delete_test_account(tx: &mut PgConnection, account: &Account) {
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(account.id)
        .execute(tx)
        .await
        .expect("deletes test account");
}

pub async fn create_test_post(
    tx: &mut PgConnection,
    user: &User,
    media_filename: Option<&str>,
    status: PostStatus,
) -> Post {
    let (media_filename, media_bytes) = match media_filename {
        Some(media_filename) => {
            let path = Path::new(TEST_MEDIA_DIR).join(media_filename);
            (
                Some(path.file_name().unwrap().to_str().unwrap().to_string()),
                Some(tokio::fs::read(path).await.expect("reads test media file")),
            )
        }
        None => (None, None),
    };

    let post_submission = PostSubmission {
        session_token: user.session_token,
        body: String::from("<&test body"),
        media_filename: media_filename.clone(),
        media_bytes,
    };

    let key = PostSubmission::generate_key(tx)
        .await
        .expect("query succeeds");
    let post = post_submission
        .insert(tx, user, &key)
        .await
        .expect("query succeeds");

    if media_filename.is_some() {
        if let Err(msg) = post_submission.encrypt_uploaded_file(&post).await {
            tracing::error!("{msg}");
            std::process::exit(1);
        }
    }

    match status {
        PostStatus::Pending => post,
        _ => {
            post.update_status(tx, status)
                .await
                .expect("query succeeds");
            Post::select_by_key(tx, &post.key)
                .await
                .expect("query succeeds")
                .expect("post exists")
        }
    }
}

pub fn response_has_cookie(response: &Response<Body>, cookie: &str, removed: bool) -> bool {
    response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .any(|h| {
            let s = h.to_str().expect("converts header");
            s.contains(cookie) && (removed == s.contains("Max-Age=0"))
        })
}

pub fn response_adds_cookie(response: &Response<Body>, cookie: &str) -> bool {
    response_has_cookie(response, cookie, false)
}

pub fn response_removes_cookie(response: &Response<Body>, cookie: &str) -> bool {
    response_has_cookie(response, cookie, true)
}

pub async fn response_body_str(response: Response<Body>) -> String {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(body.to_vec()).unwrap()
}

pub async fn select_latest_post_by_session_token(
    tx: &mut PgConnection,
    session_token: &Uuid,
) -> Option<Post> {
    sqlx::query_as("SELECT * FROM posts WHERE session_token = $1 ORDER BY id DESC LIMIT 1")
        .bind(session_token)
        .fetch_optional(tx)
        .await
        .expect("selects by session token")
}

pub async fn select_latest_post_by_account_id(
    tx: &mut PgConnection,
    account_id: i32,
) -> Option<Post> {
    sqlx::query_as("SELECT * FROM posts WHERE account_id = $1 ORDER BY id DESC LIMIT 1")
        .bind(account_id)
        .fetch_optional(tx)
        .await
        .expect("selects by account id")
}

pub async fn delete_test_ban(tx: &mut PgConnection, ip_hash: &str) {
    sqlx::query("DELETE FROM bans WHERE ip_hash = $1")
        .bind(ip_hash)
        .execute(tx)
        .await
        .expect("deletes ban");
}
