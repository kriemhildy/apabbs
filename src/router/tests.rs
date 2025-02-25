use super::*;
use crate::post::PostMediaCategory;
use axum::{
    body::Body,
    http::{
        header::{CONTENT_TYPE, COOKIE, SET_COOKIE},
        Method, Request, Response, StatusCode,
    },
    Router,
};
use form_data_builder::FormData;
use http_body_util::BodyExt;
use sqlx::PgConnection;
use std::path::Path;
use tower::util::ServiceExt; // for `call`, `oneshot`, and `ready`

const LOCAL_IP: &'static str = "::1";
const APPLICATION_WWW_FORM_URLENCODED: &'static str = "application/x-www-form-urlencoded";
const TEST_MEDIA_DIR: &'static str = "tests/media";

///////////////////////////////////////////////////////////////////////////////////////////////////
/// test helpers
///////////////////////////////////////////////////////////////////////////////////////////////////

async fn init_test() -> (Router, AppState) {
    if !init::dev() {
        panic!("not in dev mode");
    }
    let state = init::app_state().await;
    let router = router(state.clone(), false);
    (router, state)
}

fn test_credentials(user: &User) -> Credentials {
    Credentials {
        session_token: user.session_token,
        username: Uuid::new_v4().simple().to_string()[..16].to_string(),
        password: String::from("test_password"),
        confirm_password: Some(String::from("test_password")),
        year: Some("on".to_string()),
    }
}

fn test_user(account: Option<Account>) -> User {
    User {
        account,
        session_token: Uuid::new_v4(),
    }
}

fn local_ip_hash() -> String {
    sha256::digest(init::secret_key() + LOCAL_IP)
}

async fn create_test_account(tx: &mut PgConnection, admin: bool) -> User {
    let user = test_user(None);
    let credentials = test_credentials(&user);
    let account = credentials.register(tx, &local_ip_hash()).await;
    let account = if admin {
        sqlx::query("UPDATE accounts SET admin = $1 WHERE id = $2")
            .bind(true)
            .bind(account.id)
            .execute(&mut *tx)
            .await
            .expect("set account as admin");
        Account::select_by_username(&mut *tx, &account.username)
            .await
            .expect("select account")
    } else {
        account
    };
    User {
        account: Some(account),
        session_token: user.session_token,
    }
}

async fn delete_test_account(tx: &mut PgConnection, account: &Account) {
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(account.id)
        .execute(&mut *tx)
        .await
        .expect("delete test account");
}

async fn create_test_post(
    tx: &mut PgConnection,
    user: &User,
    media_file_name: Option<&str>,
    status: PostStatus,
) -> Post {
    let (media_file_name, media_bytes) = match media_file_name {
        Some(media_file_name) => {
            let path = Path::new(TEST_MEDIA_DIR).join(media_file_name);
            (
                Some(path.file_name().unwrap().to_str().unwrap().to_owned()),
                Some(std::fs::read(path).expect("read test image file")),
            )
        }
        None => (None, None),
    };
    let post_submission = PostSubmission {
        session_token: user.session_token,
        body: String::from("<&test body"),
        media_file_name: media_file_name.clone(),
        media_bytes,
    };
    let post = post_submission.insert(tx, &user, &local_ip_hash()).await;
    if media_file_name.is_some() {
        if let Err(msg) = post_submission.save_encrypted_media_file(&post.key).await {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    }
    match status {
        PostStatus::Pending => post,
        _ => {
            PostReview {
                session_token: user.session_token,
                key: post.key.clone(),
                status,
            }
            .update_status(tx)
            .await;
            Post::select_by_key(tx, &post.key)
                .await
                .expect("select post")
        }
    }
}

fn response_has_cookie(response: &Response<Body>, cookie: &str) -> bool {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .any(|h| h.to_str().unwrap().contains(cookie))
}

fn remove_encrypted_file(encrypted_file_path: &Path) {
    println!("removing encrypted file: {:?}", encrypted_file_path);
    let uploads_key_dir = encrypted_file_path.parent().unwrap();
    std::fs::remove_file(&encrypted_file_path).expect("remove encrypted file");
    std::fs::remove_dir(&uploads_key_dir).expect("remove uploads key dir");
}

async fn select_latest_post_by_session_token(
    tx: &mut PgConnection,
    session_token: &Uuid,
) -> Option<Post> {
    sqlx::query_as("SELECT * FROM posts WHERE session_token = $1 ORDER BY id DESC LIMIT 1")
        .bind(session_token)
        .fetch_optional(&mut *tx)
        .await
        .expect("select post")
}

async fn select_latest_post_by_username(tx: &mut PgConnection, username: &str) -> Option<Post> {
    sqlx::query_as("SELECT * FROM posts WHERE username = $1 ORDER BY id DESC LIMIT 1")
        .bind(username)
        .fetch_optional(&mut *tx)
        .await
        .expect("select post")
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// tests
///////////////////////////////////////////////////////////////////////////////////////////////////

#[tokio::test]
async fn test_not_found() {
    let (router, _state) = init_test().await;
    let request = Request::builder()
        .uri("/not-found")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_index() {
    let (router, _state) = init_test().await;
    let request = Request::builder().uri(ROOT).body(Body::empty()).unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    assert!(response_has_cookie(&response, SESSION_COOKIE));
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains(&init::site_name()));
}

#[tokio::test]
async fn test_submit_post() {
    let (router, state) = init_test().await;
    let user = test_user(None);
    let mut form = FormData::new(Vec::new());
    form.write_field("session_token", &user.session_token.to_string())
        .unwrap();
    form.write_field("body", "<&test body").unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/submit-post")
        .header(
            COOKIE,
            format!("{}={}", SESSION_COOKIE, &user.session_token),
        )
        .header(CONTENT_TYPE, form.content_type_header())
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(form.finish().unwrap()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post = select_latest_post_by_session_token(&mut tx, &user.session_token)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(post.body, "&lt;&amp;test body");
    assert_eq!(post.media_file_name, None);
    assert_eq!(post.media_category, None);
    assert_eq!(post.media_mime_type, None);
    assert_eq!(post.session_token, Some(user.session_token));
    assert_eq!(post.account_id, None);
    assert_eq!(post.username, None);
    assert_eq!(post.status, PostStatus::Pending);
    post.delete(&mut tx).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_submit_post_with_media() {
    let (router, state) = init_test().await;
    let user = test_user(None);
    let mut form = FormData::new(Vec::new());
    let test_image_path = Path::new(TEST_MEDIA_DIR).join("image.jpeg");
    form.write_field("session_token", &user.session_token.to_string())
        .unwrap();
    form.write_field("body", "").unwrap();
    form.write_path("media", test_image_path, "image/jpeg")
        .unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/submit-post")
        .header(
            COOKIE,
            format!("{}={}", SESSION_COOKIE, &user.session_token),
        )
        .header(CONTENT_TYPE, form.content_type_header())
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(form.finish().unwrap()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post = select_latest_post_by_session_token(&mut tx, &user.session_token)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(post.body, "");
    assert_eq!(post.media_file_name, Some(String::from("image.jpeg")));
    assert_eq!(post.media_category, Some(PostMediaCategory::Image));
    assert_eq!(post.media_mime_type, Some(String::from("image/jpeg")));
    post.delete(&mut tx).await;
    tx.commit().await.expect(COMMIT);
    let encrypted_file_path = post.encrypted_media_path();
    remove_encrypted_file(&encrypted_file_path);
}

#[tokio::test]
async fn test_submit_post_with_account() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = create_test_account(&mut tx, false).await;
    tx.commit().await.expect(COMMIT);
    let account = user.account.as_ref().unwrap();
    let mut form = FormData::new(Vec::new());
    form.write_field("session_token", &user.session_token.to_string())
        .unwrap();
    form.write_field("body", "<&test body").unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/submit-post")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, form.content_type_header())
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(form.finish().unwrap()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    let account_post = select_latest_post_by_username(&mut tx, &account.username)
        .await
        .unwrap();
    let anon_post = select_latest_post_by_session_token(&mut tx, &user.session_token).await;
    assert!(anon_post.is_none());
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(account_post.account_id, Some(account.id));
    assert_eq!(account_post.session_token, None);
    account_post.delete(&mut tx).await;
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_login_form() {
    let (router, _state) = init_test().await;
    let request = Request::builder()
        .uri("/login")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("Log in"));
}

#[tokio::test]
async fn test_authenticate() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = test_user(None);
    let credentials = test_credentials(&user);
    let account = credentials.register(&mut tx, &local_ip_hash()).await;
    tx.commit().await.expect(COMMIT);
    let creds_str = serde_urlencoded::to_string(&credentials).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(
            COOKIE,
            format!("{}={}", SESSION_COOKIE, &user.session_token),
        )
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(creds_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_has_cookie(&response, ACCOUNT_COOKIE));
    let mut tx = state.db.begin().await.expect(BEGIN);
    delete_test_account(&mut tx, &account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_registration_form() {
    let (router, _state) = init_test().await;
    let request = Request::builder()
        .uri("/register")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("Register"));
}

#[tokio::test]
async fn test_create_account() {
    let (router, state) = init_test().await;
    let user = test_user(None);
    let credentials = test_credentials(&user);
    let creds_str = serde_urlencoded::to_string(&credentials).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/register")
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(
            COOKIE,
            format!("{}={}", SESSION_COOKIE, &user.session_token),
        )
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(creds_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_has_cookie(&response, ACCOUNT_COOKIE));
    let mut tx = state.db.begin().await.expect(BEGIN);
    let account = Account::select_by_username(&mut tx, &credentials.username)
        .await
        .unwrap();
    delete_test_account(&mut tx, &account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_logout() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = create_test_account(&mut tx, false).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let logout = Logout {
        session_token: user.session_token,
    };
    let logout_str = serde_urlencoded::to_string(&logout).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/settings/logout")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(logout_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let mut tx = state.db.begin().await.expect(BEGIN);
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_hide_rejected_post() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = test_user(None);
    let post = create_test_post(&mut tx, &user, None, PostStatus::Pending).await;
    PostReview {
        session_token: user.session_token,
        key: post.key.clone(),
        status: PostStatus::Rejected,
    }
    .update_status(&mut tx)
    .await;
    tx.commit().await.expect(COMMIT);
    let post_hiding = PostHiding {
        session_token: user.session_token,
        key: post.key.clone(),
    };
    let post_hiding_str = serde_urlencoded::to_string(&post_hiding).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/hide-rejected-post")
        .header(
            COOKIE,
            format!("{}={}", SESSION_COOKIE, &user.session_token),
        )
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(post_hiding_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let mut tx = state.db.begin().await.expect(BEGIN);
    post.delete(&mut tx).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_interim() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = test_user(None);
    let post1 = create_test_post(&mut tx, &user, None, PostStatus::Approved).await;
    let post2 = create_test_post(&mut tx, &user, None, PostStatus::Approved).await;
    let post3 = create_test_post(&mut tx, &user, None, PostStatus::Approved).await;
    tx.commit().await.expect(COMMIT);
    let request = Request::builder()
        .uri(&format!("/interim/{}", &post1.key))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(!body_str.contains(&post1.key));
    assert!(body_str.contains(&post2.key));
    assert!(body_str.contains(&post3.key));
    let post2_index = body_str.find(&post2.key).unwrap();
    let post3_index = body_str.find(&post3.key).unwrap();
    assert!(post2_index < post3_index);
    let mut tx = state.db.begin().await.expect(BEGIN);
    post1.delete(&mut tx).await;
    post2.delete(&mut tx).await;
    post3.delete(&mut tx).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_user_profile() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = create_test_account(&mut tx, false).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let request = Request::builder()
        .uri(&format!("/user/{}", &account.username))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains(&account.username));
    let mut tx = state.db.begin().await.expect(BEGIN);
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_settings() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = create_test_account(&mut tx, false).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let request = Request::builder()
        .uri("/settings")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    assert!(response_has_cookie(&response, SESSION_COOKIE));
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("Settings"));
    let mut tx = state.db.begin().await.expect(BEGIN);
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_update_time_zone() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = create_test_account(&mut tx, false).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let time_zone_update = TimeZoneUpdate {
        session_token: user.session_token,
        time_zone: String::from("America/New_York"),
    };
    let time_zone_update_str = serde_urlencoded::to_string(&time_zone_update).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/settings/update-time-zone")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(time_zone_update_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let mut tx = state.db.begin().await.expect(BEGIN);
    let updated_account = Account::select_by_username(&mut tx, &account.username)
        .await
        .unwrap();
    assert_eq!(updated_account.time_zone, time_zone_update.time_zone);
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_update_password() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = create_test_account(&mut tx, false).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let credentials = Credentials {
        session_token: user.session_token,
        username: account.username.clone(),
        password: String::from("new_password"),
        confirm_password: Some(String::from("new_password")),
        year: Some("on".to_string()),
    };
    let credentials_str = serde_urlencoded::to_string(&credentials).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/settings/update-password")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(credentials_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let mut tx = state.db.begin().await.expect(BEGIN);
    let updated_account = Account::select_by_username(&mut tx, &account.username)
        .await
        .unwrap();
    assert!(credentials
        .authenticate(&mut tx)
        .await
        .is_some_and(|a| a.id == updated_account.id));
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_review_post() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = test_user(None);
    let post = create_test_post(&mut tx, &user, Some("image.jpeg"), PostStatus::Pending).await;
    let encrypted_media_path = post.encrypted_media_path();
    let user = create_test_account(&mut tx, true).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let post_review = PostReview {
        session_token: user.session_token,
        key: post.key.clone(),
        status: PostStatus::Approved,
    };
    let post_review_str = serde_urlencoded::to_string(&post_review).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/admin/review-post")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(post_review_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("select post");
    let uploads_key_dir = encrypted_media_path.parent().unwrap();
    assert!(!uploads_key_dir.exists());
    let published_media_path = post.published_media_path();
    assert!(published_media_path.exists());
    let thumbnail_path = post.thumbnail_path();
    assert!(thumbnail_path.exists());
    std::fs::remove_file(&published_media_path).expect("remove media file");
    std::fs::remove_file(&thumbnail_path).expect("remove thumbnail file");
    let media_key_dir = published_media_path.parent().unwrap();
    std::fs::remove_dir(&media_key_dir).expect("remove media key dir");
    post.delete(&mut tx).await;
    delete_test_account(&mut tx, &account).await;
    tx.commit().await.expect(COMMIT);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn test_review_post_with_small_media() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = test_user(None);
    let post = create_test_post(&mut tx, &user, Some("small.png"), PostStatus::Pending).await;
    let encrypted_media_path = post.encrypted_media_path();
    let user = create_test_account(&mut tx, true).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let post_review = PostReview {
        session_token: user.session_token,
        key: post.key.clone(),
        status: PostStatus::Approved,
    };
    let post_review_str = serde_urlencoded::to_string(&post_review).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/admin/review-post")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(post_review_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("select post");
    let uploads_key_dir = encrypted_media_path.parent().unwrap();
    assert!(!uploads_key_dir.exists());
    let published_media_path = post.published_media_path();
    assert!(published_media_path.exists());
    let thumbnail_path = post_review.thumbnail_path(post.media_file_name.as_ref().unwrap());
    assert!(!thumbnail_path.exists());
    std::fs::remove_file(&published_media_path).expect("remove media file");
    let media_key_dir = published_media_path.parent().unwrap();
    std::fs::remove_dir(&media_key_dir).expect("remove media key dir");
    post.delete(&mut tx).await;
    delete_test_account(&mut tx, &account).await;
    tx.commit().await.expect(COMMIT);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn test_decrypt_media() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let anon_user = test_user(None);
    let post = create_test_post(&mut tx, &anon_user, Some("image.jpeg"), PostStatus::Pending).await;
    let encrypted_media_path = post.encrypted_media_path();
    let user = create_test_account(&mut tx, true).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let key = format!("/admin/decrypt-media/{}", &post.key);
    let request = Request::builder()
        .uri(&key)
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    let content_type = response.headers().get(CONTENT_TYPE).unwrap();
    assert_eq!(content_type, "image/jpeg");
    let content_disposition = response.headers().get(CONTENT_DISPOSITION).unwrap();
    assert_eq!(content_disposition, r#"inline; file_name="image.jpeg""#);
    let mut tx = state.db.begin().await.expect(BEGIN);
    post.delete(&mut tx).await;
    delete_test_account(&mut tx, &account).await;
    tx.commit().await.expect(COMMIT);
    remove_encrypted_file(&encrypted_media_path);
}
