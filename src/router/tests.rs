use super::*;
use crate::{post::MediaCategory, user::AccountRole};
use axum::{
    Router,
    body::Body,
    http::{
        Method, Request, Response, StatusCode,
        header::{CONTENT_TYPE, COOKIE, SET_COOKIE},
    },
};
use form_data_builder::FormData;
use http_body_util::BodyExt;
use sqlx::PgConnection;
use std::path::Path;
use tower::util::ServiceExt; // for `call`, `oneshot`, and `ready`

const LOCAL_IP: &'static str = "::1";
const BAN_IP: &'static str = "192.0.2.0"; // RFC 5737 TEST-NET-1
const APPLICATION_WWW_FORM_URLENCODED: &'static str = "application/x-www-form-urlencoded";
const TEST_MEDIA_DIR: &'static str = "tests/media";

//-------------------------------------------------------------------------------------------------
// test helpers
//-------------------------------------------------------------------------------------------------

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
        username: Uuid::new_v4().simple().to_string()[..16].to_owned(),
        password: String::from("test_passw0rd"),
        confirm_password_opt: Some(String::from("test_passw0rd")),
        year_opt: Some("on".to_owned()),
    }
}

fn test_user(account_opt: Option<Account>) -> User {
    User {
        account_opt,
        session_token: Uuid::new_v4(),
    }
}

fn local_ip_hash() -> String {
    sha256::digest(init::secret_key() + LOCAL_IP)
}

fn ban_ip_hash() -> String {
    sha256::digest(init::secret_key() + BAN_IP)
}

async fn create_test_account(tx: &mut PgConnection, role: AccountRole) -> User {
    let user = test_user(None);
    let credentials = test_credentials(&user);
    let account = credentials.register(tx, &local_ip_hash()).await;
    let account = if role != AccountRole::Novice {
        sqlx::query("UPDATE accounts SET role = $1 WHERE id = $2")
            .bind(role)
            .bind(account.id)
            .execute(&mut *tx)
            .await
            .expect("set account as role");
        Account::select_by_username(&mut *tx, &account.username)
            .await
            .expect("account is some")
    } else {
        account
    };
    User {
        account_opt: Some(account),
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
    media_filename_opt: Option<&str>,
    status: PostStatus,
) -> Post {
    let (media_filename_opt, media_bytes_opt) = match media_filename_opt {
        Some(media_filename) => {
            let path = Path::new(TEST_MEDIA_DIR).join(media_filename);
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
        media_filename_opt: media_filename_opt.clone(),
        media_bytes_opt,
    };
    let key = PostSubmission::generate_key(tx).await;
    let post = post_submission
        .insert(tx, &user, &local_ip_hash(), &key)
        .await;
    if media_filename_opt.is_some() {
        if let Err(msg) = post_submission.encrypt_uploaded_file(&post).await {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    }
    match status {
        PostStatus::Pending => post,
        _ => {
            post.update_status(tx, &status).await;
            Post::select_by_key(tx, &post.key)
                .await
                .expect("post is some")
        }
    }
}

fn response_has_cookie(response: &Response<Body>, cookie: &str, removed: bool) -> bool {
    response.headers().get_all(SET_COOKIE).iter().any(|h| {
        let s = h.to_str().expect("header to str");
        s.contains(cookie) && (removed == s.contains("Max-Age=0"))
    })
}

fn response_adds_cookie(response: &Response<Body>, cookie: &str) -> bool {
    response_has_cookie(response, cookie, false)
}

fn response_removes_cookie(response: &Response<Body>, cookie: &str) -> bool {
    response_has_cookie(response, cookie, true)
}

async fn response_body_str(response: Response<Body>) -> String {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(body.to_vec()).unwrap()
}

async fn select_latest_post_by_session_token(
    tx: &mut PgConnection,
    session_token: &Uuid,
) -> Option<Post> {
    sqlx::query_as("SELECT * FROM posts WHERE session_token_opt = $1 ORDER BY id DESC LIMIT 1")
        .bind(session_token)
        .fetch_optional(&mut *tx)
        .await
        .expect("select post")
}

async fn select_latest_post_by_account_id(tx: &mut PgConnection, account_id: i32) -> Option<Post> {
    sqlx::query_as("SELECT * FROM posts WHERE account_id_opt = $1 ORDER BY id DESC LIMIT 1")
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await
        .expect("select post")
}

async fn delete_test_ban(tx: &mut PgConnection, ip_hash: &str) {
    sqlx::query("DELETE FROM bans WHERE ip_hash = $1")
        .bind(ip_hash)
        .execute(&mut *tx)
        .await
        .expect("delete test ban");
}

//-------------------------------------------------------------------------------------------------
// tests
//-------------------------------------------------------------------------------------------------

#[tokio::test]
async fn not_found() {
    let (router, _state) = init_test().await;
    let request = Request::builder()
        .uri("/not-found")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn index() {
    let (router, _state) = init_test().await;
    let request = Request::builder().uri(ROOT).body(Body::empty()).unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    assert!(response_adds_cookie(&response, SESSION_COOKIE));
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains(r#"<div id="posts">"#));
    assert!(body_str.contains(&init::site_name()));
}

#[tokio::test]
async fn solo_post() {
    let (router, state) = init_test().await;
    let user = test_user(None);
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post = create_test_post(&mut tx, &user, None, PostStatus::Approved).await;
    tx.commit().await.expect(COMMIT);
    let uri = format!("/{}", &post.key);
    let request = Request::builder().uri(&uri).body(Body::empty()).unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    assert!(response_adds_cookie(&response, SESSION_COOKIE));
    let body_str = response_body_str(response).await;
    assert!(!body_str.contains(r#"<div id="posts">"#));
    let mut tx = state.db.begin().await.expect(BEGIN);
    post.delete(&mut tx).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn index_with_page() {
    let (router, state) = init_test().await;
    let user = test_user(None);
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post1 = create_test_post(&mut tx, &user, None, PostStatus::Approved).await;
    let post2 = create_test_post(&mut tx, &user, None, PostStatus::Approved).await;
    let post3 = create_test_post(&mut tx, &user, None, PostStatus::Approved).await;
    tx.commit().await.expect(COMMIT);
    let uri = format!("/page/{}", &post2.key);
    let request = Request::builder().uri(&uri).body(Body::empty()).unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    assert!(response_adds_cookie(&response, SESSION_COOKIE));
    let body_str = response_body_str(response).await;
    assert!(body_str.contains(&post1.key));
    assert!(body_str.contains(&post2.key));
    assert!(!body_str.contains(&post3.key));
    let post1_index = body_str.find(&post1.key).unwrap();
    let post2_index = body_str.find(&post2.key).unwrap();
    assert!(post2_index < post1_index);
    let mut tx = state.db.begin().await.expect(BEGIN);
    post1.delete(&mut tx).await;
    post2.delete(&mut tx).await;
    post3.delete(&mut tx).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn submit_post() {
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
    assert_eq!(post.media_filename_opt, None);
    assert_eq!(post.media_category_opt, None);
    assert_eq!(post.media_mime_type_opt, None);
    assert_eq!(post.session_token_opt, Some(user.session_token));
    assert_eq!(post.account_id_opt, None);
    assert_eq!(post.status, PostStatus::Pending);
    post.delete(&mut tx).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn submit_post_with_media() {
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
    assert_eq!(post.media_filename_opt, Some(String::from("image.jpeg")));
    assert_eq!(post.media_category_opt, Some(MediaCategory::Image));
    assert_eq!(post.media_mime_type_opt, Some(String::from("image/jpeg")));
    post.delete(&mut tx).await;
    tx.commit().await.expect(COMMIT);
    let encrypted_file_path = post.encrypted_media_path();
    PostReview::delete_upload_key_dir(&encrypted_file_path);
}

#[tokio::test]
async fn submit_post_with_account() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    tx.commit().await.expect(COMMIT);
    let account = user.account_opt.as_ref().unwrap();
    let mut form = FormData::new(Vec::new());
    form.write_field("session_token", &user.session_token.to_string())
        .unwrap();
    form.write_field("body", "<&test body").unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/submit-post")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(CONTENT_TYPE, form.content_type_header())
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(form.finish().unwrap()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    let account_post = select_latest_post_by_account_id(&mut tx, account.id)
        .await
        .unwrap();
    let anon_post = select_latest_post_by_session_token(&mut tx, &user.session_token).await;
    assert!(anon_post.is_none());
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(account_post.account_id_opt, Some(account.id));
    assert_eq!(account_post.session_token_opt, None);
    account_post.delete(&mut tx).await;
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn autoban() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = test_user(None);
    let mut credentials = test_credentials(&user);
    for _ in 0..3 {
        credentials.session_token = Uuid::new_v4();
        credentials.username = Uuid::new_v4().simple().to_string()[..16].to_owned();
        credentials.register(&mut tx, &ban_ip_hash()).await;
    }
    let mut post_submission = PostSubmission {
        session_token: user.session_token,
        body: String::from("trololol"),
        ..Default::default()
    };
    for _ in 0..5 {
        post_submission.session_token = Uuid::new_v4();
        let key = PostSubmission::generate_key(&mut tx).await;
        post_submission
            .insert(&mut tx, &user, &ban_ip_hash(), &key)
            .await;
    }
    assert_eq!(ban::new_accounts_count(&mut tx, &ban_ip_hash()).await, 3);
    assert_eq!(ban::new_posts_count(&mut tx, &ban_ip_hash()).await, 5);
    assert!(ban::exists(&mut tx, &ban_ip_hash(), None).await.is_none());
    assert!(!ban::flooding(&mut tx, &ban_ip_hash()).await);
    post_submission.session_token = Uuid::new_v4();
    let key = PostSubmission::generate_key(&mut tx).await;
    post_submission
        .insert(&mut tx, &user, &ban_ip_hash(), &key)
        .await;
    assert_eq!(ban::new_accounts_count(&mut tx, &ban_ip_hash()).await, 3);
    assert_eq!(ban::new_posts_count(&mut tx, &ban_ip_hash()).await, 6);
    assert!(ban::exists(&mut tx, &ban_ip_hash(), None).await.is_none());
    assert!(ban::flooding(&mut tx, &ban_ip_hash()).await);
    tx.commit().await.expect(COMMIT);
    let mut form = FormData::new(Vec::new());
    let bogus_session_token = Uuid::new_v4();
    form.write_field("session_token", &bogus_session_token.to_string())
        .unwrap();
    form.write_field("body", "trololol").unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/submit-post")
        .header(
            COOKIE,
            format!("{}={}", SESSION_COOKIE, bogus_session_token),
        )
        .header(CONTENT_TYPE, form.content_type_header())
        .header(X_REAL_IP, BAN_IP)
        .body(Body::from(form.finish().unwrap()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let mut tx = state.db.begin().await.expect(BEGIN);
    assert!(ban::exists(&mut tx, &ban_ip_hash(), None).await.is_some());
    assert!(!ban::flooding(&mut tx, &ban_ip_hash()).await);
    assert_eq!(ban::new_accounts_count(&mut tx, &ban_ip_hash()).await, 0);
    assert_eq!(ban::new_posts_count(&mut tx, &ban_ip_hash()).await, 0);
    delete_test_ban(&mut tx, &ban_ip_hash()).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn login_form() {
    let (router, _state) = init_test().await;
    let request = Request::builder()
        .uri("/login")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    let body_str = response_body_str(response).await;
    assert!(body_str.contains("Log in"));
}

#[tokio::test]
async fn authenticate() {
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
    assert!(response_adds_cookie(&response, ACCOUNT_COOKIE));
    let mut tx = state.db.begin().await.expect(BEGIN);
    delete_test_account(&mut tx, &account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn registration_form() {
    let (router, _state) = init_test().await;
    let request = Request::builder()
        .uri("/register")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    let body_str = response_body_str(response).await;
    assert!(body_str.contains("Register"));
}

#[tokio::test]
async fn create_account() {
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
    assert!(response_adds_cookie(&response, ACCOUNT_COOKIE));
    let mut tx = state.db.begin().await.expect(BEGIN);
    let account = Account::select_by_username(&mut tx, &credentials.username)
        .await
        .unwrap();
    delete_test_account(&mut tx, &account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn logout() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account_opt.as_ref().unwrap();
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
    assert!(response_removes_cookie(&response, ACCOUNT_COOKIE));
    let mut tx = state.db.begin().await.expect(BEGIN);
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn reset_account_token() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account_opt.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let logout = Logout {
        session_token: user.session_token,
    };
    let logout_str = serde_urlencoded::to_string(&logout).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/settings/reset-account-token")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(logout_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_removes_cookie(&response, ACCOUNT_COOKIE));
    let mut tx = state.db.begin().await.expect(BEGIN);
    let updated_account = Account::select_by_username(&mut tx, &account.username)
        .await
        .unwrap();
    assert_ne!(updated_account.token, account.token);
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn hide_post() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = test_user(None);
    let post = create_test_post(&mut tx, &user, None, PostStatus::Pending).await;
    let admin_user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = admin_user.account_opt.as_ref().unwrap();
    post.update_status(&mut tx, &PostStatus::Rejected).await;
    tx.commit().await.expect(COMMIT);
    let post_hiding = PostHiding {
        session_token: user.session_token,
        key: post.key.clone(),
    };
    let post_hiding_str = serde_urlencoded::to_string(&post_hiding).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/hide-post")
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
    delete_test_account(&mut tx, &account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn interim() {
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
    let body_str = response_body_str(response).await;
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
async fn user_profile() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account_opt.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let request = Request::builder()
        .uri(&format!("/user/{}", &account.username))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    let body_str = response_body_str(response).await;
    assert!(body_str.contains(&account.username));
    let mut tx = state.db.begin().await.expect(BEGIN);
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn settings() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account_opt.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let request = Request::builder()
        .uri("/settings")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    assert!(response_adds_cookie(&response, SESSION_COOKIE));
    let body_str = response_body_str(response).await;
    assert!(body_str.contains("Settings"));
    let mut tx = state.db.begin().await.expect(BEGIN);
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn update_time_zone() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account_opt.as_ref().unwrap();
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
async fn update_password() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account_opt.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let credentials = Credentials {
        session_token: user.session_token,
        username: account.username.clone(),
        password: String::from("new_passw0rd"),
        confirm_password_opt: Some(String::from("new_passw0rd")),
        year_opt: Some("on".to_owned()),
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
    assert!(
        credentials
            .authenticate(&mut tx)
            .await
            .is_some_and(|a| a.id == updated_account.id)
    );
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn review_post() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = test_user(None);
    let post = create_test_post(&mut tx, &user, Some("image.jpeg"), PostStatus::Pending).await;
    let encrypted_media_path = post.encrypted_media_path();
    let user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = user.account_opt.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let post_review = PostReview {
        session_token: user.session_token,
        status: PostStatus::Approved,
    };
    let post_review_str = serde_urlencoded::to_string(&post_review).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/review/{}", &post.key))
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(post_review_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("post is some");
    let uploads_key_dir = encrypted_media_path.parent().unwrap();
    assert!(!uploads_key_dir.exists());
    let published_media_path = post.published_media_path();
    assert!(published_media_path.exists());
    let thumbnail_path = post.thumbnail_path();
    assert!(thumbnail_path.exists());
    PostReview::delete_media_key_dir(&post.key);
    post.delete(&mut tx).await;
    delete_test_account(&mut tx, &account).await;
    tx.commit().await.expect(COMMIT);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn review_post_with_small_media() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = test_user(None);
    let post = create_test_post(&mut tx, &user, Some("small.png"), PostStatus::Pending).await;
    let user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = user.account_opt.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let post_review = PostReview {
        session_token: user.session_token,
        status: PostStatus::Approved,
    };
    let post_review_str = serde_urlencoded::to_string(&post_review).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/review/{}", &post.key))
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(post_review_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("post is some");
    let encrypted_media_path = post.encrypted_media_path();
    let uploads_key_dir = encrypted_media_path.parent().unwrap();
    assert!(!uploads_key_dir.exists());
    assert!(post.published_media_path().exists());
    assert!(post.thumbnail_opt.is_none());
    let (_thumbnail_filename, thumbnail_path) = PostReview::new_thumbnail_info(&post);
    assert!(!thumbnail_path.exists());
    PostReview::delete_media_key_dir(&post.key);
    post.delete(&mut tx).await;
    delete_test_account(&mut tx, &account).await;
    tx.commit().await.expect(COMMIT);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn decrypt_media() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let anon_user = test_user(None);
    let post = create_test_post(&mut tx, &anon_user, Some("image.jpeg"), PostStatus::Pending).await;
    let encrypted_media_path = post.encrypted_media_path();
    let user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = user.account_opt.as_ref().unwrap();
    tx.commit().await.expect(COMMIT);
    let key = format!("/decrypt-media/{}", &post.key);
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
    assert_eq!(content_disposition, r#"inline; filename="image.jpeg""#);
    let mut tx = state.db.begin().await.expect(BEGIN);
    post.delete(&mut tx).await;
    delete_test_account(&mut tx, &account).await;
    tx.commit().await.expect(COMMIT);
    PostReview::delete_upload_key_dir(&encrypted_media_path);
}
