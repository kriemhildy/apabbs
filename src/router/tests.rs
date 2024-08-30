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
use std::path::{Path, PathBuf};
use tower::util::ServiceExt; // for `call`, `oneshot`, and `ready`

const LOCAL_IP: &'static str = "::1";
const APPLICATION_WWW_FORM_URLENCODED: &'static str = "application/x-www-form-urlencoded";

///////////////////////////////////////////////////////////////////////////////////////////////////
/// test helpers
///////////////////////////////////////////////////////////////////////////////////////////////////

async fn init_test() -> (Router, AppState) {
    if !dev() {
        panic!("not in dev mode");
    }
    let state = init::app_state().await;
    let router = router(state.clone(), false);
    (router, state)
}

fn test_credentials() -> Credentials {
    let uuid = Uuid::new_v4().simple().to_string();
    Credentials {
        username: String::from(&uuid[..16]),
        password: String::from("test_password"),
    }
}

async fn delete_account(tx: &mut PgConnection, account_id: i32) {
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .expect("delete test account");
}

async fn create_test_post(tx: &mut PgConnection, media_file_name: Option<&str>) -> (Post, User) {
    let media_file_name = match media_file_name {
        Some(name) => Some(String::from(name)),
        None => None,
    };
    let user = User {
        account: None,
        anon_token: Uuid::new_v4().hyphenated().to_string(),
    };
    let post = PostSubmission {
        body: String::from("test body"),
        anon: Some(String::from("on")),
        media_file_name: media_file_name,
        uuid: Uuid::new_v4().hyphenated().to_string(),
    }
    .insert(tx, &user, LOCAL_IP)
    .await;
    (post, user)
}

async fn mark_as_admin(tx: &mut PgConnection, account_id: i32) {
    sqlx::query("UPDATE accounts SET admin = $1 WHERE id = $2")
        .bind(true)
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .expect("set account as admin");
}

async fn create_test_cocoon(state: &AppState) -> (Post, PathBuf, Account) {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (post, _user) = create_test_post(&mut tx, Some("image.jpeg")).await;
    let cocoon_path = cocoon_path(&post);
    let cocoon_uuid_dir = cocoon_path.parent().unwrap().to_path_buf();
    std::fs::create_dir(&cocoon_uuid_dir).expect("create uuid dir");
    let mut file = File::create(&cocoon_path).expect("create file");
    let data = std::fs::read("tests/media/image.jpeg").expect("read tests/media/image.jpeg");
    let secret_key = std::env::var("SECRET_KEY").expect("read SECRET_KEY env");
    let mut cocoon = Cocoon::new(secret_key.as_bytes());
    cocoon.dump(data, &mut file).expect("dump cocoon to file");
    let admin_account = test_credentials().register(&mut tx, LOCAL_IP).await;
    mark_as_admin(&mut tx, admin_account.id).await;
    tx.commit().await.expect(COMMIT);
    (post, cocoon_path, admin_account)
}

fn response_has_cookie(response: &Response<Body>, cookie: &str) -> bool {
    response
        .headers()
        .get(SET_COOKIE)
        .is_some_and(|c| c.to_str().unwrap().contains(cookie))
}

fn remove_cocoon(cocoon_path: &Path) {
    let cocoon_uuid_dir = cocoon_path.parent().unwrap();
    std::fs::remove_file(&cocoon_path).expect("remove cocoon file");
    std::fs::remove_dir(&cocoon_uuid_dir).expect("remove uploads uuid dir");
}

fn cocoon_path(post: &Post) -> PathBuf {
    let cocoon_file_name = String::from(post.media_file_name.as_ref().unwrap()) + ".cocoon";
    Path::new(UPLOADS_DIR)
        .join(&post.uuid)
        .join(&cocoon_file_name)
        .to_path_buf()
}

async fn select_latest_post_by_token(tx: &mut PgConnection, anon_token: &str) -> Post {
    sqlx::query_as("SELECT * FROM posts WHERE anon_token = $1 ORDER BY id DESC LIMIT 1")
        .bind(anon_token)
        .fetch_one(&mut *tx)
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
    assert!(response_has_cookie(&response, ANON_COOKIE));
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains(&site_name()));
}

#[tokio::test]
async fn test_submit_post() {
    let (router, state) = init_test().await;
    let anon_token = Uuid::new_v4().hyphenated().to_string();
    let mut form = FormData::new(Vec::new());
    form.write_field("body", "<test body").unwrap();
    form.write_path("media", "tests/media/image.jpeg", "image/jpeg")
        .unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/post")
        .header(COOKIE, format!("{}={}", ANON_COOKIE, &anon_token))
        .header(CONTENT_TYPE, form.content_type_header())
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(form.finish().unwrap()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post = select_latest_post_by_token(&mut tx, &anon_token).await;
    post.delete(&mut tx).await;
    tx.commit().await.expect(COMMIT);
    let cocoon_path = cocoon_path(&post);
    remove_cocoon(&cocoon_path);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(post.body, "&lt;test body");
    assert_eq!(post.media_file_name, Some(String::from("image.jpeg")));
    assert_eq!(post.media_category, Some(PostMediaCategory::Image));
    assert_eq!(post.media_mime_type, Some(String::from("image/jpeg")));
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
    let credentials = test_credentials();
    let account = credentials.register(&mut tx, LOCAL_IP).await;
    tx.commit().await.expect(COMMIT);
    let creds_str = serde_urlencoded::to_string(&credentials).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(creds_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    delete_account(&mut tx, account.id).await;
    tx.commit().await.expect(COMMIT);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_has_cookie(&response, ACCOUNT_COOKIE));
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
    let credentials = test_credentials();
    let creds_str = serde_urlencoded::to_string(&credentials).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/register")
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(creds_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    let account: Account = sqlx::query_as("SELECT * FROM accounts WHERE username = $1")
        .bind(&credentials.username)
        .fetch_one(&mut *tx)
        .await
        .expect("select account");
    delete_account(&mut tx, account.id).await;
    tx.commit().await.expect(COMMIT);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_has_cookie(&response, ACCOUNT_COOKIE));
}

#[tokio::test]
async fn test_logout() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let account = test_credentials().register(&mut tx, LOCAL_IP).await;
    tx.commit().await.expect(COMMIT);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/logout")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, &account.token))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    delete_account(&mut tx, account.id).await;
    tx.commit().await.expect(COMMIT);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn test_new_hash() {
    let (router, _state) = init_test().await;
    let anon_token = Uuid::new_v4().hyphenated().to_string();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/hash")
        .header(COOKIE, format!("{}={}", ANON_COOKIE, &anon_token))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_has_cookie(&response, ANON_COOKIE));
}

#[tokio::test]
async fn test_hide_rejected_post() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (post, user) = create_test_post(&mut tx, None).await;
    PostReview {
        uuid: post.uuid.clone(),
        status: PostStatus::Rejected,
    }
    .update_status(&mut tx)
    .await;
    tx.commit().await.expect(COMMIT);
    let post_hiding = PostHiding {
        uuid: post.uuid.clone(),
    };
    let post_hiding_str = serde_urlencoded::to_string(&post_hiding).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/hide-rejected-post")
        .header(COOKIE, format!("{}={}", ANON_COOKIE, &user.anon_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(post_hiding_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    post.delete(&mut tx).await;
    tx.commit().await.expect(COMMIT);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn test_review_post() {
    let (router, state) = init_test().await;
    let (post, cocoon_path, admin_account) = create_test_cocoon(&state).await;
    let post_review = PostReview {
        uuid: post.uuid.clone(),
        status: PostStatus::Approved,
    };
    let post_review_str = serde_urlencoded::to_string(&post_review).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/admin/review-post")
        .header(
            COOKIE,
            format!("{}={}", ACCOUNT_COOKIE, &admin_account.token),
        )
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(post_review_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let cocoon_uuid_dir = cocoon_path.parent().unwrap();
    assert!(!cocoon_uuid_dir.exists());
    let media_path = Path::new(MEDIA_DIR).join(&post.uuid).join("image.jpeg");
    assert!(media_path.exists());
    std::fs::remove_file(&media_path).expect("remove media file");
    let media_uuid_dir = media_path.parent().unwrap();
    std::fs::remove_dir(&media_uuid_dir).expect("remove media uuid dir");
    let mut tx = state.db.begin().await.expect(BEGIN);
    post.delete(&mut tx).await;
    delete_account(&mut tx, admin_account.id).await;
    tx.commit().await.expect(COMMIT);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn test_decrypt_media() {
    let (router, state) = init_test().await;
    let (post, cocoon_path, admin_account) = create_test_cocoon(&state).await;
    let uri = format!("/admin/decrypt-media/{}", &post.uuid);
    let request = Request::builder()
        .uri(&uri)
        .header(
            COOKIE,
            format!("{}={}", ACCOUNT_COOKIE, &admin_account.token),
        )
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
    delete_account(&mut tx, admin_account.id).await;
    tx.commit().await.expect(COMMIT);
    remove_cocoon(&cocoon_path);
}
