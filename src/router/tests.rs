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
        confirm_password: Some(String::from("test_password")),
    }
}

fn local_ip_hash() -> String {
    let secret_key = std::env::var("SECRET_KEY").expect("read SECRET_KEY env");
    sha256::digest(secret_key + LOCAL_IP)
}

async fn create_test_account(tx: &mut PgConnection, admin: bool) -> Account {
    let credentials = test_credentials();
    let account = credentials.register(tx, &local_ip_hash()).await;
    if admin {
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
    }
}

async fn delete_test_account(tx: &mut PgConnection, account: Account) {
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(account.id)
        .execute(&mut *tx)
        .await
        .expect("delete test account");
}

async fn create_test_post(tx: &mut PgConnection, media_file_name: Option<&str>) -> (Post, User) {
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
    let user = User {
        account: None,
        anon_token: Uuid::new_v4(),
    };
    let post_submission = PostSubmission {
        body: String::from("test body"),
        anon: None,
        media_file_name: media_file_name.clone(),
        uuid: Uuid::new_v4(),
        media_bytes: media_bytes,
    };
    let post = post_submission.insert(tx, &user, &local_ip_hash()).await;
    if media_file_name.is_some() {
        if let Err(msg) = post_submission.save_encrypted_media_file().await {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    }
    (post, user)
}

fn response_has_cookie(response: &Response<Body>, cookie: &str) -> bool {
    response
        .headers()
        .get(SET_COOKIE)
        .is_some_and(|c| c.to_str().unwrap().contains(cookie))
}

fn remove_encrypted_file(encrypted_file_path: &Path) {
    println!("removing encrypted file: {:?}", encrypted_file_path);
    let uploads_uuid_dir = encrypted_file_path.parent().unwrap();
    std::fs::remove_file(&encrypted_file_path).expect("remove encrypted file");
    std::fs::remove_dir(&uploads_uuid_dir).expect("remove uploads uuid dir");
}

async fn select_latest_post_by_anon_token(
    tx: &mut PgConnection,
    anon_token: &Uuid,
) -> Option<Post> {
    sqlx::query_as("SELECT * FROM posts WHERE anon_token = $1 ORDER BY id DESC LIMIT 1")
        .bind(anon_token)
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
    assert!(response_has_cookie(&response, ANON_COOKIE));
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains(&site_name()));
}

#[tokio::test]
async fn test_submit_post() {
    let (router, state) = init_test().await;
    let anon_token = Uuid::new_v4();
    let mut form = FormData::new(Vec::new());
    form.write_field("body", "<test body").unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/submit-post")
        .header(COOKIE, format!("{}={}", ANON_COOKIE, &anon_token))
        .header(CONTENT_TYPE, form.content_type_header())
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(form.finish().unwrap()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post = select_latest_post_by_anon_token(&mut tx, &anon_token)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(post.body, "&lt;test body");
    assert_eq!(post.media_file_name, None);
    assert_eq!(post.media_category, None);
    assert_eq!(post.media_mime_type, None);
    assert_eq!(post.anon_token, Some(anon_token));
    assert_eq!(post.account_id, None);
    assert_eq!(post.username, None);
    assert_eq!(post.status, PostStatus::Pending);
    post.delete(&mut tx).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_submit_post_with_media() {
    let (router, state) = init_test().await;
    let anon_token = Uuid::new_v4();
    let mut form = FormData::new(Vec::new());
    let test_image_path = Path::new(TEST_MEDIA_DIR).join("image.jpeg");
    form.write_field("body", "").unwrap();
    form.write_path("media", test_image_path, "image/jpeg")
        .unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/submit-post")
        .header(COOKIE, format!("{}={}", ANON_COOKIE, &anon_token))
        .header(CONTENT_TYPE, form.content_type_header())
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(form.finish().unwrap()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post = select_latest_post_by_anon_token(&mut tx, &anon_token)
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
    let account = create_test_account(&mut tx, false).await;
    tx.commit().await.expect(COMMIT);
    let anon_token = Uuid::new_v4();
    let mut form = FormData::new(Vec::new());
    form.write_field("body", "<test body").unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/submit-post")
        .header(COOKIE, format!("{}={}", ANON_COOKIE, &anon_token))
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, &account.token))
        .header(CONTENT_TYPE, form.content_type_header())
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(form.finish().unwrap()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post = select_latest_post_by_username(&mut tx, &account.username)
        .await
        .unwrap();
    let anon_token_post_option = select_latest_post_by_anon_token(&mut tx, &anon_token).await;
    assert!(anon_token_post_option.is_none());
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(post.account_id, Some(account.id));
    assert_eq!(post.anon_token, None);
    post.delete(&mut tx).await;
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_submit_post_with_account_while_anon() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let account = create_test_account(&mut tx, false).await;
    tx.commit().await.expect(COMMIT);
    let anon_token = Uuid::new_v4();
    let mut form = FormData::new(Vec::new());
    form.write_field("body", "<test body").unwrap();
    form.write_field("anon", "on").unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/submit-post")
        .header(COOKIE, format!("{}={}", ANON_COOKIE, &anon_token))
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, &account.token))
        .header(CONTENT_TYPE, form.content_type_header())
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(form.finish().unwrap()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post = select_latest_post_by_anon_token(&mut tx, &anon_token)
        .await
        .unwrap();
    let username_post_option = select_latest_post_by_username(&mut tx, &account.username).await;
    assert!(username_post_option.is_none());
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(post.account_id, None);
    post.delete(&mut tx).await;
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
    let credentials = test_credentials();
    let account = credentials.register(&mut tx, &local_ip_hash()).await;
    tx.commit().await.expect(COMMIT);
    let creds_str = serde_urlencoded::to_string(&credentials).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(creds_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_has_cookie(&response, ACCOUNT_COOKIE));
    let mut tx = state.db.begin().await.expect(BEGIN);
    delete_test_account(&mut tx, account).await;
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
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_has_cookie(&response, ACCOUNT_COOKIE));
    let mut tx = state.db.begin().await.expect(BEGIN);
    let account = Account::select_by_username(&mut tx, &credentials.username)
        .await
        .unwrap();
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_logout() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let account = test_credentials().register(&mut tx, &local_ip_hash()).await;
    tx.commit().await.expect(COMMIT);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/logout")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, &account.token))
        .body(Body::empty())
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
    let (post, user) = create_test_post(&mut tx, Some("image.jpeg")).await;
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
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let mut tx = state.db.begin().await.expect(BEGIN);
    post.delete(&mut tx).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_interim() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (post1, _user) = create_test_post(&mut tx, None).await;
    PostReview {
        uuid: post1.uuid.clone(),
        status: PostStatus::Approved,
    }
    .update_status(&mut tx)
    .await;
    let (post2, _user) = create_test_post(&mut tx, None).await;
    PostReview {
        uuid: post2.uuid.clone(),
        status: PostStatus::Approved,
    }
    .update_status(&mut tx)
    .await;
    tx.commit().await.expect(COMMIT);
    let request = Request::builder()
        .uri(&format!("/interim/{}", &post1.uuid))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(!body_str.contains(&post1.uuid.to_string()));
    assert!(body_str.contains(&post2.uuid.to_string()));
    let mut tx = state.db.begin().await.expect(BEGIN);
    post1.delete(&mut tx).await;
    post2.delete(&mut tx).await;
    tx.commit().await.expect(COMMIT);
}

#[tokio::test]
async fn test_user_profile() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let account = create_test_account(&mut tx, false).await;
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
async fn test_update_time_zone() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let account = create_test_account(&mut tx, false).await;
    tx.commit().await.expect(COMMIT);
    let time_zone_update = TimeZoneUpdate {
        username: account.username.clone(),
        time_zone: String::from("America/New_York"),
    };
    let time_zone_update_str = serde_urlencoded::to_string(&time_zone_update).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/update-time-zone")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, &account.token))
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
    let account = create_test_account(&mut tx, false).await;
    tx.commit().await.expect(COMMIT);
    let credentials = Credentials {
        username: account.username.clone(),
        password: String::from("new_password"),
        confirm_password: Some(String::from("new_password")),
    };
    let credentials_str = serde_urlencoded::to_string(&credentials).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/update-password")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, &account.token))
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
    let (post, _user) = create_test_post(&mut tx, Some("image.jpeg")).await;
    let encrypted_media_path = post.encrypted_media_path();
    let admin_account = create_test_account(&mut tx, true).await;
    tx.commit().await.expect(COMMIT);
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
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post = Post::select_by_uuid(&mut tx, &post.uuid)
        .await
        .expect("select post");
    let uploads_uuid_dir = encrypted_media_path.parent().unwrap();
    assert!(!uploads_uuid_dir.exists());
    let published_media_path = post.published_media_path();
    assert!(published_media_path.exists());
    let thumbnail_path = post.thumbnail_path();
    assert!(thumbnail_path.exists());
    std::fs::remove_file(&published_media_path).expect("remove media file");
    std::fs::remove_file(&thumbnail_path).expect("remove thumbnail file");
    let media_uuid_dir = published_media_path.parent().unwrap();
    std::fs::remove_dir(&media_uuid_dir).expect("remove media uuid dir");
    post.delete(&mut tx).await;
    delete_test_account(&mut tx, admin_account).await;
    tx.commit().await.expect(COMMIT);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn test_review_post_with_small_media() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (post, _user) = create_test_post(&mut tx, Some("small.png")).await;
    let encrypted_media_path = post.encrypted_media_path();
    let admin_account = create_test_account(&mut tx, true).await;
    tx.commit().await.expect(COMMIT);
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
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post = Post::select_by_uuid(&mut tx, &post.uuid)
        .await
        .expect("select post");
    let uploads_uuid_dir = encrypted_media_path.parent().unwrap();
    assert!(!uploads_uuid_dir.exists());
    let published_media_path = post.published_media_path();
    assert!(published_media_path.exists());
    let thumbnail_path = post_review.thumbnail_path(post.media_file_name.as_ref().unwrap());
    assert!(!thumbnail_path.exists());
    std::fs::remove_file(&published_media_path).expect("remove media file");
    let media_uuid_dir = published_media_path.parent().unwrap();
    std::fs::remove_dir(&media_uuid_dir).expect("remove media uuid dir");
    post.delete(&mut tx).await;
    delete_test_account(&mut tx, admin_account).await;
    tx.commit().await.expect(COMMIT);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn test_decrypt_media() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (post, _user) = create_test_post(&mut tx, Some("image.jpeg")).await;
    let encrypted_media_path = post.encrypted_media_path();
    let admin_account = create_test_account(&mut tx, true).await;
    tx.commit().await.expect(COMMIT);
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
    delete_test_account(&mut tx, admin_account).await;
    tx.commit().await.expect(COMMIT);
    remove_encrypted_file(&encrypted_media_path);
}
