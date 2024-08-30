use super::*;
use crate::post::PostMediaCategory;
use axum::{
    body::Body,
    http::{
        header::{CONTENT_TYPE, COOKIE, SET_COOKIE},
        Method, Request, StatusCode,
    },
    Router,
};
use form_data_builder::FormData;
use http_body_util::BodyExt;
use tower::util::ServiceExt; // for `call`, `oneshot`, and `ready`

const LOCAL_IP: &'static str = "::1";
const APPLICATION_WWW_FORM_URLENCODED: &'static str = "application/x-www-form-urlencoded";

async fn init_test() -> (Router, AppState) {
    if !dev() {
        panic!("not in dev mode");
    }
    let state = init::app_state().await;
    let router = router(state.clone(), false);
    (router, state)
}

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
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response
        .headers()
        .get(SET_COOKIE)
        .is_some_and(|c| c.to_str().unwrap().contains(ANON_COOKIE)));
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains(&site_name()));
}

#[tokio::test]
async fn test_submit_post() {
    let (router, state) = init_test().await;
    let post_submission = PostSubmission {
        body: String::from("<test body"),
        anon: Some(String::from("on")),
        media_file_name: None,
        uuid: Uuid::new_v4().hyphenated().to_string(),
    };
    let anon_token = Uuid::new_v4().hyphenated().to_string();
    let mut form = FormData::new(Vec::new());
    form.write_field("body", &post_submission.body).unwrap();
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
    let post: Post =
        sqlx::query_as("SELECT * FROM posts WHERE anon_token = $1 ORDER BY id DESC LIMIT 1")
            .bind(&anon_token)
            .fetch_one(&state.db)
            .await
            .expect("select post");
    sqlx::query("DELETE FROM posts WHERE id = $1")
        .bind(post.id)
        .execute(&state.db)
        .await
        .expect("delete test post");
    let cocoon_file_name = "image.jpeg.cocoon";
    let cocoon_path = std::path::Path::new(UPLOADS_DIR)
        .join(&post.uuid)
        .join(&cocoon_file_name);
    let uploads_uuid_dir = cocoon_path.parent().unwrap();
    std::fs::remove_file(&cocoon_path).expect("remove cocoon file");
    std::fs::remove_dir(&uploads_uuid_dir).expect("remove uploads uuid dir");
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
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("Log in"));
}

#[tokio::test]
async fn test_authenticate() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let credentials = Credentials {
        username: String::from("test1"),
        password: String::from("test_password"),
    };
    credentials.register(&mut tx, LOCAL_IP).await;
    tx.commit().await.expect(COMMIT);
    let creds_str = serde_urlencoded::to_string(&credentials).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .body(Body::from(creds_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    sqlx::query("DELETE FROM accounts WHERE username = $1")
        .bind("test1")
        .execute(&state.db)
        .await
        .expect("delete test account");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response
        .headers()
        .get(SET_COOKIE)
        .is_some_and(|c| c.to_str().unwrap().contains(ACCOUNT_COOKIE)));
}

#[tokio::test]
async fn test_registration_form() {
    let (router, _state) = init_test().await;
    let request = Request::builder()
        .uri("/register")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("Register"));
}

#[tokio::test]
async fn test_create_account() {
    let (router, state) = init_test().await;
    let credentials = Credentials {
        username: String::from("test2"),
        password: String::from("test_password"),
    };
    let creds_str = serde_urlencoded::to_string(&credentials).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/register")
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(creds_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    sqlx::query("DELETE FROM accounts WHERE username = $1")
        .bind("test2")
        .execute(&state.db)
        .await
        .expect("delete test account");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response
        .headers()
        .get(SET_COOKIE)
        .is_some_and(|c| c.to_str().unwrap().contains(ACCOUNT_COOKIE)));
}

#[tokio::test]
async fn test_logout() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let credentials = Credentials {
        username: String::from("test3"),
        password: String::from("test_password"),
    };
    let account = credentials.register(&mut tx, LOCAL_IP).await;
    tx.commit().await.expect(COMMIT);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/logout")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, &account.token))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    sqlx::query("DELETE FROM accounts WHERE username = $1")
        .bind("test3")
        .execute(&state.db)
        .await
        .expect("delete test account");
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
    assert!(response
        .headers()
        .get(SET_COOKIE)
        .is_some_and(|c| c.to_str().unwrap().contains(ANON_COOKIE)));
}

#[tokio::test]
async fn test_hide_rejected_post() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = User {
        account: None,
        anon_token: Uuid::new_v4().hyphenated().to_string(),
    };
    let post = PostSubmission {
        body: String::from("test body"),
        anon: Some(String::from("on")),
        media_file_name: None,
        uuid: Uuid::new_v4().hyphenated().to_string(),
    }
    .insert(&mut tx, &user, LOCAL_IP)
    .await;
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
    sqlx::query("DELETE FROM posts WHERE anon_token = $1")
        .bind(&user.anon_token)
        .execute(&state.db)
        .await
        .expect("delete test post");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn test_review_post() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post_user = User {
        account: None,
        anon_token: Uuid::new_v4().hyphenated().to_string(),
    };
    let post_submission = PostSubmission {
        body: String::from("test body"),
        anon: Some(String::from("on")),
        media_file_name: Some(String::from("image.jpeg")),
        uuid: Uuid::new_v4().hyphenated().to_string(),
    }
    .insert(&mut tx, &post_user, LOCAL_IP)
    .await;
    let cocoon_file_name = post_submission.media_file_name.unwrap().clone() + ".cocoon";
    let cocoon_path = std::path::Path::new(UPLOADS_DIR)
        .join(&post_submission.uuid)
        .join(&cocoon_file_name);
    let cocoon_uuid_dir = cocoon_path.parent().unwrap();
    std::fs::create_dir(cocoon_uuid_dir).expect("create uuid dir");
    let mut file = File::create(&cocoon_path).expect("create file");
    let data = std::fs::read("tests/media/image.jpeg").expect("read tests/media/image.jpeg");
    let secret_key = std::env::var("SECRET_KEY").expect("read SECRET_KEY env");
    let mut cocoon = Cocoon::new(secret_key.as_bytes());
    cocoon.dump(data, &mut file).expect("dump cocoon to file");
    let admin_account = Credentials {
        username: String::from("test4"),
        password: String::from("test_password"),
    }
    .register(&mut tx, LOCAL_IP)
    .await;
    sqlx::query("UPDATE accounts SET admin = $1 WHERE id = $2")
        .bind(true)
        .bind(admin_account.id)
        .execute(&mut *tx)
        .await
        .expect("set account as admin");
    tx.commit().await.expect(COMMIT);
    let post_review = PostReview {
        uuid: post_submission.uuid.clone(),
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
    assert!(!cocoon_uuid_dir.exists());
    let media_path = std::path::Path::new(MEDIA_DIR)
        .join(&post_submission.uuid)
        .join("image.jpeg");
    assert!(media_path.exists());
    std::fs::remove_file(&media_path).expect("remove media file");
    let media_uuid_dir = media_path.parent().unwrap();
    std::fs::remove_dir(&media_uuid_dir).expect("remove media uuid dir");
    sqlx::query("DELETE FROM posts WHERE anon_token = $1")
        .bind(&post_user.anon_token)
        .execute(&state.db)
        .await
        .expect("delete test post");
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(&admin_account.id)
        .execute(&state.db)
        .await
        .expect("delete test admin account");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn test_decrypt_media() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let post_user = User {
        account: None,
        anon_token: Uuid::new_v4().hyphenated().to_string(),
    };
    let post = PostSubmission {
        body: String::from("test body"),
        anon: Some(String::from("on")),
        media_file_name: Some(String::from("image.jpeg")),
        uuid: Uuid::new_v4().hyphenated().to_string(),
    }
    .insert(&mut tx, &post_user, LOCAL_IP)
    .await;
    let cocoon_file_name = post.media_file_name.unwrap().clone() + ".cocoon";
    let cocoon_path = std::path::Path::new(UPLOADS_DIR)
        .join(&post.uuid)
        .join(&cocoon_file_name);
    let cocoon_uuid_dir = cocoon_path.parent().unwrap();
    std::fs::create_dir(cocoon_uuid_dir).expect("create uuid dir");
    let mut file = File::create(&cocoon_path).expect("create file");
    let data = std::fs::read("tests/media/image.jpeg").expect("read tests/media/image.jpeg");
    let secret_key = std::env::var("SECRET_KEY").expect("read SECRET_KEY env");
    let mut cocoon = Cocoon::new(secret_key.as_bytes());
    cocoon.dump(data, &mut file).expect("dump cocoon to file");
    let admin_account = Credentials {
        username: String::from("test5"),
        password: String::from("test_password"),
    }
    .register(&mut tx, LOCAL_IP)
    .await;
    sqlx::query("UPDATE accounts SET admin = $1 WHERE id = $2")
        .bind(true)
        .bind(admin_account.id)
        .execute(&mut *tx)
        .await
        .expect("set account as admin");
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
    assert_eq!(response.status(), StatusCode::OK);
    sqlx::query("DELETE FROM posts WHERE id = $1")
        .bind(post.id)
        .execute(&state.db)
        .await
        .expect("delete test post");
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(admin_account.id)
        .execute(&state.db)
        .await
        .expect("delete test admin account");
    std::fs::remove_file(&cocoon_path).expect("remove cocoon file");
    std::fs::remove_dir(&cocoon_uuid_dir).expect("remove uploads uuid dir");
}
