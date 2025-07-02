//! Post-related integration tests (creation, viewing, pagination, media, hiding, interim, etc.)

mod helpers;

use apabbs::{
    post::{MediaCategory, PostStatus::*, review::PostReview, submission::PostHiding},
    router::{
        ROOT,
        helpers::{ACCOUNT_COOKIE, SESSION_COOKIE, X_REAL_IP},
    },
    user::AccountRole,
};
use axum::{
    body::Body,
    http::{
        Request, StatusCode,
        header::{CONTENT_TYPE, COOKIE},
    },
};
use helpers::*;
use http_body_util::BodyExt;
use std::path::Path;
use tower::ServiceExt;

#[tokio::test]
async fn not_found() {
    let (router, _state) = init_test().await;
    let request = Request::builder()
        .uri("/not-found")
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn index() {
    let (router, _state) = init_test().await;
    let request = Request::builder()
        .uri(ROOT)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    assert!(response_adds_cookie(&response, SESSION_COOKIE));
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains(r#"<div id=\"posts\">"#));
    assert!(body_str.contains(&apabbs::host()));
}

#[tokio::test]
async fn solo_post() {
    let (router, state) = init_test().await;
    let user = test_user(None);
    let mut tx = state.db.begin().await.expect("begins");
    let post = create_test_post(&mut tx, &user, None, Approved).await;
    tx.commit().await.expect("commits");
    let uri = format!("/p/{}", &post.key);
    let request = Request::builder()
        .uri(&uri)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    assert!(response_adds_cookie(&response, SESSION_COOKIE));
    let body_str = response_body_str(response).await;
    assert!(!body_str.contains(r#"<div id=\"posts\">"#));
    assert!(body_str.contains(r#"<div id=\"created-at\">"#));
    let mut tx = state.db.begin().await.expect("begins");
    post.delete(&mut tx).await.expect("query succeeds");
    tx.commit().await.expect("commits");
}

#[tokio::test]
async fn index_with_page() {
    let (router, state) = init_test().await;
    let user = test_user(None);
    let mut tx = state.db.begin().await.expect("begins");
    let post1 = create_test_post(&mut tx, &user, None, Approved).await;
    let post2 = create_test_post(&mut tx, &user, None, Approved).await;
    let post3 = create_test_post(&mut tx, &user, None, Approved).await;
    tx.commit().await.expect("commits");
    let uri = format!("/page/{}", &post2.key);
    let request = Request::builder()
        .uri(&uri)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())
        .unwrap();
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
    let mut tx = state.db.begin().await.expect("begins");
    post1.delete(&mut tx).await.expect("query succeeds");
    post2.delete(&mut tx).await.expect("query succeeds");
    post3.delete(&mut tx).await.expect("query succeeds");
    tx.commit().await.expect("commits");
}

#[tokio::test]
async fn submit_post_without_media() {
    let (router, state) = init_test().await;
    let user = test_user(None);
    let mut form = form_data_builder::FormData::new(Vec::new());
    form.write_field("session_token", &user.session_token.to_string())
        .unwrap();
    form.write_field("body", "<&test body").unwrap();
    let request = Request::builder()
        .method("POST")
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
    let mut tx = state.db.begin().await.expect("begins");
    let post = select_latest_post_by_session_token(&mut tx, &user.session_token)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(post.body, "&lt;&amp;test body");
    assert_eq!(post.media_filename, None);
    assert_eq!(post.media_category, None);
    assert_eq!(post.media_mime_type, None);
    assert_eq!(post.session_token, Some(user.session_token));
    assert_eq!(post.account_id, None);
    assert_eq!(post.status, Pending);
    post.delete(&mut tx).await.expect("query succeeds");
    tx.commit().await.expect("commits");
}

#[tokio::test]
async fn submit_post_with_media() {
    let (router, state) = init_test().await;
    let user = test_user(None);
    let mut form = form_data_builder::FormData::new(Vec::new());
    let test_image_path = Path::new(TEST_MEDIA_DIR).join("image.jpeg");
    form.write_field("session_token", &user.session_token.to_string())
        .unwrap();
    form.write_field("body", "").unwrap();
    form.write_path("media", test_image_path, "image/jpeg")
        .unwrap();
    let request = Request::builder()
        .method("POST")
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
    let mut tx = state.db.begin().await.expect("begins");
    let post = select_latest_post_by_session_token(&mut tx, &user.session_token)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(post.body, "");
    assert_eq!(post.media_filename, Some(String::from("image.jpeg")));
    assert_eq!(post.media_category, Some(MediaCategory::Image));
    assert_eq!(post.media_mime_type, Some(String::from("image/jpeg")));
    post.delete(&mut tx).await.expect("query succeeds");
    tx.commit().await.expect("commits");
    let encrypted_file_path = post.encrypted_media_path();
    PostReview::delete_upload_key_dir(&encrypted_file_path)
        .await
        .expect("deletes upload key dir");
}

#[tokio::test]
async fn submit_post_with_account() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    tx.commit().await.expect("commits");
    let account = user.account.as_ref().unwrap();
    let mut form = form_data_builder::FormData::new(Vec::new());
    form.write_field("session_token", &user.session_token.to_string())
        .unwrap();
    form.write_field("body", "<&test body").unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/submit-post")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(CONTENT_TYPE, form.content_type_header())
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(form.finish().unwrap()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let mut tx = state.db.begin().await.expect("begins");
    let account_post = select_latest_post_by_account_id(&mut tx, account.id)
        .await
        .unwrap();
    let anon_post = select_latest_post_by_session_token(&mut tx, &user.session_token).await;
    assert!(anon_post.is_none());
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(account_post.account_id, Some(account.id));
    assert_eq!(account_post.session_token, None);
    account_post.delete(&mut tx).await.expect("query succeeds");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
}

#[tokio::test]
async fn hide_post() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");
    let user = test_user(None);
    let post = create_test_post(&mut tx, &user, None, Pending).await;
    let admin_user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = admin_user.account.as_ref().unwrap();
    post.update_status(&mut tx, Rejected)
        .await
        .expect("query succeeds");
    tx.commit().await.expect("commits");
    let post_hiding = PostHiding {
        session_token: user.session_token,
        key: post.key.clone(),
    };
    let post_hiding_str = serde_urlencoded::to_string(&post_hiding).expect("serializes");
    let request = Request::builder()
        .method("POST")
        .uri("/hide-post")
        .header(
            COOKIE,
            format!("{}={}", SESSION_COOKIE, &user.session_token),
        )
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(post_hiding_str))
        .expect("builds request");
    let response = router.oneshot(request).await.expect("request succeeds");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let mut tx = state.db.begin().await.expect("begins");
    post.delete(&mut tx).await.expect("query succeeds");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
}

#[tokio::test]
async fn interim() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");
    let user = test_user(None);
    let post1 = create_test_post(&mut tx, &user, None, Approved).await;
    let post2 = create_test_post(&mut tx, &user, None, Approved).await;
    let post3 = create_test_post(&mut tx, &user, None, Approved).await;
    tx.commit().await.expect("commits");
    let request = Request::builder()
        .uri(format!("/interim/{}", &post1.key))
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())
        .expect("builds request");
    let response = router.oneshot(request).await.expect("request succeeds");
    assert!(response.status().is_success());
    let body_str = response_body_str(response).await;
    assert!(!body_str.contains(&post1.key));
    assert!(body_str.contains(&post2.key));
    assert!(body_str.contains(&post3.key));
    let post2_index = body_str.find(&post2.key).unwrap();
    let post3_index = body_str.find(&post3.key).unwrap();
    assert!(post2_index < post3_index);
    let mut tx = state.db.begin().await.expect("begins");
    post1.delete(&mut tx).await.expect("query succeeds");
    post2.delete(&mut tx).await.expect("query succeeds");
    post3.delete(&mut tx).await.expect("query succeeds");
    tx.commit().await.expect("commits");
}

#[tokio::test]
async fn decrypt_media() {
    use axum::http::header::CONTENT_DISPOSITION;
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");
    let anon_user = test_user(None);
    let post = create_test_post(&mut tx, &anon_user, Some("image.jpeg"), Pending).await;
    let user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("commits");
    let key = format!("/decrypt-media/{}", &post.key);
    let request = Request::builder()
        .uri(&key)
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .unwrap();
    assert_eq!(content_type, "image/jpeg");
    let content_disposition = response.headers().get(CONTENT_DISPOSITION).unwrap();
    assert_eq!(content_disposition, r#"inline; filename=\"image.jpeg\""#);
    let mut tx = state.db.begin().await.expect("begins");
    post.delete(&mut tx).await.expect("query succeeds");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
}
