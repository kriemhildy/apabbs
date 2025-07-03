//! Moderation, review, and ban-related integration tests.

mod helpers;

use apabbs::{
    ban,
    post::{Post, PostStatus, review::PostReview, submission::PostSubmission},
    router::helpers::{ACCOUNT_COOKIE, SESSION_COOKIE, X_REAL_IP},
    user::{AccountRole, User},
};
use axum::{
    body::Body,
    http::{
        Method, Request, StatusCode,
        header::{CONTENT_TYPE, COOKIE},
    },
};
use form_data_builder::FormData;
use helpers::{
    APPLICATION_WWW_FORM_URLENCODED, LOCAL_IP, create_test_account, delete_test_account, init_test,
    test_credentials, test_user,
};
use tower::ServiceExt;
use uuid::Uuid;

use crate::helpers::{create_test_post, delete_test_ban};

pub const BAN_IP: &str = "192.0.2.0";

/// Tests decrypting and serving media files.
#[tokio::test]
async fn decrypt_media() {
    use axum::http::header::CONTENT_DISPOSITION;

    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");
    let anon_user = test_user(None);
    let post = create_test_post(&mut tx, &anon_user, Some("image.jpeg"), PostStatus::Pending).await;
    let user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("commits");

    // Request the encrypted media
    let key = format!("/decrypt-media/{}", &post.key);
    let request = Request::builder()
        .uri(&key)
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();

    // Verify response headers and status
    assert!(response.status().is_success());
    let content_type = response.headers().get(CONTENT_TYPE).unwrap();
    assert_eq!(content_type, "image/jpeg");
    let content_disposition = response.headers().get(CONTENT_DISPOSITION).unwrap();
    assert_eq!(content_disposition, r#"inline; filename="image.jpeg""#);

    // Clean up
    let mut tx = state.db.begin().await.expect("begins");
    post.delete(&mut tx).await.expect("query succeeds");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
    let encrypted_file_path = post.encrypted_media_path();
    PostReview::delete_upload_key_dir(&encrypted_file_path)
        .await
        .expect("deletes upload key dir");
}

/// Tests automatic banning functionality for suspicious activity.
#[tokio::test]
async fn autoban() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");
    let user = User {
        ip_hash: sha256::digest(apabbs::secret_key() + BAN_IP),
        ..User::default()
    };

    // Create several accounts from the same IP
    let mut credentials = test_credentials(&user);
    for _ in 0..3 {
        credentials.session_token = Uuid::new_v4();
        credentials.username = Uuid::new_v4().simple().to_string()[..16].to_string();
        credentials
            .register(&mut tx, &user.ip_hash)
            .await
            .expect("query succeeds");
    }

    // Create several posts from the same IP
    let mut post_submission = PostSubmission {
        session_token: user.session_token,
        body: String::from("trololol"),
        ..PostSubmission::default()
    };
    for _ in 0..5 {
        post_submission.session_token = Uuid::new_v4();
        let key = PostSubmission::generate_key(&mut tx)
            .await
            .expect("query succeeds");
        post_submission
            .insert(&mut tx, &user, &key)
            .await
            .expect("query succeeds");
    }

    // Verify state before flooding threshold is reached
    assert_eq!(
        ban::new_accounts_count(&mut tx, &user.ip_hash)
            .await
            .expect("query succeeds"),
        3
    );
    assert_eq!(
        ban::new_posts_count(&mut tx, &user.ip_hash)
            .await
            .expect("query succeeds"),
        5
    );
    assert!(
        ban::exists(&mut tx, &user.ip_hash, None)
            .await
            .expect("query succeeds")
            .is_none()
    );
    assert!(
        !ban::flooding(&mut tx, &user.ip_hash)
            .await
            .expect("query succeeds")
    );

    // Create one more post to trigger flooding detection
    post_submission.session_token = Uuid::new_v4();
    let key = PostSubmission::generate_key(&mut tx)
        .await
        .expect("query succeeds");
    post_submission
        .insert(&mut tx, &user, &key)
        .await
        .expect("query succeeds");

    // Verify flooding is detected but ban not yet applied
    assert_eq!(
        ban::new_accounts_count(&mut tx, &user.ip_hash)
            .await
            .expect("query succeeds"),
        3
    );
    assert_eq!(
        ban::new_posts_count(&mut tx, &user.ip_hash)
            .await
            .expect("query succeeds"),
        6
    );
    assert!(
        ban::exists(&mut tx, &user.ip_hash, None)
            .await
            .expect("query succeeds")
            .is_none()
    );
    assert!(
        ban::flooding(&mut tx, &user.ip_hash)
            .await
            .expect("query succeeds")
    );
    tx.commit().await.expect("commits");

    // Attempt another post to trigger the ban
    let mut form = FormData::new(Vec::new());
    let bogus_session_token = Uuid::new_v4();
    form.write_field("session_token", &bogus_session_token.to_string())
        .unwrap();
    form.write_field("body", "trololol").unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/submit-post")
        .header(COOKIE, format!("{SESSION_COOKIE}={bogus_session_token}"))
        .header(CONTENT_TYPE, form.content_type_header())
        .header(X_REAL_IP, BAN_IP)
        .body(Body::from(form.finish().unwrap()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();

    // Verify ban was applied
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Verify ban state after ban
    let mut tx = state.db.begin().await.expect("begins");
    assert!(
        ban::exists(&mut tx, &user.ip_hash, None)
            .await
            .expect("query succeeds")
            .is_some()
    );
    assert!(
        !ban::flooding(&mut tx, &user.ip_hash)
            .await
            .expect("query succeeds")
    );
    assert_eq!(
        ban::new_accounts_count(&mut tx, &user.ip_hash)
            .await
            .expect("query succeeds"),
        0
    );
    assert_eq!(
        ban::new_posts_count(&mut tx, &user.ip_hash)
            .await
            .expect("query succeeds"),
        0
    );

    // Clean up
    delete_test_ban(&mut tx, &user.ip_hash).await;
    tx.commit().await.expect("commits");
}

/// Tests reviewing a post with a normal image.
#[tokio::test]
async fn review_post_with_normal_image() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");
    let user = test_user(None);
    let post = create_test_post(&mut tx, &user, Some("image.jpeg"), PostStatus::Pending).await;
    let encrypted_media_path = post.encrypted_media_path();
    let user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("commits");

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
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(post_review_str))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Initial check - post should be in processing state
    let mut tx = state.db.begin().await.expect("begins");
    let post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("query succeeds")
        .expect("post exists");
    tx.commit().await.expect("commits");
    assert_eq!(post.status, PostStatus::Processing);

    // Poll for completion - wait until the post is no longer in processing state
    let max_attempts = 10;
    let wait_time = std::time::Duration::from_millis(500);
    let mut processed = false;

    for _ in 0..max_attempts {
        tokio::time::sleep(wait_time).await;
        let mut tx = state.db.begin().await.expect("begins");
        let updated_post = Post::select_by_key(&mut tx, &post.key)
            .await
            .expect("query succeeds")
            .expect("post exists");
        tx.commit().await.expect("commits");

        if updated_post.status != PostStatus::Processing {
            processed = true;

            // After processing completes, verify all assets were created
            let uploads_key_dir = encrypted_media_path.parent().unwrap();
            assert!(!uploads_key_dir.exists());
            let published_media_path = updated_post.published_media_path();
            assert!(published_media_path.exists());
            let thumbnail_path = updated_post.thumbnail_path();
            assert!(thumbnail_path.exists());
            assert!(updated_post.media_width.is_some());
            assert!(updated_post.media_height.is_some());

            break;
        }
    }

    assert!(
        processed,
        "Background processing did not complete in the expected time"
    );

    // Clean up
    let mut tx = state.db.begin().await.expect("begins");
    let final_post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("query succeeds")
        .expect("post exists");
    PostReview::delete_media_key_dir(&post.key)
        .await
        .expect("deletes media key dir");
    final_post.delete(&mut tx).await.expect("query succeeds");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
}

/// Tests reviewing a post with a small image.
#[tokio::test]
async fn review_post_with_small_image() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");
    let user = test_user(None);
    let post = create_test_post(&mut tx, &user, Some("small.png"), PostStatus::Pending).await;
    let encrypted_media_path = post.encrypted_media_path();
    let user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("commits");

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
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(post_review_str))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Initial check - post should be in processing state
    let mut tx = state.db.begin().await.expect("begins");
    let post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("query succeeds")
        .expect("post exists");
    tx.commit().await.expect("commits");
    assert_eq!(post.status, PostStatus::Processing);

    // Poll for completion - wait until the post is no longer in processing state
    let max_attempts = 10;
    let wait_time = std::time::Duration::from_millis(500);
    let mut processed = false;

    for _ in 0..max_attempts {
        tokio::time::sleep(wait_time).await;
        let mut tx = state.db.begin().await.expect("begins");
        let updated_post = Post::select_by_key(&mut tx, &post.key)
            .await
            .expect("query succeeds")
            .expect("post exists");
        tx.commit().await.expect("commits");

        if updated_post.status != PostStatus::Processing {
            processed = true;

            // After processing completes, verify assets
            let uploads_key_dir = encrypted_media_path.parent().unwrap();
            assert!(!uploads_key_dir.exists());
            let published_media_path = updated_post.published_media_path();
            assert!(published_media_path.exists());

            // Small images shouldn't have thumbnails
            assert!(updated_post.thumb_filename.is_none());
            let thumbnail_path = PostReview::alternate_path(&published_media_path, "tn_", ".webp");
            assert!(!thumbnail_path.exists());

            break;
        }
    }

    assert!(
        processed,
        "Background processing did not complete in the expected time"
    );

    // Clean up
    let mut tx = state.db.begin().await.expect("begins");
    let final_post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("query succeeds")
        .expect("post exists");
    PostReview::delete_media_key_dir(&post.key)
        .await
        .expect("deletes media key dir");
    final_post.delete(&mut tx).await.expect("query succeeds");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
}

/// Tests reviewing a post with a video.
#[tokio::test]
async fn review_post_with_video() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");
    let user = test_user(None);
    let post = create_test_post(&mut tx, &user, Some("video.mp4"), PostStatus::Pending).await;
    let encrypted_media_path = post.encrypted_media_path();
    let user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("commits");

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
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(post_review_str))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Initial check - post should be in processing state
    let mut tx = state.db.begin().await.expect("begins");
    let post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("query succeeds")
        .expect("post exists");
    tx.commit().await.expect("commits");
    assert_eq!(post.status, PostStatus::Processing);

    // Poll for completion - wait until the post is no longer in processing state
    let max_attempts = 10;
    let wait_time = std::time::Duration::from_millis(500);
    let mut processed = false;

    for _ in 0..max_attempts {
        tokio::time::sleep(wait_time).await;
        let mut tx = state.db.begin().await.expect("begins");
        let updated_post = Post::select_by_key(&mut tx, &post.key)
            .await
            .expect("query succeeds")
            .expect("post exists");
        tx.commit().await.expect("commits");

        if updated_post.status != PostStatus::Processing {
            processed = true;

            // After processing completes, verify all assets were created
            let uploads_key_dir = encrypted_media_path.parent().unwrap();
            assert!(!uploads_key_dir.exists());
            let published_media_path = updated_post.published_media_path();
            assert!(published_media_path.exists());
            // Thumbnail is only created for very large videos now
            // Check for compatibility video, though
            assert!(updated_post.thumb_filename.is_none());
            assert!(
                PostReview::video_is_compatible(&published_media_path)
                    .await
                    .unwrap()
            );
            assert!(updated_post.compat_video.is_none());
            assert!(updated_post.media_width.is_some());
            assert!(updated_post.media_height.is_some());

            break;
        }
    }

    assert!(
        processed,
        "Background processing did not complete in the expected time"
    );

    // Clean up
    let mut tx = state.db.begin().await.expect("begins");
    let final_post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("query succeeds")
        .expect("post exists");
    PostReview::delete_media_key_dir(&post.key)
        .await
        .expect("deletes media key dir");
    final_post.delete(&mut tx).await.expect("query succeeds");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
}
