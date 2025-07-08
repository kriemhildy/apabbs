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
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let anon_user = test_user(None);
    let post = create_test_post(&mut tx, &anon_user, Some("image.jpeg"), PostStatus::Pending).await;
    let user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("Commit transaction");

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
    let mut tx = state.db.begin().await.expect("Begin transaction");
    post.delete(&mut tx).await.expect("Execute query");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("Commit transaction");
    PostReview::delete_upload_key_dir(&post.key)
        .await
        .expect("Delete directory");
}

/// Tests automatic banning functionality for suspicious activity.
#[tokio::test]
async fn autoban() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("Begin transaction");
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
            .expect("Execute query");
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
            .expect("Execute query");
        post_submission
            .insert(&mut tx, &user, &key)
            .await
            .expect("Execute query");
    }

    // Verify state before flooding threshold is reached
    assert_eq!(
        ban::new_accounts_count(&mut tx, &user.ip_hash)
            .await
            .expect("Execute query"),
        3
    );
    assert_eq!(
        ban::new_posts_count(&mut tx, &user.ip_hash)
            .await
            .expect("Execute query"),
        5
    );
    assert!(
        ban::exists(&mut tx, &user.ip_hash, None)
            .await
            .expect("Execute query")
            .is_none()
    );
    assert!(
        !ban::flooding(&mut tx, &user.ip_hash)
            .await
            .expect("Execute query")
    );

    // Create one more post to trigger flooding detection
    post_submission.session_token = Uuid::new_v4();
    let key = PostSubmission::generate_key(&mut tx)
        .await
        .expect("Execute query");
    post_submission
        .insert(&mut tx, &user, &key)
        .await
        .expect("Execute query");

    // Verify flooding is detected but ban not yet applied
    assert_eq!(
        ban::new_accounts_count(&mut tx, &user.ip_hash)
            .await
            .expect("Execute query"),
        3
    );
    assert_eq!(
        ban::new_posts_count(&mut tx, &user.ip_hash)
            .await
            .expect("Execute query"),
        6
    );
    assert!(
        ban::exists(&mut tx, &user.ip_hash, None)
            .await
            .expect("Execute query")
            .is_none()
    );
    assert!(
        ban::flooding(&mut tx, &user.ip_hash)
            .await
            .expect("Execute query")
    );
    tx.commit().await.expect("Commit transaction");

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
    let mut tx = state.db.begin().await.expect("Begin transaction");
    assert!(
        ban::exists(&mut tx, &user.ip_hash, None)
            .await
            .expect("Execute query")
            .is_some()
    );
    assert!(
        !ban::flooding(&mut tx, &user.ip_hash)
            .await
            .expect("Execute query")
    );
    assert_eq!(
        ban::new_accounts_count(&mut tx, &user.ip_hash)
            .await
            .expect("Execute query"),
        0
    );
    assert_eq!(
        ban::new_posts_count(&mut tx, &user.ip_hash)
            .await
            .expect("Execute query"),
        0
    );

    // Clean up
    delete_test_ban(&mut tx, &user.ip_hash).await;
    tx.commit().await.expect("Commit transaction");
}

/// Tests reviewing a post with a normal image.
#[tokio::test]
async fn approve_post_with_normal_image() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let user = test_user(None);
    let post = create_test_post(&mut tx, &user, Some("image.jpeg"), PostStatus::Pending).await;
    let encrypted_media_path = post.encrypted_media_path();
    let user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("Commit transaction");

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
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("Execute query")
        .unwrap();
    tx.commit().await.expect("Commit transaction");
    assert_eq!(post.status, PostStatus::Processing);

    // Poll for completion - wait until the post is no longer in processing state
    let max_attempts = 10;
    let wait_time = std::time::Duration::from_millis(500);
    let mut processed = false;

    for _ in 0..max_attempts {
        tokio::time::sleep(wait_time).await;
        let mut tx = state.db.begin().await.expect("Begin transaction");
        let post = Post::select_by_key(&mut tx, &post.key)
            .await
            .expect("Execute query")
            .unwrap();
        tx.commit().await.expect("Commit transaction");

        if post.status != PostStatus::Processing {
            processed = true;

            // After processing completes, verify all assets were created
            let uploads_key_dir = encrypted_media_path.parent().unwrap();
            assert!(!uploads_key_dir.exists());
            assert!(post.published_media_path().exists());
            assert!(post.thumbnail_path().exists());
            assert!(post.media_width.is_some());
            assert!(post.media_height.is_some());

            break;
        }
    }

    assert!(
        processed,
        "Background processing did not complete in the expected time"
    );

    // Clean up
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let final_post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("Execute query")
        .unwrap();
    PostReview::delete_media_key_dir(&post.key)
        .await
        .expect("Delete directory");
    final_post.delete(&mut tx).await.expect("Execute query");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("Commit transaction");
}

/// Tests reviewing a post with a small image.
#[tokio::test]
async fn approve_post_with_small_image() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let user = test_user(None);
    let post = create_test_post(&mut tx, &user, Some("small.png"), PostStatus::Pending).await;
    let encrypted_media_path = post.encrypted_media_path();
    let user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("Commit transaction");

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
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("Execute query")
        .unwrap();
    tx.commit().await.expect("Commit transaction");
    assert_eq!(post.status, PostStatus::Processing);

    // Poll for completion - wait until the post is no longer in processing state
    let max_attempts = 10;
    let wait_time = std::time::Duration::from_millis(500);
    let mut processed = false;

    for _ in 0..max_attempts {
        tokio::time::sleep(wait_time).await;
        let mut tx = state.db.begin().await.expect("Begin transaction");
        let updated_post = Post::select_by_key(&mut tx, &post.key)
            .await
            .expect("Execute query")
            .unwrap();
        tx.commit().await.expect("Commit transaction");

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
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let final_post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("Execute query")
        .unwrap();
    PostReview::delete_media_key_dir(&post.key)
        .await
        .expect("Delete directory");
    final_post.delete(&mut tx).await.expect("Execute query");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("Commit transaction");
}

/// Tests reviewing a post with a compatible video.
#[tokio::test]
async fn approve_post_with_compatible_video() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let user = test_user(None);
    let post = create_test_post(&mut tx, &user, Some("video.mp4"), PostStatus::Pending).await;
    let encrypted_media_path = post.encrypted_media_path();
    let user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("Commit transaction");

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
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("Execute query")
        .unwrap();
    tx.commit().await.expect("Commit transaction");
    assert_eq!(post.status, PostStatus::Processing);

    // Poll for completion - wait until the post is no longer in processing state
    let max_attempts = 10;
    let wait_time = std::time::Duration::from_millis(500);
    let mut processed = false;

    for _ in 0..max_attempts {
        tokio::time::sleep(wait_time).await;
        let mut tx = state.db.begin().await.expect("Begin transaction");
        let post = Post::select_by_key(&mut tx, &post.key)
            .await
            .expect("Execute query")
            .unwrap();
        tx.commit().await.expect("Commit transaction");

        if post.status != PostStatus::Processing {
            processed = true;

            // After processing completes, verify all assets were created
            let uploads_key_dir = encrypted_media_path.parent().unwrap();
            assert!(!uploads_key_dir.exists());
            assert!(post.published_media_path().exists());
            assert!(post.thumb_filename.is_none());
            assert!(post.compat_video.is_none());
            assert!(post.media_width.is_some());
            assert!(post.media_height.is_some());

            break;
        }
    }

    assert!(
        processed,
        "Background processing did not complete in the expected time"
    );

    // Clean up
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let final_post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("Execute query")
        .unwrap();
    PostReview::delete_media_key_dir(&post.key)
        .await
        .expect("Delete directory");
    final_post.delete(&mut tx).await.expect("Execute query");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("Commit transaction");
}

#[tokio::test]
async fn approve_post_with_incompatible_video() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let user = test_user(None);
    let post = create_test_post(&mut tx, &user, Some("video.webm"), PostStatus::Pending).await;
    let encrypted_media_path = post.encrypted_media_path();
    let user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("Commit transaction");

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
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("Execute query")
        .unwrap();
    tx.commit().await.expect("Commit transaction");
    assert_eq!(post.status, PostStatus::Processing);

    // Poll for completion - wait until the post is no longer in processing state
    let max_attempts = 10;
    let wait_time = std::time::Duration::from_millis(500);
    let mut processed = false;

    for _ in 0..max_attempts {
        tokio::time::sleep(wait_time).await;
        let mut tx = state.db.begin().await.expect("Begin transaction");
        let post = Post::select_by_key(&mut tx, &post.key)
            .await
            .expect("Execute query")
            .unwrap();
        tx.commit().await.expect("Commit transaction");

        if post.status != PostStatus::Processing {
            processed = true;

            // After processing completes, verify all assets were created
            let uploads_key_dir = encrypted_media_path.parent().unwrap();
            assert!(!uploads_key_dir.exists());
            assert!(post.published_media_path().exists());
            assert!(post.thumb_filename.is_none());
            assert!(post.compat_video.is_some());
            assert!(post.compat_video_path().exists());
            assert!(post.media_width.is_some());
            assert!(post.media_height.is_some());

            break;
        }
    }

    assert!(
        processed,
        "Background processing did not complete in the expected time"
    );

    // Clean up
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let final_post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("Execute query")
        .unwrap();
    PostReview::delete_media_key_dir(&post.key)
        .await
        .expect("Delete directory");
    final_post.delete(&mut tx).await.expect("Execute query");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("Commit transaction");
}

/// Tests a mod reporting an approved post, which should re-encrypt the media file.
#[tokio::test]
async fn mod_reports_approved_post() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let user = test_user(None);
    // Create a post with status Approved and a media file
    let post = create_test_post(&mut tx, &user, Some("image.jpeg"), PostStatus::Approved).await;

    // Create a mod account
    let mod_user = create_test_account(&mut tx, AccountRole::Mod).await;
    let mod_account = mod_user.account.as_ref().unwrap();
    tx.commit().await.expect("Commit transaction");

    // Mod reports the approved post
    let post_review = PostReview {
        session_token: mod_user.session_token,
        status: PostStatus::Reported,
    };
    let post_review_str = serde_urlencoded::to_string(&post_review).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/review/{}", &post.key))
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, mod_account.token))
        .header(
            COOKIE,
            format!("{}={}", SESSION_COOKIE, mod_user.session_token),
        )
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(post_review_str))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Wait for background processing to complete
    let max_attempts = 10;
    let wait_time = std::time::Duration::from_millis(500);
    let mut processed = false;
    for _ in 0..max_attempts {
        tokio::time::sleep(wait_time).await;
        let mut tx = state.db.begin().await.expect("Begin transaction");
        let post = Post::select_by_key(&mut tx, &post.key)
            .await
            .expect("Execute query")
            .unwrap();
        tx.commit().await.expect("Commit transaction");
        // The post should now be in Reported status
        if post.status == PostStatus::Reported {
            // The published media file should have been re-encrypted (i.e., removed from published location)
            assert!(
                !post.published_media_path().exists(),
                "Published media should be removed"
            );
            // The encrypted media file should exist again
            assert!(
                post.encrypted_media_path().exists(),
                "Encrypted media should exist after re-encryption"
            );
            processed = true;
            break;
        }
    }
    assert!(
        processed,
        "Background processing did not complete in the expected time"
    );

    // Clean up
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let final_post = Post::select_by_key(&mut tx, &post.key)
        .await
        .expect("Execute query")
        .unwrap();
    PostReview::delete_upload_key_dir(&post.key)
        .await
        .expect("Delete directory");
    final_post.delete(&mut tx).await.expect("Execute query");
    delete_test_account(&mut tx, mod_account).await;
    tx.commit().await.expect("Commit transaction");
}

/// Tests IP hash scrubbing for old posts.
#[tokio::test]
async fn scrub_ips() {
    let (_router, state) = init_test().await;
    let ip_hash = sha256::digest(apabbs::secret_key() + BAN_IP);
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let key = PostSubmission::generate_key(&mut tx)
        .await
        .expect("Generate test key");

    // Insert the post directly using SQL to set created_at in the past
    sqlx::query(concat!(
        "INSERT INTO posts (body, status, key, ip_hash, created_at) ",
        "VALUES ($1, 'approved', $2, $3, now() - interval '2 days') ",
        "RETURNING id"
    ))
    .bind("test body")
    .bind(&key)
    .bind(&ip_hash)
    .execute(&mut *tx)
    .await
    .expect("Insert test post");

    // Run the scrub command
    let result = apabbs::ban::scrub(&mut tx).await;
    assert!(result.is_ok(), "Scrub should succeed: {result:?}");

    // Verify the post no longer has an ip_hash
    let post = Post::select_by_key(&mut tx, &key)
        .await
        .expect("Select post by key after scrub")
        .unwrap();
    assert!(
        post.ip_hash.is_none(),
        "ip_hash should be scrubbed (set to NULL)"
    );

    // Clean up
    post.delete(&mut tx).await.expect("Delete test post");
    tx.commit().await.expect("Commit transaction");
}
