mod helpers;

use apabbs::{
    cron::{screenshot_task, scrub_task},
    post::{Post, submission::PostSubmission},
};
use helpers::{BAN_IP, init_test};
use std::fs;

/// Tests the screenshot task to ensure it creates a screenshot file.
#[tokio::test]
async fn test_screenshot_task() {
    const TEST_SCREENSHOT_PATH: &str = "pub/test_screenshot.webp";

    assert!(
        fs::metadata(TEST_SCREENSHOT_PATH).is_err(),
        "Screenshot file should not exist before test"
    );
    screenshot_task(TEST_SCREENSHOT_PATH).await;
    assert!(
        fs::metadata(TEST_SCREENSHOT_PATH).is_ok(),
        "Screenshot file should exist"
    );
    // Clean up
    fs::remove_file(TEST_SCREENSHOT_PATH).expect("Remove test screenshot");
}

/// Tests IP hash scrubbing for old posts.
#[tokio::test]
async fn test_scrub_task() {
    let (_router, state) = init_test().await;
    let ip_hash = sha256::digest(apabbs::secret_key() + BAN_IP);
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let key = PostSubmission::generate_key(&mut tx)
        .await
        .expect("Generate test key");

    // Insert the post directly using SQL to set created_at in the past
    sqlx::query(concat!(
        "INSERT INTO posts (body, status, key, ip_hash, created_at) ",
        "VALUES ($1, 'approved', $2, $3, now() - interval '2 days')",
    ))
    .bind("test body")
    .bind(&key)
    .bind(&ip_hash)
    .execute(&mut *tx)
    .await
    .expect("Insert test post");
    tx.commit().await.expect("Commit transaction");

    // Run the scrub task
    scrub_task().await;

    // Verify the post no longer has an ip_hash
    let mut tx = state.db.begin().await.expect("Begin transaction");
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
