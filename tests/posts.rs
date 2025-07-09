//! Post-related integration tests (creation, viewing, pagination, media, hiding, interim, etc.)

mod helpers;

use apabbs::{
    post::{MediaCategory, Post, PostStatus::*, review::PostReview, submission::PostHiding},
    router::{
        ROOT,
        helpers::{ACCOUNT_COOKIE, SESSION_COOKIE, X_REAL_IP},
    },
    user::AccountRole,
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
    APPLICATION_WWW_FORM_URLENCODED, LOCAL_IP, create_test_account, create_test_post,
    delete_test_account, init_test, response_adds_cookie, response_body_str, test_user,
};
use http_body_util::BodyExt;
use std::path::Path;
use tower::ServiceExt;

use crate::helpers::{
    TEST_MEDIA_DIR, select_latest_post_by_account_id, select_latest_post_by_session_token,
};

/// Tests the 404 Not Found handler.
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

/// Tests the index page rendering and session creation.
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
    assert!(body_str.contains(r#"<div id="posts">"#));
    assert!(body_str.contains(&apabbs::host()));
}

/// Tests viewing a single post page.
#[tokio::test]
async fn solo_post() {
    let (router, state) = init_test().await;

    // Create a test post
    let user = test_user(None);
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let post = create_test_post(&mut tx, &user, None, Approved).await;
    tx.commit().await.expect("Commit transaction");

    // Request the post page
    let uri = format!("/p/{}", &post.key);
    let request = Request::builder()
        .uri(&uri)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();

    // Verify response
    assert!(response.status().is_success());
    assert!(response_adds_cookie(&response, SESSION_COOKIE));
    let body_str = response_body_str(response).await;
    assert!(!body_str.contains(r#"<div id="posts">"#));
    assert!(body_str.contains(r#"<div id="created-at">"#));

    // Clean up
    let mut tx = state.db.begin().await.expect("Begin transaction");
    post.delete(&mut tx).await.expect("Execute query");
    tx.commit().await.expect("Commit transaction");
}

/// Tests pagination for the index page.
#[tokio::test]
async fn index_with_page() {
    let (router, state) = init_test().await;

    // Create test posts
    let user = test_user(None);
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let post1 = create_test_post(&mut tx, &user, None, Approved).await;
    let post2 = create_test_post(&mut tx, &user, None, Approved).await;
    let post3 = create_test_post(&mut tx, &user, None, Approved).await;
    tx.commit().await.expect("Commit transaction");

    // Request a specific page
    let uri = format!("/page/{}", &post2.key);
    let request = Request::builder()
        .uri(&uri)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();

    // Verify pagination behavior
    assert!(response.status().is_success());
    assert!(response_adds_cookie(&response, SESSION_COOKIE));

    let body_str = response_body_str(response).await;
    assert!(body_str.contains(&post1.key));
    assert!(body_str.contains(&post2.key));
    assert!(!body_str.contains(&post3.key));

    // Check post order
    let post1_index = body_str.find(&post1.key).unwrap();
    let post2_index = body_str.find(&post2.key).unwrap();
    assert!(post2_index < post1_index);

    // Clean up
    let mut tx = state.db.begin().await.expect("Begin transaction");
    post1.delete(&mut tx).await.expect("Execute query");
    post2.delete(&mut tx).await.expect("Execute query");
    post3.delete(&mut tx).await.expect("Execute query");
    tx.commit().await.expect("Commit transaction");
}

/// Tests submitting a text-only post.
#[tokio::test]
async fn submit_post_without_media() {
    let (router, state) = init_test().await;
    let user = test_user(None);

    // Create form data
    let mut form = FormData::new(Vec::new());
    form.write_field("session_token", &user.session_token.to_string())
        .unwrap();
    form.write_field("body", "<&test body").unwrap();

    // Submit the post
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

    // Verify post was created correctly
    let mut tx = state.db.begin().await.expect("Begin transaction");
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

    // Clean up
    post.delete(&mut tx).await.expect("Execute query");
    tx.commit().await.expect("Commit transaction");
}

/// Tests submitting a post with an image attachment.
#[tokio::test]
async fn submit_post_with_media() {
    let (router, state) = init_test().await;
    let user = test_user(None);

    // Create form data with image
    let mut form = FormData::new(Vec::new());
    let test_image_path = Path::new(TEST_MEDIA_DIR).join("image.jpeg");
    form.write_field("session_token", &user.session_token.to_string())
        .unwrap();
    form.write_field("body", "").unwrap();
    form.write_path("media", test_image_path, "image/jpeg")
        .unwrap();

    // Submit the post
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

    // Verify post was created with media
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let post = select_latest_post_by_session_token(&mut tx, &user.session_token)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(post.body, "");
    assert_eq!(post.media_filename, Some(String::from("image.jpeg")));
    assert_eq!(post.media_category, Some(MediaCategory::Image));
    assert_eq!(post.media_mime_type, Some(String::from("image/jpeg")));

    // Clean up
    post.delete(&mut tx).await.expect("Execute query");
    tx.commit().await.expect("Commit transaction");
    PostReview::delete_upload_key_dir(&post.key)
        .await
        .expect("Delete directory");
}

/// Tests submitting a post while logged in with an account.
#[tokio::test]
async fn submit_post_with_account() {
    let (router, state) = init_test().await;

    // Create test account
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    tx.commit().await.expect("Commit transaction");
    let account = user.account.as_ref().unwrap();

    // Create form data
    let mut form = FormData::new(Vec::new());
    form.write_field("session_token", &user.session_token.to_string())
        .unwrap();
    form.write_field("body", "<&test body").unwrap();

    // Submit the post
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

    // Verify post was created with account association
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let account_post = select_latest_post_by_account_id(&mut tx, account.id)
        .await
        .unwrap();
    let anon_post = select_latest_post_by_session_token(&mut tx, &user.session_token).await;

    assert!(anon_post.is_none());
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(account_post.account_id, Some(account.id));
    assert_eq!(account_post.session_token, None);

    // Clean up
    account_post.delete(&mut tx).await.expect("Execute query");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("Commit transaction");
}

/// Tests hiding a post from the user interface.
#[tokio::test]
async fn hide_post() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let user = test_user(None);

    // Create a post and admin user
    let post = create_test_post(&mut tx, &user, None, Pending).await;
    let admin_user = create_test_account(&mut tx, AccountRole::Admin).await;
    let account = admin_user.account.as_ref().unwrap();
    post.update_status(&mut tx, Rejected)
        .await
        .expect("Execute query");
    tx.commit().await.expect("Commit transaction");

    // Submit hide post request
    let post_hiding = PostHiding {
        session_token: user.session_token,
        key: post.key.clone(),
    };
    let post_hiding_str = serde_urlencoded::to_string(&post_hiding).expect("serializes");
    let request = Request::builder()
        .method(Method::POST)
        .uri("/hide-post")
        .header(
            COOKIE,
            format!("{}={}", SESSION_COOKIE, &user.session_token),
        )
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(post_hiding_str))
        .expect("Build request");

    let response = router.oneshot(request).await.expect("request succeeds");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Clean up
    let mut tx = state.db.begin().await.expect("Begin transaction");
    post.delete(&mut tx).await.expect("Execute query");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("Commit transaction");
}

/// Tests interim post visibility (posts not yet approved).
#[tokio::test]
async fn interim() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let user = test_user(None);

    // Create approved and pending posts
    let post1 = create_test_post(&mut tx, &user, None, Approved).await;
    let post2 = create_test_post(&mut tx, &user, None, Approved).await;
    let post3 = create_test_post(&mut tx, &user, None, Approved).await;
    tx.commit().await.expect("Commit transaction");

    // Request the interim page
    let request = Request::builder()
        .uri(format!("/interim/{}", &post1.key))
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())
        .expect("Build request");
    let response = router.oneshot(request).await.expect("Execute request");

    // Verify response
    assert!(response.status().is_success());
    let body_str = response_body_str(response).await;
    assert!(!body_str.contains(&post1.key));
    assert!(body_str.contains(&post2.key));
    assert!(body_str.contains(&post3.key));

    // Check post order
    let post2_index = body_str.find(&post2.key).unwrap();
    let post3_index = body_str.find(&post3.key).unwrap();
    assert!(post2_index < post3_index);

    // Clean up
    let mut tx = state.db.begin().await.expect("Begin transaction");
    post1.delete(&mut tx).await.expect("Execute query");
    post2.delete(&mut tx).await.expect("Execute query");
    post3.delete(&mut tx).await.expect("Execute query");
    tx.commit().await.expect("Commit transaction");
}

/// Tests establishing a WebSocket connection and receiving real-time updates.
#[tokio::test]
async fn websocket_connection() {
    use axum::http::Uri;
    use futures::StreamExt;
    use tokio_tungstenite::tungstenite;

    let (router, state) = init_test().await;

    // Create a test post to trigger notifications
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let user = test_user(None);
    let test_post = create_test_post(&mut tx, &user, None, Approved).await;
    tx.commit().await.expect("Commit transaction");

    // Start a server for testing
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    // Create WebSocket client
    let ws_uri: Uri = format!("ws://{addr}/web-socket")
        .parse()
        .expect("Parse URI");
    let req = tungstenite::ClientRequestBuilder::new(ws_uri).with_header(X_REAL_IP, LOCAL_IP);
    let (mut ws_client, _) = tokio_tungstenite::connect_async(req)
        .await
        .expect("Connect WebSocket");

    // Send a post update through the broadcast channel
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await; // Give connection time to establish
    let mut tx = state.db.begin().await.expect("Begin transaction");
    let post = Post::select_by_key(&mut tx, &test_post.key)
        .await
        .expect("Execute query")
        .unwrap();
    tx.commit().await.expect("Commit transaction");
    state.sender.send(post.clone()).expect("Send post");

    // Wait for and verify message reception
    let message = tokio::time::timeout(tokio::time::Duration::from_secs(2), ws_client.next())
        .await
        .expect("Wait for message")
        .expect("Receive message")
        .unwrap();

    // Check content
    match message {
        tungstenite::Message::Text(text) => {
            let json: serde_json::Value = serde_json::from_str(&text).expect("Parse JSON");
            assert_eq!(json["key"], post.key);
            assert!(json["html"].as_str().unwrap().contains(&post.key));
        }
        other => panic!("Expected text message, got {other:?}"),
    }

    // Clean up
    ws_client.close(None).await.unwrap();
    server_handle.abort(); // Stop the server

    let mut tx = state.db.begin().await.expect("Begin transaction");
    test_post.delete(&mut tx).await.expect("Execute query");
    tx.commit().await.expect("Commit transaction");
}

/// Tests the conversion of post body text to HTML with YouTube embed generation.
#[tokio::test]
pub async fn body_to_html() {
    use apabbs::post::submission::{PostSubmission, YOUTUBE_DIR};
    apabbs::init_tracing_for_test();
    // Setup test with various types of content:
    // - HTML special characters
    // - Line breaks
    // - Regular URLs
    // - YouTube links in different formats
    let submission = PostSubmission {
        body: concat!(
            "<&test body\"' コンピューター\n\n",
            "https://example.com\n",
            " https://m.youtube.com/watch?v=jNQXAC9IVRw\n",
            "https://youtu.be/kixirmHePCc?si=q9OkPEWRQ0RjoWg&t=3\n",
            "http://youtube.com/shorts/cHMCGCWit6U?si=q9OkPEWRQ0RjoWg \n",
            "https://example.com?m.youtube.com/watch?v=jNQXAC9IVRw\n",
            "foo https://www.youtube.com/watch?v=ySrBS4ulbmQ&t=2m1s\n\n",
            "https://www.youtube.com/watch?v=ySrBS4ulbmQ bar\n",
            "https://www.youtube.com/watch?t=10s&app=desktop&v=28jr-6-XDPM",
        )
        .to_string(),
        ..PostSubmission::default()
    };

    // Keep track of existing test directories to avoid deleting user data
    let test_ids = [
        "jNQXAC9IVRw",
        "kixirmHePCc",
        "cHMCGCWit6U",
        "28jr-6-XDPM",
        "ySrBS4ulbmQ",
        "dQw4w9WgXcQ",
    ];
    let mut existing_ids = Vec::new();
    for id in test_ids {
        if std::path::Path::new(YOUTUBE_DIR).join(id).exists() {
            existing_ids.push(id);
        }
    }

    // Run the test
    let key = "testkey1";
    assert_eq!(
        submission.body_to_html(key).await.unwrap(),
        concat!(
            "&lt;&amp;test body&quot;&apos; コンピューター<br>\n",
            "<br>\n",
            "<a href=\"https://example.com\" rel=\"noopener\" target=\"_blank\">",
            "https://example.com</a><br>\n",
            "<div class=\"youtube\">\n",
            "    <div class=\"youtube-logo\">\n",
            "        <a href=\"https://www.youtube.com/watch?v=jNQXAC9IVRw\" ",
            "rel=\"noopener\" target=\"_blank\">",
            "<img src=\"/youtube.svg\" alt=\"YouTube jNQXAC9IVRw\" width=\"20\" height=\"20\">",
            "</a>\n",
            "    </div>\n",
            "    <div class=\"youtube-thumbnail\">\n",
            "        <a href=\"/p/testkey1\">",
            "<img src=\"/youtube/jNQXAC9IVRw/hqdefault.jpg\" alt=\"Post testkey1\" ",
            "width=\"480\" height=\"360\">",
            "</a>\n",
            "    </div>\n",
            "</div>\n",
            "<div class=\"youtube\">\n",
            "    <div class=\"youtube-logo\">\n",
            "        <a href=\"https://www.youtube.com/watch?v=kixirmHePCc&amp;t=3\" ",
            "rel=\"noopener\" target=\"_blank\">",
            "<img src=\"/youtube.svg\" alt=\"YouTube kixirmHePCc\" width=\"20\" height=\"20\">",
            "</a>\n",
            "    </div>\n",
            "    <div class=\"youtube-thumbnail\">\n",
            "        <a href=\"/p/testkey1\">",
            "<img src=\"/youtube/kixirmHePCc/maxresdefault.jpg\" alt=\"Post testkey1\" ",
            "width=\"1280\" height=\"720\">",
            "</a>\n",
            "    </div>\n",
            "</div>\n",
            "<div class=\"youtube\">\n",
            "    <div class=\"youtube-logo\">\n",
            "        <a href=\"https://www.youtube.com/shorts/cHMCGCWit6U\" ",
            "rel=\"noopener\" target=\"_blank\">",
            "<img src=\"/youtube.svg\" alt=\"YouTube cHMCGCWit6U\" width=\"20\" height=\"20\">",
            "</a>\n",
            "    </div>\n",
            "    <div class=\"youtube-thumbnail\">\n",
            "        <a href=\"/p/testkey1\">",
            "<img src=\"/youtube/cHMCGCWit6U/oar2.jpg\" alt=\"Post testkey1\" ",
            "width=\"1080\" height=\"1920\">",
            "</a>\n",
            "    </div>\n",
            "</div>\n",
            "<a href=\"https://example.com?m.youtube.com/watch?v=jNQXAC9IVRw\" ",
            "rel=\"noopener\" target=\"_blank\">",
            "https://example.com?m.youtube.com/watch?v=jNQXAC9IVRw",
            "</a><br>\n",
            "foo ",
            "<a href=\"https://www.youtube.com/watch?v=ySrBS4ulbmQ&amp;t=2m1s\" ",
            "rel=\"noopener\" target=\"_blank\">",
            "https://www.youtube.com/watch?v=ySrBS4ulbmQ&amp;t=2m1s",
            "</a><br>\n",
            "<br>\n",
            "<a href=\"https://www.youtube.com/watch?v=ySrBS4ulbmQ\" ",
            "rel=\"noopener\" target=\"_blank\">",
            "https://www.youtube.com/watch?v=ySrBS4ulbmQ",
            "</a> bar<br>\n",
            "<div class=\"youtube\">\n",
            "    <div class=\"youtube-logo\">\n",
            "        <a href=\"https://www.youtube.com/watch?v=28jr-6-XDPM&amp;t=10s\" ",
            "rel=\"noopener\" target=\"_blank\">",
            "<img src=\"/youtube.svg\" alt=\"YouTube 28jr-6-XDPM\" width=\"20\" height=\"20\">",
            "</a>\n",
            "    </div>\n",
            "    <div class=\"youtube-thumbnail\">\n",
            "        <a href=\"/p/testkey1\">",
            "<img src=\"/youtube/28jr-6-XDPM/hqdefault.jpg\" alt=\"Post testkey1\" ",
            "width=\"480\" height=\"360\">",
            "</a>\n",
            "    </div>\n",
            "</div>",
        )
    );

    // Clean up test data but preserve any existing directories
    for id in test_ids {
        if !existing_ids.contains(&id) {
            tokio::fs::remove_dir_all(std::path::Path::new(YOUTUBE_DIR).join(id))
                .await
                .ok(); // Use ok() to ignore errors if directory doesn't exist
        }
    }
}
