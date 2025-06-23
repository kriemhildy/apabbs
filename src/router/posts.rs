//! Post content routes and real-time update handlers.
//!
//! This module provides endpoints for displaying, submitting, hiding, and streaming posts.
//! It supports pagination, single post views, post creation with media, and websocket updates.

use super::*;
use axum::extract::{
    Multipart,
    ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade},
};
use std::collections::HashMap;

/// Handles the main index page and paginated content.
///
/// Renders the home page with a list of posts, supporting pagination through
/// the optional page key parameter.
pub async fn index(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Path(path): Path<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN_FAILED_ERR);

    // Initialize user from session
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };

    // Handle pagination parameter if present
    let page_post = match path.get("key") {
        Some(key) => match init_post(&mut tx, key, &user).await {
            Err(response) => return response,
            Ok(post) => Some(post),
        },
        None => None,
    };

    // Get posts for current page
    let page_post_id = page_post.as_ref().map(|p| p.id);
    let mut posts = Post::select(&mut tx, &user, page_post_id, false).await;

    // Check if there's a next page by seeing if we got more posts than our page size
    let prior_page_post = if posts.len() <= crate::per_page() {
        None
    } else {
        posts.pop()
    };

    // Get a timestamp of the current UTC hour for cache-busting the screenshot file
    let utc_hour_timestamp = utc_hour_timestamp(&mut tx).await;

    // Render the page
    let html = Html(render(
        &state,
        "index.jinja",
        minijinja::context!(
            dev => crate::dev(),
            host => crate::host(),
            user_agent => analyze_user_agent(&headers),
            nav => true,
            user,
            posts,
            page_post,
            prior_page_post,
            solo => false,
            utc_hour_timestamp,
        ),
    ));

    (jar, html).into_response()
}

/// Displays a single post in full-page view.
///
/// Renders a dedicated page for viewing a single post by its unique key.
pub async fn solo_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN_FAILED_ERR);

    // Initialize user from session
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };

    // Get the requested post
    let post = match init_post(&mut tx, &key, &user).await {
        Err(response) => return response,
        Ok(post) => post,
    };

    // Render the page
    let html = Html(render(
        &state,
        "solo.jinja",
        minijinja::context!(
            dev => crate::dev(),
            host => crate::host(),
            user_agent => analyze_user_agent(&headers),
            user,
            post,
            solo => true,
        ),
    ));

    (jar, html).into_response()
}

/// Handles post submission.
///
/// Processes new post creation with optional media attachments.
pub async fn submit_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN_FAILED_ERR);

    // Parse multipart form data
    let mut post_submission = PostSubmission::default();
    while let Some(field) = multipart
        .next_field()
        .await
        .expect("Failed to read multipart field")
    {
        let name = field
            .name()
            .expect("Multipart field missing name")
            .to_owned();
        match name.as_str() {
            "session_token" => {
                post_submission.session_token = match Uuid::try_parse(
                    &field
                        .text()
                        .await
                        .expect("Failed to read session_token field"),
                ) {
                    Err(_) => return bad_request("Invalid session token"),
                    Ok(uuid) => uuid,
                };
            }
            "body" => post_submission.body = field.text().await.expect("Failed to read body field"),
            "media" => {
                if post_submission.media_filename.is_some() {
                    return bad_request("Only one media file can be uploaded");
                }
                let filename = match field.file_name() {
                    None => return bad_request("Media file has no filename"),
                    Some(filename) => filename.to_owned(),
                };
                if filename.is_empty() {
                    continue;
                }
                post_submission.media_filename = Some(filename);
                post_submission.media_bytes = Some(
                    field
                        .bytes()
                        .await
                        .expect("Failed to read media bytes")
                        .to_vec(),
                );
            }
            _ => return bad_request(&format!("Unexpected field: {name}")),
        };
    }

    // Get user IP hash for tracking
    let ip_hash = ip_hash(&headers);

    // Initialize user from session
    let (user, jar) =
        match init_user(jar, &mut tx, method, Some(post_submission.session_token)).await {
            Err(response) => return response,
            Ok(tuple) => tuple,
        };

    // Check if user is banned
    if let Some(response) =
        check_for_ban(&mut tx, &ip_hash, user.account.as_ref().map(|a| a.id), None).await
    {
        tx.commit().await.expect(COMMIT_FAILED_ERR);
        return response;
    }

    // Validate post content
    if post_submission.body.is_empty() && post_submission.media_filename.is_none() {
        return bad_request("Post cannot be empty unless there is a media file");
    }

    // Generate unique key and insert post
    let key = PostSubmission::generate_key(&mut tx).await;
    let post = post_submission.insert(&mut tx, &user, &ip_hash, &key).await;

    // Handle media file encryption if present
    if post_submission.media_filename.is_some() {
        if let Err(msg) = post_submission.encrypt_uploaded_file(&post).await {
            return internal_server_error(msg);
        }
    }

    tx.commit().await.expect(COMMIT_FAILED_ERR);

    // Notify clients of new post
    if state.sender.send(post).is_err() {
        println!("No active receivers to send to");
    }

    // Return appropriate response based on request type
    let response = if is_fetch_request(&headers) {
        StatusCode::CREATED.into_response()
    } else {
        Redirect::to(ROOT).into_response()
    };

    (jar, response).into_response()
}

/// Hides a post from the user's view.
///
/// Allows users to hide their rejected posts from view.
pub async fn hide_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(post_hiding): Form<PostHiding>,
) -> Response {
    use PostStatus::*;
    let mut tx = state.db.begin().await.expect(BEGIN_FAILED_ERR);

    // Initialize user from session
    let (user, jar) = match init_user(jar, &mut tx, method, Some(post_hiding.session_token)).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };

    // Process post hiding if authorized and eligible
    if let Some(post) = Post::select_by_key(&mut tx, &post_hiding.key).await {
        if !post.author(&user) {
            return unauthorized("You are not the author of this post");
        }
        match post.status {
            Rejected => {
                post_hiding.hide_post(&mut tx).await;
                tx.commit().await.expect(COMMIT_FAILED_ERR);
            }
            Reported | Banned => (),
            _ => return bad_request("Post is not rejected, reported, or banned"),
        }
    };

    // Return appropriate response based on request type
    let response = if is_fetch_request(&headers) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        Redirect::to(ROOT).into_response()
    };

    (jar, response).into_response()
}

/// Handles WebSocket connections for real-time updates.
///
/// Establishes a persistent connection to send new posts to the client as they're created.
pub async fn web_socket(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    upgrade: WebSocketUpgrade,
) -> Response {
    use tokio::sync::broadcast::Receiver;

    /// Inner function to process the WebSocket connection
    async fn watch_receiver(
        State(state): State<AppState>,
        mut socket: WebSocket,
        mut receiver: Receiver<Post>,
        user: User,
    ) {
        use AccountRole::*;
        use PostStatus::*;

        while let Ok(post) = receiver.recv().await {
            // Determine if this post should be sent to the user
            let should_send = post.author(&user)
                || match user.account {
                    None => post.status == Approved,
                    Some(ref account) => match account.role {
                        Admin => true,
                        Mod => [Pending, Approved, Delisted, Reported].contains(&post.status),
                        Member | Novice => post.status == Approved,
                    },
                };

            if !should_send {
                continue;
            }

            // Render post HTML and send as JSON
            let html = render(&state, "post.jinja", minijinja::context!(post, user));
            let json_utf8 =
                Utf8Bytes::from(serde_json::json!({"key": post.key, "html": html}).to_string());

            if socket.send(Message::Text(json_utf8)).await.is_err() {
                break; // client disconnect
            }
        }
    }

    let mut tx = state.db.begin().await.expect(BEGIN_FAILED_ERR);

    // Initialize user from session
    let (user, _jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };

    // Subscribe to broadcast channel and upgrade connection
    let receiver = state.sender.subscribe();
    upgrade.on_upgrade(move |socket| watch_receiver(State(state), socket, receiver, user))
}

/// Fetches posts created after the latest approved post.
///
/// Used for recovering updates since websocket interruption.
pub async fn interim(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Path(key): Path<String>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN_FAILED_ERR);

    // Initialize user from session
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };

    // Get the reference post
    let since_post = match init_post(&mut tx, &key, &user).await {
        Err(response) => return response,
        Ok(post) => post,
    };

    // Fetch newer posts
    let since_post_id = Some(since_post.id);
    let new_posts = Post::select(&mut tx, &user, since_post_id, true).await;

    if new_posts.is_empty() {
        return (jar, StatusCode::NO_CONTENT).into_response();
    }

    // Build JSON response with rendered HTML for each post
    let mut json_posts: Vec<serde_json::Value> = Vec::new();
    for post in new_posts {
        let html = render(&state, "post.jinja", minijinja::context!(post, user));
        json_posts.push(serde_json::json!({
            "key": post.key,
            "html": html
        }));
    }

    let json = serde_json::json!({"posts": json_posts}).to_string();
    (jar, json).into_response()
}
