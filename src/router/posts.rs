//! Post content routes and real-time update handlers.
//!
//! This module provides endpoints for displaying, submitting, hiding, and streaming posts.
//! It supports pagination, single post views, post creation with media, and websocket updates.
//!
//! # Endpoints
//! - `index`: Home page and paginated post listing
//! - `solo_post`: Single post full-page view
//! - `submit_post`: Post creation with optional media
//! - `hide_post`: Hide rejected posts from user view
//! - `web_socket`: Real-time post updates via websocket
//! - `interim`: Fetch posts created after a reference post
//!
//! # Error Handling
//! - All errors are logged and returned as appropriate HTTP responses
//! - User-facing errors are clear and actionable
//!
//! # Real-Time Updates
//! - WebSocket endpoint streams new posts to clients
//! - Interim endpoint recovers missed posts after disconnect

use super::*;
use axum::extract::{
    Multipart,
    ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade},
};
use std::collections::HashMap;

// =========================
// Post Display Endpoints
// =========================

/// Handles the main index page and paginated content.
///
/// Renders the home page with a list of posts, supporting pagination through the optional page key parameter.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `Path(path)`: Path parameters as a map (for pagination key)
/// - `headers`: HTTP headers for user agent analysis
///
/// # Returns
/// A `Response` containing the rendered index page.
///
/// # Errors
/// Returns `InternalServerError` for database or rendering errors.
pub async fn index(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Path(path): Path<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Handle pagination parameter if present
    let page_post = match path.get("key") {
        Some(key) => Some(init_post(&mut tx, key, &user).await.map_err(|e| {
            tracing::error!("Failed to initialize page post: {:?}", e);
            e
        })?),
        None => None,
    };

    // Get posts for current page
    let page_post_id = page_post.as_ref().map(|p| p.id);
    let mut posts = Post::select(&mut tx, &user, page_post_id, false).await?;

    // Check if there's a next page by seeing if we got more posts than our page size
    let prior_page_post = if posts.len() <= crate::per_page() {
        None
    } else {
        posts.pop()
    };

    // Get a timestamp of the current UTC hour for cache-busting the screenshot file
    let utc_hour_timestamp = utc_hour_timestamp(&mut tx).await?;

    // Render the page
    let html = Html(render(
        &state,
        "index.jinja",
        minijinja::context!(
            dev => crate::dev(),
            host => crate::host(),
            nav => true,
            user,
            posts,
            page_post,
            prior_page_post,
            utc_hour_timestamp,
        ),
    ));

    Ok((jar, html).into_response())
}

/// Displays a single post in full-page view.
///
/// Renders a dedicated page for viewing a single post by its unique key.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `Path(key)`: Path parameter for the post key
/// - `headers`: HTTP headers for user agent analysis
///
/// # Returns
/// A `Response` containing the rendered solo post page.
///
/// # Errors
/// Returns `NotFound` if the post does not exist, or `InternalServerError` for database/rendering errors.
pub async fn solo_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Get the requested post
    let post = init_post(&mut tx, &key, &user).await.map_err(|e| {
        tracing::error!("Failed to initialize post: {:?}", e);
        e
    })?;

    // Render the page
    let html = Html(render(
        &state,
        "solo.jinja",
        minijinja::context!(
            dev => crate::dev(),
            host => crate::host(),
            user,
            post,
        ),
    ));

    Ok((jar, html).into_response())
}

// =========================
// Post Submission & Hiding
// =========================

/// Handles post submission.
///
/// Processes new post creation with optional media attachments.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `headers`: HTTP headers for IP hash and validation
/// - `multipart`: Multipart form data for post content and media
///
/// # Returns
/// A `Response` indicating the result of the post submission.
///
/// # Errors
/// Returns `BadRequest` for invalid input, `Banned` if user is banned, or `InternalServerError` for database/media errors.
#[axum::debug_handler]
pub async fn submit_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, ResponseError> {
    let mut tx = begin_transaction(&state.db).await?;

    // Parse multipart form data
    let mut post_submission = PostSubmission::default();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| BadRequest(format!("Failed to read field: {e}")))?
    {
        let name = field
            .name()
            .ok_or_else(|| BadRequest("Missing field name.".to_string()))?
            .to_owned();
        match name.as_str() {
            "session_token" => {
                post_submission.session_token = match Uuid::try_parse(
                    &field
                        .text()
                        .await
                        .map_err(|e| BadRequest(format!("Failed to read session token: {e}")))?,
                ) {
                    Err(e) => {
                        return Err(BadRequest(format!("Invalid session token: {e}")));
                    }
                    Ok(uuid) => uuid,
                };
            }
            "body" => {
                post_submission.body = field
                    .text()
                    .await
                    .map_err(|e| BadRequest(format!("Failed to read post body: {e}")))?
            }
            "media" => {
                if post_submission.media_filename.is_some() {
                    return Err(BadRequest(
                        "Only one media file can be uploaded.".to_string(),
                    ));
                }
                let filename = field
                    .file_name()
                    .ok_or_else(|| BadRequest("Media file has no filename.".to_string()))?
                    .to_owned();
                if filename.is_empty() {
                    continue;
                }
                post_submission.media_filename = Some(filename);
                post_submission.media_bytes = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| BadRequest(format!("Failed to read media file: {e}")))?
                        .to_vec(),
                );
            }
            _ => return Err(BadRequest(format!("Unexpected field: {name}"))),
        };
    }

    // Initialize user from session
    let (user, jar) = init_user(
        jar,
        &mut tx,
        method,
        &headers,
        Some(post_submission.session_token),
    )
    .await?;

    // Check for existing IP ban
    if let Some(expires_at) = user.ban_expires_at {
        return Err(Forbidden(format!(
            "You have been banned until {expires_at}."
        )));
    }

    // Ban user if they are flooding
    if let Some(expires_at) =
        ban_if_flooding(&mut tx, &user.ip_hash, user.account.as_ref().map(|a| a.id)).await?
    {
        commit_transaction(tx).await?;
        return Err(Forbidden(format!(
            "You have been banned for flooding until {expires_at}."
        )));
    }

    // Validate post content
    if post_submission.body.is_empty() && post_submission.media_filename.is_none() {
        return Err(BadRequest(
            "Post cannot be empty unless there is a media file.".to_string(),
        ));
    }

    // Generate unique key and insert post
    let key = PostSubmission::generate_key(&mut tx).await?;
    let post = post_submission.insert(&mut tx, &user, &key).await?;

    // Handle media file encryption if present
    if post_submission.media_filename.is_some() {
        if let Err(msg) = post_submission.encrypt_uploaded_file(&post).await {
            return Err(InternalServerError(format!(
                "Failed to encrypt media file: {msg}"
            )));
        }
    }

    commit_transaction(tx).await?;

    // Notify clients of new post
    send_to_websocket(&state.sender, post);

    // Return appropriate response based on request type
    let response = if is_fetch_request(&headers) {
        StatusCode::CREATED.into_response()
    } else {
        Redirect::to(ROOT).into_response()
    };

    Ok((jar, response).into_response())
}

/// Hides a post from the user's view.
///
/// Allows users to hide their rejected posts from view.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `headers`: HTTP headers for request context
/// - `Form(post_hiding)`: Form data containing the post hiding request
///
/// # Returns
/// A `Response` indicating the result of the hide action.
///
/// # Errors
/// Returns `Unauthorized` if the user is not the author, `BadRequest` for invalid status, or `InternalServerError` for database errors.
pub async fn hide_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(post_hiding): Form<PostHiding>,
) -> Result<Response, ResponseError> {
    use PostStatus::*;
    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session
    let (user, jar) = init_user(
        jar,
        &mut tx,
        method,
        &headers,
        Some(post_hiding.session_token),
    )
    .await?;

    // Process post hiding if authorized and eligible
    if let Some(post) = Post::select_by_key(&mut tx, &post_hiding.key).await? {
        if !post.author(&user) {
            return Err(Unauthorized(
                "You are not the author of this post.".to_string(),
            ));
        }
        match post.status {
            Rejected => {
                post_hiding.hide_post(&mut tx).await?;
                commit_transaction(tx).await?;
            }
            Reported | Banned => (),
            _ => {
                return Err(BadRequest(
                    "Post is not rejected, reported, or banned.".to_string(),
                ));
            }
        }
    }

    // Return appropriate response based on request type
    let response = if is_fetch_request(&headers) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        Redirect::to(ROOT).into_response()
    };

    Ok((jar, response).into_response())
}

// =========================
// Real-Time & Interim Updates
// =========================

/// Handles WebSocket connections for real-time updates.
///
/// Establishes a persistent connection to send new posts to the client as they're created.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `upgrade`: WebSocket upgrade request
///
/// # Returns
/// A `Response` that upgrades the connection to a WebSocket.
///
/// # Errors
/// Returns `InternalServerError` for database or websocket errors.
pub async fn web_socket(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ResponseError> {
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
            let html = match render(&state, "post.jinja", minijinja::context!(post, user)) {
                Ok(html) => html,
                Err(e) => {
                    tracing::error!("Failed to render post for websocket: {:?}", e);
                    continue;
                }
            };
            let json_utf8 =
                Utf8Bytes::from(serde_json::json!({"key": post.key, "html": html}).to_string());

            if socket.send(Message::Text(json_utf8)).await.is_err() {
                break; // client disconnect
            }
        }
    }

    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session
    let (user, _jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Subscribe to broadcast channel and upgrade connection
    let receiver = state.sender.subscribe();
    let state_clone = state.clone();
    Ok(
        upgrade
            .on_upgrade(move |socket| watch_receiver(State(state_clone), socket, receiver, user)),
    )
}

/// Fetches posts created after the latest approved post.
///
/// Used for recovering updates since websocket interruption.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `Path(key)`: Path parameter for the reference post key
///
/// # Returns
/// A `Response` containing new posts as rendered HTML in JSON format.
///
/// # Errors
/// Returns `NotFound` if the reference post does not exist, or `InternalServerError` for database/rendering errors.
pub async fn interim(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Response, ResponseError> {
    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Get the reference post
    let since_post = init_post(&mut tx, &key, &user).await.map_err(|e| {
        tracing::error!("Failed to initialize reference post: {:?}", e);
        e
    })?;

    // Fetch newer posts
    let since_post_id = Some(since_post.id);
    let new_posts = Post::select(&mut tx, &user, since_post_id, true).await?;

    if new_posts.is_empty() {
        return Ok((jar, StatusCode::NO_CONTENT).into_response());
    }

    // Build JSON response with rendered HTML for each post
    let mut json_posts: Vec<serde_json::Value> = Vec::new();
    for post in new_posts {
        let html = render(&state, "post.jinja", minijinja::context!(post, user))?;
        json_posts.push(serde_json::json!({
            "key": post.key,
            "html": html
        }));
    }

    let json = serde_json::json!({"posts": json_posts}).to_string();
    Ok((jar, json).into_response())
}
