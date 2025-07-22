//! Post content routes and real-time update handlers.
//!
//! This module provides endpoints for displaying, submitting, hiding, and streaming posts.
//! It supports pagination, single post views, post creation with media, and websocket updates.

use super::{
    ROOT,
    errors::ResponseError,
    helpers::{ban_if_flooding, init_post, init_user, is_fetch_request},
};
use crate::{
    AppMessage, AppState,
    ban::{self, Ban},
    post::{
        Post, PostStatus, media,
        submission::{self, PostHiding, PostSubmission},
    },
    user::{Account, User},
    utils::{render, utc_hour_timestamp},
};
use axum::{
    Form,
    extract::{
        Multipart, Path, State,
        ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, Method, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use std::collections::HashMap;
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;

// =========================
// Post Display Endpoints
// =========================

/// Handles the main index page and paginated content.
pub async fn index(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Path(path): Path<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Handle pagination parameter if present
    let page_post = match path.get("key") {
        Some(key) => Some(init_post(&mut tx, key, &user).await?),
        None => None,
    };

    // Get posts for current page
    let page_post_id = page_post.as_ref().map(|p| p.id);
    let mut posts = Post::select(&mut tx, &user, page_post_id, false).await?;

    // Check if there's a next page by seeing if we got more posts than our page size
    let next_page_post = if posts.len() <= crate::per_page() {
        None
    } else {
        posts.pop()
    };

    // Get a timestamp of the current UTC hour for cache-busting the screenshot file
    let utc_hour_timestamp = utc_hour_timestamp(&mut tx).await?;

    // Check for pending accounts so that admins can review them
    let pending_accounts = if user.admin() {
        Account::select_pending(&mut tx).await?
    } else {
        Vec::new()
    };

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
            next_page_post,
            utc_hour_timestamp,
            pending_accounts,
        ),
    )?);

    Ok((jar, html).into_response())
}

/// Displays a single post in full-page view.
pub async fn solo_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Get the requested post
    let post = init_post(&mut tx, &key, &user).await?;

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
    )?);

    Ok((jar, html).into_response())
}

// =========================
// Post Submission & Hiding
// =========================

/// Handles post submission with optional media attachments.
pub async fn submit_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Parse multipart form data
    let mut post_submission = PostSubmission::default();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ResponseError::BadRequest(format!("Failed to read field: {e}")))?
    {
        let name = field
            .name()
            .ok_or_else(|| ResponseError::BadRequest("Missing field name.".to_string()))?
            .to_string();
        match name.as_str() {
            "session_token" => {
                post_submission.session_token =
                    match Uuid::try_parse(&field.text().await.map_err(|e| {
                        ResponseError::BadRequest(format!("Failed to read session token: {e}"))
                    })?) {
                        Err(e) => {
                            return Err(ResponseError::BadRequest(format!(
                                "Invalid session token: {e}"
                            )));
                        }
                        Ok(uuid) => uuid,
                    };
            }
            "body" => {
                post_submission.body = field.text().await.map_err(|e| {
                    ResponseError::BadRequest(format!("Failed to read post body: {e}"))
                })?
            }
            "media" => {
                if post_submission.media_filename.is_some() {
                    return Err(ResponseError::BadRequest(
                        "Only one media file can be uploaded.".to_string(),
                    ));
                }
                let filename = field
                    .file_name()
                    .ok_or_else(|| {
                        ResponseError::BadRequest("Media file has no filename.".to_string())
                    })?
                    .to_string();
                if filename.is_empty() {
                    continue;
                }
                post_submission.media_filename = Some(filename);
                post_submission.media_bytes = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| {
                            ResponseError::BadRequest(format!("Failed to read media file: {e}"))
                        })?
                        .to_vec(),
                );
            }
            _ => {
                return Err(ResponseError::BadRequest(format!(
                    "Unexpected field: {name}"
                )));
            }
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
        return Err(ResponseError::Forbidden(format!(
            "You are banned until {expires_at}."
        )));
    }

    // Ban user if they are flooding
    if let Some(expires_at) =
        ban_if_flooding(&mut tx, &user.ip_hash, user.account.as_ref().map(|a| a.id)).await?
    {
        tx.commit().await?;
        return Err(ResponseError::Forbidden(format!(
            "You have been banned for flooding until {expires_at}."
        )));
    }

    // Validate post content
    if post_submission.body.is_empty() && post_submission.media_filename.is_none() {
        return Err(ResponseError::BadRequest(
            "Post cannot be empty unless there is a media file.".to_string(),
        ));
    }

    // Ensure post does not contain a spam word
    if ban::contains_spam_word(&mut tx, &post_submission.body).await? {
        let ban = Ban {
            ip_hash: user.ip_hash.clone(),
            banned_account_id: user.account.as_ref().map(|a| a.id),
            ..Ban::default()
        };
        let expires_at = ban.insert(&mut tx).await?;
        tx.commit().await?;
        return Err(ResponseError::Forbidden(format!(
            "You have been banned for spam until {expires_at}."
        )));
    }

    // Generate unique key and insert post
    let key = submission::generate_key(&mut tx).await?;
    let post = post_submission.insert(&mut tx, &user, &key).await?;

    // Handle media file encryption if present
    if let Some(bytes) = post_submission.media_bytes {
        media::encryption::encrypt_uploaded_file(&post, bytes).await?;
    }

    tx.commit().await?;

    // Notify clients of new post
    state.sender.send(AppMessage::Post(post)).ok();

    // Return appropriate response based on request type
    let response = if is_fetch_request(&headers) {
        StatusCode::CREATED.into_response()
    } else {
        Redirect::to(ROOT).into_response()
    };

    Ok((jar, response).into_response())
}

/// Hides a post from the user's view if authorized.
pub async fn hide_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(post_hiding): Form<PostHiding>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

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
            return Err(ResponseError::Unauthorized(
                "You are not the author of this post.".to_string(),
            ));
        }
        match post.status {
            PostStatus::Rejected => {
                post_hiding.hide_post(&mut tx).await?;
                tx.commit().await?;
            }
            PostStatus::Reported | PostStatus::Banned => (),
            _ => {
                return Err(ResponseError::BadRequest(
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

/// Inner function to process the WebSocket connection
pub async fn watch_receiver(
    State(state): State<AppState>,
    mut socket: WebSocket,
    mut receiver: Receiver<AppMessage>,
    user: User,
) {
    use crate::{post::PostStatus, user::AccountRole};

    while let Ok(msg) = receiver.recv().await {
        match msg {
            AppMessage::Post(post) => {
                // Determine if this post should be sent to the user
                let should_send = post.author(&user)
                    || match user.account {
                        None => post.status == PostStatus::Approved,
                        Some(ref account) => match account.role {
                            AccountRole::Admin => true,
                            AccountRole::Mod => [
                                PostStatus::Pending,
                                PostStatus::Approved,
                                PostStatus::Delisted,
                                PostStatus::Reported,
                            ]
                            .contains(&post.status),
                            AccountRole::Member | AccountRole::Novice => {
                                post.status == PostStatus::Approved
                            }
                            AccountRole::Pending => false,
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
            AppMessage::Account(_) => {
                // Handle account updates if needed
                // Currently not implemented
            }
        }
    }
}

/// Handles WebSocket connections for real-time post updates.
pub async fn web_socket(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

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

/// Fetches posts created after the latest approved post for interim updates.
pub async fn interim(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Get the reference post
    let since_post = init_post(&mut tx, &key, &user).await?;

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
