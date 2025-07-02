//! Admin and moderator endpoints for post review and moderation.
//!
//! This module provides handlers for approving, rejecting, banning, and decrypting posts.
//! It enforces moderator/admin permissions and manages background media processing.

// =========================
// Moderation Endpoints
// =========================

use super::{
    ResponseError::{self, *},
    helpers::{init_user, is_fetch_request},
};
use crate::{
    AppState, ban,
    post::{Post, review::PostReview},
    router::ROOT,
    utils::{begin_transaction, commit_transaction, send_to_websocket},
};
use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;

/// Processes post moderation actions, enforcing business rules and managing background media processing.
pub async fn review_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(key): Path<String>,
    Form(post_review): Form<PostReview>,
) -> Result<Response, ResponseError> {
    use crate::{
        post::{PostStatus::*, review::ReviewError::*},
        user::AccountRole::*,
    };

    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session
    let (user, jar) = init_user(
        jar,
        &mut tx,
        method,
        &headers,
        Some(post_review.session_token),
    )
    .await?;

    // Verify user has moderator privileges
    let account = match user.account {
        None => {
            return Err(Unauthorized(
                "You must be logged in to moderate posts".to_string(),
            ));
        }
        Some(account) => account,
    };

    if ![Admin, Mod].contains(&account.role) {
        return Err(Unauthorized(
            "You must be an admin or moderator to perform this action".to_string(),
        ));
    };

    // Get the post to review
    let post = Post::select_by_key(&mut tx, &key)
        .await?
        .ok_or_else(|| NotFound("Post does not exist".to_string()))?;

    // Determine appropriate review action
    let review_action = PostReview::determine_action(&post, post_review.status, account.role);

    use futures::future::BoxFuture;
    // Handle various review actions
    let background_task: Option<BoxFuture<'static, ()>> = match review_action {
        // Handle errors
        Err(e @ SameStatus)
        | Err(e @ ReturnToPending)
        | Err(e @ RejectedOrBanned)
        | Err(e @ CurrentlyProcessing)
        | Err(e @ ManualProcessing) => {
            return Err(BadRequest(e.to_string()));
        }
        Err(e @ AdminOnly) | Err(e @ RecentOnly) => {
            return Err(Unauthorized(e.to_string()));
        }

        // Handle media operations
        Ok(action) => PostReview::process_action(&state, &post, post_review.status, action).await?,
    };

    // Set appropriate status based on background processing
    let status = if background_task.is_some() {
        Processing
    } else {
        post_review.status
    };

    // Update post status and record review action
    let post = post.update_status(&mut tx, status).await?;
    post_review.insert(&mut tx, account.id, post.id).await?;

    // Handle banned post cleanup
    if post.status == Banned {
        if let Some(ip_hash) = post.ip_hash.as_ref() {
            ban::insert(&mut tx, ip_hash, post.account_id, Some(account.id)).await?;
        }
        post.delete(&mut tx).await?;
    }

    commit_transaction(tx).await?;

    // Notify clients of the update
    send_to_websocket(&state.sender, post.clone());

    // If we have a background task, spawn it
    if let Some(task) = background_task {
        tokio::spawn(task);
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
// Media Access Endpoints
// =========================

/// Serves decrypted media files to moderators or admins for review.
pub async fn decrypt_media(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Response, ResponseError> {
    use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};

    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Verify user has required privileges
    if !user.mod_or_admin() {
        return Err(Unauthorized(
            "You must be a moderator or admin to access this media".to_string(),
        ));
    }

    // Get the post
    let post = Post::select_by_key(&mut tx, &key)
        .await?
        .ok_or_else(|| NotFound("Post does not exist".to_string()))?;

    // Verify media exists
    if !post.encrypted_media_path().exists() {
        return Err(NotFound("Encrypted media file does not exist".to_string()));
    }

    // Get media details
    let media_filename = post
        .media_filename
        .as_ref()
        .ok_or_else(|| InternalServerError("Missing filename".to_string()))?;
    let media_bytes = post.decrypt_media_file().await?;
    if media_bytes.is_empty() {
        return Err(InternalServerError(
            "Decrypted media bytes are empty".to_string(),
        ));
    }
    let content_type = post
        .media_mime_type
        .ok_or_else(|| InternalServerError("Missing MIME type".to_string()))?;

    // Set response headers for download
    let headers = [
        (CONTENT_TYPE, &content_type),
        (
            CONTENT_DISPOSITION,
            &format!("inline; filename=\"{media_filename}\""),
        ),
    ];

    Ok((jar, headers, media_bytes).into_response())
}
