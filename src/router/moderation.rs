//! Admin and moderator endpoints for post review and moderation.
//!
//! This module provides handlers for approving, rejecting, banning, and decrypting posts.
//! It enforces moderator/admin permissions and manages background media processing.

use super::{
    errors::ResponseError,
    helpers::{init_user, is_fetch_request},
};
use crate::{
    AppState,
    ban::Ban,
    post::{Post, PostStatus, media::encryption, review::PostReview},
    router::ROOT,
    user::{Account, AccountRole},
};
use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use uuid::Uuid;

// ===========================
// Moderation Review Endpoints
// ===========================

/// Processes post moderation actions, enforcing business rules and managing background media processing.
pub async fn review_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(key): Path<String>,
    Form(post_review): Form<PostReview>,
) -> Result<Response, ResponseError> {
    use crate::post::review::{self, ReviewError};
    use futures::future::BoxFuture;

    let mut tx = state.db.begin().await?;

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
        None => return Err(ResponseError::Unauthorized("Not logged in".to_string())),
        Some(account) => account,
    };
    if ![AccountRole::Admin, AccountRole::Mod].contains(&account.role) {
        return Err(ResponseError::Unauthorized(
            "Must be admin or moderator".to_string(),
        ));
    };

    // Get the post to review
    let post = Post::select_by_key(&mut tx, &key)
        .await?
        .ok_or_else(|| ResponseError::NotFound("Post does not exist".to_string()))?;

    // Determine appropriate review action
    let review_action = review::determine_action(&post, post_review.status, account.role);

    // Handle various review actions
    let background_task: Option<BoxFuture<'static, ()>> = match review_action {
        // Handle errors
        Err(e @ ReviewError::SameStatus)
        | Err(e @ ReviewError::ReturnToPending)
        | Err(e @ ReviewError::RejectedOrBanned)
        | Err(e @ ReviewError::CurrentlyProcessing)
        | Err(e @ ReviewError::ManualProcessing) => {
            return Err(ResponseError::BadRequest(e.to_string()));
        }
        Err(e @ ReviewError::AdminOnly) | Err(e @ ReviewError::RecentOnly) => {
            return Err(ResponseError::Unauthorized(e.to_string()));
        }
        // Handle media operations
        Ok(action) => review::process_action(&state, &post, post_review.status, action).await?,
    };

    // Set appropriate status based on background processing
    let status = if background_task.is_some() {
        PostStatus::Processing
    } else {
        post_review.status
    };

    // Update post status and record review action
    let post = post.update_status(&mut tx, status).await?;
    post_review.insert(&mut tx, account.id, post.id).await?;

    // Handle banned post cleanup
    if post.status == PostStatus::Banned {
        if let Some(ip_hash) = post.ip_hash.as_ref() {
            let ban = Ban {
                ip_hash: ip_hash.to_string(),
                banned_account_id: post.account_id,
                admin_account_id: Some(account.id),
            };
            ban.insert(&mut tx).await?;
        }
        post.delete(&mut tx).await?;
    }

    tx.commit().await?;

    // Notify clients of the update
    state.sender.send(post).ok();

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

/// Form struct for account review submission.
#[derive(Debug, serde::Deserialize)]
pub struct AccountReviewForm {
    pub session_token: Uuid,
    pub username: String,
    pub action: String, // "approve" or "reject"
}

/// Handles the admin review a new user account.
pub async fn review_account(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(form): Form<AccountReviewForm>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, Some(form.session_token)).await?;

    // Verify user has admin privileges
    if !user.admin() {
        return Err(ResponseError::Unauthorized(
            "Must be admin to review accounts".to_string(),
        ));
    }

    // Get the account to review
    let account = Account::select_by_username(&mut tx, &form.username)
        .await?
        .ok_or_else(|| ResponseError::NotFound("Account does not exist".to_string()))?;

    // Ensure account is pending
    if account.role != AccountRole::Pending {
        return Err(ResponseError::BadRequest(
            "Account must be pending".to_string(),
        ));
    }

    // Handle the review action
    match form.action.as_str() {
        "approve" => {
            // Approve the account
            account.update_role(&mut tx, AccountRole::Novice).await?;
            // Notify the user of approval
            state.sender.send(account.clone()).ok();
        }
        "reject" => {
            // Reject the account
            account.update_role(&mut tx, AccountRole::Rejected).await?;
            // Optionally delete the account or notify the user
            account.delete(&mut tx).await?;
        }
        _ => {
            return Err(ResponseError::BadRequest(
                r#"Invalid action, must be "approve" or "reject""#.to_string(),
            ));
        }
    }

    let response = "ok";
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

    let mut tx = state.db.begin().await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Verify user has required privileges
    if !user.mod_or_admin() {
        return Err(ResponseError::Unauthorized(
            "Must be moderator or admin".to_string(),
        ));
    }

    // Get the post
    let post = Post::select_by_key(&mut tx, &key)
        .await?
        .ok_or_else(|| ResponseError::NotFound("Post does not exist".to_string()))?;

    // Ensure post is pending
    if post.status != PostStatus::Pending {
        return Err(ResponseError::BadRequest(
            "Post must be pending".to_string(),
        ));
    }

    // Verify media exists
    if post.media_filename.is_none() {
        return Err(ResponseError::NotFound("Post has no media".to_string()));
    }

    // Get media details
    let media_filename = post.media_filename.as_ref().unwrap();
    let encrypted_media_path = post.encrypted_media_path();
    let media_bytes = encryption::gpg_decrypt(&encrypted_media_path).await?;
    let content_type = post.media_mime_type.unwrap();

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
