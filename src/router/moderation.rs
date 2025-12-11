//! Admin and moderator endpoints for post review and moderation.
//!
//! This module provides handlers for approving, rejecting, banning, and decrypting posts.
//! It enforces moderator/admin permissions and manages background media processing.

use super::{
    errors::ResponseError,
    helpers::{init_user, is_fetch_request},
};
use crate::{
    AppMessage, AppState,
    ban::{Ban, SpamTerm},
    post::{Post, PostStatus, media::encryption, review::PostReview},
    router::ROOT,
    user::{Account, AccountRole}, utils::render,
};
use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
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
        return Err(ResponseError::Forbidden(
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
    state.sender.send(AppMessage::Post(post)).ok();

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
#[derive(Debug, Serialize, Deserialize)]
pub struct AccountReviewForm {
    pub session_token: Uuid,
    pub username: String,
    pub intent: String, // "approve" or "reject"
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

    // Verify user is logged in
    if user.account.is_none() {
        return Err(ResponseError::Unauthorized("Not logged in".to_string()));
    }

    // Verify user has admin privileges
    if !user.admin() {
        return Err(ResponseError::Forbidden(
            "Must be admin to review accounts".to_string(),
        ));
    }

    // Get the account to review
    let review_account = Account::select_by_username(&mut tx, &form.username)
        .await?
        .ok_or_else(|| ResponseError::NotFound("Account does not exist".to_string()))?;

    // Ensure account is pending
    if review_account.role != AccountRole::Pending {
        return Err(ResponseError::BadRequest(
            "Account must be pending".to_string(),
        ));
    }

    // Find the new role corresponding to the intent
    let role = match form.intent.as_str() {
        "approve" => AccountRole::Novice,
        "reject" => AccountRole::Rejected,
        _ => {
            return Err(ResponseError::BadRequest(
                r#"Invalid intent, must be "approve" or "reject""#.to_string(),
            ));
        }
    };

    // Update the account role
    let review_account = review_account.update_role(&mut tx, role).await?;
    // Update WebSocket clients
    state.sender.send(AppMessage::Account(review_account.clone())).ok();

    // If the account is rejected, delete it
    if review_account.role == AccountRole::Rejected {
        review_account.delete(&mut tx).await?;
    }

    tx.commit().await?;

    if is_fetch_request(&headers) {
        Ok((jar, StatusCode::NO_CONTENT).into_response())
    } else {
        Ok((jar, Redirect::to(ROOT)).into_response())
    }
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

    // Verify user is logged in
    if user.account.is_none() {
        return Err(ResponseError::Unauthorized("Not logged in".to_string()));
    }

    // Verify user has required privileges
    if !user.mod_or_admin() {
        return Err(ResponseError::Forbidden(
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

// =========================
// Spam Term Endpoints
// =========================

/// Displays the list of spam terms for admin management.
pub async fn list_spam_terms(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Verify user is logged in
    if user.account.is_none() {
        return Err(ResponseError::Unauthorized("Not logged in".to_string()));
    }

    // Verify user has admin privileges
    if !user.admin() {
        return Err(ResponseError::Forbidden(
            "Must be admin to view spam terms".to_string(),
        ));
    }

    // Get latest spam terms
    let spam_terms = SpamTerm::select_latest(&mut tx).await?;

    // Render the page
    let html = Html(render(
        &state,
        "spam.jinja",
        minijinja::context!(
            dev => crate::dev(),
            host => crate::prod_host(),
            nav => false,
            user,
            spam_terms,
        ),
    )?);

    Ok((jar, html).into_response())
}

/// Represents a spam term form.
#[derive(Serialize, Deserialize)]
pub struct SpamTermForm {
    /// Session token to invalidate during logout
    pub session_token: Uuid,
    /// The spam term to be added
    pub term: String,
}

/// Adds a new spam term to the system.
pub async fn add_spam_term(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(form): Form<SpamTermForm>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, Some(form.session_token)).await?;

    // Verify user is logged in
    if user.account.is_none() {
        return Err(ResponseError::Unauthorized("Not logged in".to_string()));
    }

    // Verify user has admin privileges
    if !user.admin() {
        return Err(ResponseError::Forbidden(
            "Must be admin to add spam terms".to_string(),
        ));
    }

    // Add the spam term
    let spam_term = SpamTerm { term: form.term };
    spam_term.insert(&mut tx).await?;
    tx.commit().await?;

    // Redirect back to the spam terms page
    let response = Redirect::to("/spam");
    Ok((jar, response).into_response())
}

