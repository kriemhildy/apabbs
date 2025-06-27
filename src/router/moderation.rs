//! Admin and moderator post review and moderation handlers.
//!
//! This module provides endpoints for post review, approval, rejection, banning, and media decryption.
//! It enforces business rules for moderator/admin actions and manages background media processing.
//!
//! # Endpoints
//! - `review_post`: Handles moderation actions (approve, reject, ban, decrypt, re-encrypt, delete media, etc.)
//! - `decrypt_media`: Serves decrypted media files to moderators/admins for review
//!
//! # Business Rules
//! - Only moderators and admins can perform moderation actions
//! - Certain actions are restricted to admins only
//! - Media operations are handled in the background when needed
//! - Banned posts trigger IP/account bans and cleanup
//! - Thumbnails are validated for approved posts
//!
//! # Error Handling
//! - All errors are logged using `tracing` macros and returned as appropriate HTTP responses
//! - User-facing errors are clear, actionable, and capitalized
//!
//! # Background Tasks
//! - Media decryption and re-encryption are performed asynchronously
//! - Clients are notified of post updates via broadcast

use super::*;

// =========================
// Moderation Endpoints
// =========================

/// Processes post moderation actions.
///
/// Allows moderators and admins to approve, reject, ban, or re-encrypt posts, enforcing business rules and managing background media processing.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `headers`: HTTP headers for request context
/// - `Path(key)`: Path parameter for the post key
/// - `Form(post_review)`: Form data containing the post review action
///
/// # Returns
/// A `Response` indicating the result of the moderation action, with background processing as needed.
///
/// # Errors
/// Returns appropriate `ResponseError` variants for authentication, authorization, business rule, or internal errors.
pub async fn review_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(key): Path<String>,
    Form(post_review): Form<PostReview>,
) -> Result<Response, ResponseError> {
    use AccountRole::*;
    use PostStatus::*;
    use ReviewAction::*;
    use ReviewError::*;

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

    match account.role {
        Admin | Mod => (),
        _ => {
            return Err(Unauthorized(
                "You must be an admin or moderator to perform this action".to_string(),
            ));
        }
    };

    // Get the post to review
    let post = Post::select_by_key(&mut tx, &key)
        .await?
        .ok_or_else(|| NotFound("Post does not exist".to_string()))?;

    // Determine appropriate review action
    let review_action = post_review.determine_action(&post, &account.role);

    // Handle various review actions
    let mut background_task: Option<BoxFuture> = None;
    match review_action {
        // Handle errors
        Err(SameStatus) => return Err(BadRequest("Post already has this status".to_string())),
        Err(ReturnToPending) => {
            return Err(BadRequest("Cannot return post to pending".to_string()));
        }
        Err(ModOnly) => return Err(Unauthorized("Only moderators can report posts".to_string())),
        Err(AdminOnly) => {
            return Err(Unauthorized(
                "Only admins can ban or reject posts".to_string(),
            ));
        }
        Err(RejectedOrBanned) => {
            return Err(BadRequest(
                "Cannot review a banned or rejected post".to_string(),
            ));
        }
        Err(RecentOnly) => {
            return Err(Unauthorized(
                "Moderators can only review approved posts for two days".to_string(),
            ));
        }
        Err(CurrentlyProcessing) => {
            return Err(BadRequest("Post is currently being processed".to_string()));
        }
        Err(ManualProcessing) => {
            return Err(BadRequest(
                "Cannot manually set post to processing".to_string(),
            ));
        }

        // Handle media operations
        Ok(PublishMedia | DeleteEncryptedMedia) => {
            if post.media_filename.is_some() {
                let encrypted_media_path = post.encrypted_media_path();
                if !encrypted_media_path.exists() {
                    return Err(NotFound("Encrypted media file does not exist".to_string()));
                }

                if review_action == Ok(PublishMedia) {
                    // Create background task for media publication
                    background_task = Some(Box::pin(publish_media_task(
                        state.clone(),
                        post.clone(),
                        post_review.clone(),
                        encrypted_media_path.clone(),
                    )));
                }
            }
        }

        // Handle media deletion
        Ok(DeletePublishedMedia) => {
            if post.media_filename.as_ref().is_some() && post.published_media_path().exists() {
                PostReview::delete_media_key_dir(&post.key).await?;
            }
        }

        // Handle media re-encryption
        Ok(ReencryptMedia) => {
            background_task = Some(Box::pin(reencrypt_media_task(
                state.clone(),
                post.clone(),
                post_review.clone(),
            )));
        }

        Ok(NoAction) => (),
    };

    // Set appropriate status based on background processing
    let status = if background_task.is_some() {
        Processing
    } else {
        post_review.status
    };

    // Update post status and record review action
    post.update_status(&mut tx, status).await?;
    post_review.insert(&mut tx, account.id, post.id).await?;

    // Get updated post
    let post = Post::select_by_key(&mut tx, &key)
        .await?
        .ok_or_else(|| NotFound("Post does not exist".to_string()))?;

    // Handle banned post cleanup
    if post.status == Banned {
        if let Some(ip_hash) = post.ip_hash.as_ref() {
            ban::insert(&mut tx, ip_hash, post.account_id, Some(account.id)).await?;
        }
        post.delete(&mut tx).await?;
    }

    // Ensure approved posts have thumbnails if needed
    // This should be done more internally, and already is I think.
    if post.status == Approved && post.thumb_filename.is_some() && !post.thumbnail_path().exists() {
        return Err(InternalServerError(
            "Error setting post thumbnail".to_string(),
        ));
    }

    commit_transaction(tx).await?;

    // Notify clients of the update
    send_to_websocket(&state.sender, post);

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
///
/// Allows privileged users to access original media files for moderation or review.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `Path(key)`: Path parameter for the post key
///
/// # Returns
/// A `Response` containing the decrypted media file for download or inline viewing.
///
/// # Errors
/// Returns `Unauthorized` if the user is not a moderator/admin, or `NotFound`/`InternalServerError` for missing or failed media operations.
pub async fn decrypt_media(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Response, ResponseError> {
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

// =========================
// Background Media Tasks
// =========================

/// Background task for publishing media and updating post status.
///
/// Handles media publication, post status update, cleanup, and client notification asynchronously.
/// Logs errors using `tracing::error!` if any step fails.
pub async fn publish_media_task(
    state: AppState,
    initial_post: Post,
    post_review: PostReview,
    encrypted_media_path: std::path::PathBuf,
) {
    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
        let mut tx = begin_transaction(&state.db).await?;

        // Attempt media publication
        PostReview::publish_media(&mut tx, &initial_post).await?;

        // Update post status
        initial_post
            .update_status(&mut tx, post_review.status)
            .await?;

        // Get updated post
        let updated_post = Post::select_by_key(&mut tx, &initial_post.key)
            .await?
            .ok_or_else(|| "post does not exist after publishing media".to_string())?;

        commit_transaction(tx).await?;

        // Clean up and notify clients
        PostReview::delete_upload_key_dir(&encrypted_media_path)
            .await
            .map_err(|e| format!("failed to delete upload directory: {e}"))?;
        send_to_websocket(&state.sender, updated_post);
        Ok(())
    }
    .await;

    if let Err(e) = result {
        tracing::error!("Error in publish_media_task: {e}");
    }
}

/// Background task for re-encrypting media and updating post status.
///
/// Handles media re-encryption, post status update, and client notification asynchronously.
/// Logs errors using `tracing::error!` if any step fails.
pub async fn reencrypt_media_task(state: AppState, initial_post: Post, post_review: PostReview) {
    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
        let mut tx = begin_transaction(&state.db).await?;

        // Attempt media re-encryption
        initial_post
            .reencrypt_media_file()
            .await
            .map_err(|e| format!("failed to re-encrypt media: {e}"))?;

        // Update post status
        initial_post
            .update_status(&mut tx, post_review.status)
            .await?;

        // Get updated post
        let updated_post = Post::select_by_key(&mut tx, &initial_post.key)
            .await?
            .ok_or_else(|| "post does not exist after re-encrypting media".to_string())?;

        commit_transaction(tx).await?;

        // Notify clients
        send_to_websocket(&state.sender, updated_post);
        Ok(())
    }
    .await;

    if let Err(e) = result {
        tracing::error!("Error in reencrypt_media_task: {e}");
    }
}
