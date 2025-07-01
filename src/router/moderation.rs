//! Admin and moderator endpoints for post review and moderation.
//!
//! This module provides handlers for approving, rejecting, banning, and decrypting posts.
//! It enforces moderator/admin permissions and manages background media processing.

use super::*;

// =========================
// Moderation Endpoints
// =========================

/// Processes post moderation actions, enforcing business rules and managing background media processing.
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
    let review_action = PostReview::determine_action(&post, post_review.status, account.role);

    // Handle various review actions
    let mut background_task: Option<BoxFuture> = None;
    match review_action {
        // Handle errors
        Err(e @ SameStatus)
        | Err(e @ ReturnToPending)
        | Err(e @ RejectedOrBanned)
        | Err(e @ CurrentlyProcessing)
        | Err(e @ ManualProcessing) => {
            return Err(BadRequest(e.to_string()));
        }
        Err(e @ AdminOnly)
        | Err(e @ RecentOnly) => {
            return Err(Unauthorized(e.to_string()));
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
                    background_task = Some(Box::pin(PostReview::publish_media_task(
                        state.clone(),
                        post.clone(),
                        post_review.clone(),
                    )));
                } else {
                    // Delete the encrypted media file
                    PostReview::delete_upload_key_dir(&encrypted_media_path).await?;
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
            background_task = Some(Box::pin(PostReview::reencrypt_media_task(
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
    let post = post.update_status(&mut tx, status).await?;
    post_review.insert(&mut tx, account.id, post.id).await?;

    // Handle banned post cleanup
    if post.status == Banned {
        if let Some(ref ip_hash) = post.ip_hash {
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
