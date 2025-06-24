//! Admin and moderator post review and moderation handlers.
//!
//! This module provides endpoints for post review, approval, rejection, banning, and media decryption.
//! It enforces business rules for moderator/admin actions and manages background media processing.

use super::*;

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

    let mut tx = state.db.begin().await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, Some(post_review.session_token)).await?;

    // Verify user has moderator privileges
    let account = match user.account {
        None => {
            return Err(Unauthorized(
                "You must be logged in to moderate posts".to_owned(),
            ));
        }
        Some(account) => account,
    };

    match account.role {
        Admin | Mod => (),
        _ => {
            return Err(Unauthorized(
                "You must be an admin or moderator to perform this action".to_owned(),
            ));
        }
    };

    // Get the post to review
    let post = match Post::select_by_key(&mut tx, &key).await? {
        None => return Err(NotFound("Post does not exist".to_owned())),
        Some(post) => post,
    };

    // Determine appropriate review action
    let review_action = post_review.determine_action(&post, &account.role);

    // Handle various review actions
    let background_task: Option<BoxFuture> = match review_action {
        // Handle errors
        Err(SameStatus) => return Err(BadRequest("Post already has this status".to_owned())),
        Err(ReturnToPending) => return Err(BadRequest("Cannot return post to pending".to_owned())),
        Err(ModOnly) => return Err(Unauthorized("Only moderators can report posts".to_owned())),
        Err(AdminOnly) => {
            return Err(Unauthorized(
                "Only admins can ban or reject posts".to_owned(),
            ));
        }
        Err(RejectedOrBanned) => {
            return Err(BadRequest(
                "Cannot review a banned or rejected post".to_owned(),
            ));
        }
        Err(RecentOnly) => {
            return Err(Unauthorized(
                "Moderators can only review approved posts for two days".to_owned(),
            ));
        }
        Err(CurrentlyProcessing) => {
            return Err(BadRequest("Post is currently being processed".to_owned()));
        }
        Err(ManualProcessing) => {
            return Err(BadRequest(
                "Cannot manually set post to processing".to_owned(),
            ));
        }

        // Handle media operations
        Ok(DecryptMedia | DeleteEncryptedMedia) => {
            if post.media_filename.is_none() {
                None
            } else {
                let encrypted_media_path = post.encrypted_media_path();
                if !encrypted_media_path.exists() {
                    return Err(NotFound("Encrypted media file does not exist".to_owned()));
                }

                if review_action == Ok(DecryptMedia) {
                    // Create background task for media decryption
                    Some(Box::pin(decrypt_media_task(
                        state.clone(),
                        post.clone(),
                        post_review.clone(),
                        encrypted_media_path.clone(),
                    )))
                } else {
                    None
                }
            }
        }

        // Handle media deletion
        Ok(DeletePublishedMedia) => {
            if post.media_filename.as_ref().is_some() && post.published_media_path().exists() {
                PostReview::delete_media_key_dir(&post.key).await?;
            }
            None
        }

        // Handle media re-encryption
        Ok(ReencryptMedia) => Some(Box::pin(reencrypt_media_task(
            state.clone(),
            post.clone(),
            post_review.clone(),
        ))),

        Ok(NoAction) => None,
    };

    // Set appropriate status based on background processing
    let status = if background_task.is_some() {
        Processing
    } else {
        post_review.status
    };

    // Update post status and record review action
    post.update_status(&mut tx, status)
        .await
        .expect("query succeeds");
    post_review.insert(&mut tx, account.id, post.id).await?;

    // Get updated post
    let post = match Post::select_by_key(&mut tx, &key).await? {
        None => return Err(NotFound("Post does not exist".to_owned())),
        Some(post) => post,
    };

    // Handle banned post cleanup
    if post.status == Banned {
        if let Some(ip_hash) = post.ip_hash.as_ref() {
            ban::insert(&mut tx, ip_hash, post.account_id, Some(account.id))
                .await
                .expect("query succeeds");
        }
        post.delete(&mut tx).await.expect("query succeeds");
    }

    // Ensure approved posts have thumbnails if needed
    if post.status == Approved && post.thumb_filename.is_some() && !post.thumbnail_path().exists() {
        return Err(InternalServerError(
            "Error setting post thumbnail".to_owned(),
        ));
    }

    tx.commit().await?;

    // Notify clients of the update
    if state.sender.send(post).is_err() {
        println!("No active receivers to send to");
    }

    // Start background task if needed
    if let Some(task) = background_task {
        tokio::task::spawn_blocking(move || tokio::runtime::Handle::current().block_on(task));
    }

    // Return appropriate response based on request type
    let response = if is_fetch_request(&headers) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        Redirect::to(ROOT).into_response()
    };

    Ok((jar, response).into_response())
}

/// Serves decrypted media files to moderators.
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
pub async fn decrypt_media(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Path(key): Path<String>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, None).await?;

    // Verify user has required privileges
    if !user.mod_or_admin() {
        return Err(Unauthorized(
            "You must be a moderator or admin to access this media".to_owned(),
        ));
    }

    // Get the post
    let post = match Post::select_by_key(&mut tx, &key).await? {
        None => return Err(NotFound("Post does not exist".to_owned())),
        Some(post) => post,
    };

    // Verify media exists
    if !post.encrypted_media_path().exists() {
        return Err(NotFound("Encrypted media file does not exist".to_owned()));
    }

    // Get media details
    let media_filename = post
        .media_filename
        .as_ref()
        .ok_or(InternalServerError("Missing filename".to_owned()))?;
    let media_bytes = post.decrypt_media_file().await?;
    if media_bytes.is_empty() {
        return Err(InternalServerError(
            "Failed to decrypt media file".to_owned(),
        ));
    }
    let content_type = post
        .media_mime_type
        .ok_or(InternalServerError("Missing MIME type".to_owned()))?;

    // Set response headers for download
    let headers = [
        (CONTENT_TYPE, &content_type),
        (
            CONTENT_DISPOSITION,
            &format!("inline; filename=\"{}\"", media_filename),
        ),
    ];

    Ok((jar, headers, media_bytes).into_response())
}

pub async fn decrypt_media_task(
    state: AppState,
    initial_post: Post,
    post_review: PostReview,
    encrypted_media_path: std::path::PathBuf,
) {
    let result: Result<(), Box<dyn std::error::Error>> = async {
        let mut tx = state
            .db
            .begin()
            .await
            .map_err(|e| format!("Failed to begin database transaction: {e}"))?;

        // Attempt media decryption
        PostReview::handle_decrypt_media(&mut tx, &initial_post)
            .await
            .map_err(|e| format!("Failed to decrypt media: {e}"))?;

        // Update post status
        initial_post
            .update_status(&mut tx, post_review.status)
            .await
            .map_err(|e| format!("Failed to update post status: {e}"))?;

        // Get updated post
        let updated_post = match Post::select_by_key(&mut tx, &initial_post.key)
            .await
            .map_err(|e| format!("Failed to select updated post by key: {e}"))?
        {
            None => {
                eprintln!("Post does not exist after decrypting media");
                return Ok(());
            }
            Some(post) => post,
        };

        tx.commit()
            .await
            .map_err(|e| format!("Failed to commit transaction: {e}"))?;

        // Clean up and notify clients
        PostReview::delete_upload_key_dir(&encrypted_media_path)
            .await
            .map_err(|e| format!("Failed to delete upload directory: {e}"))?;
        if state.sender.send(updated_post).is_err() {
            eprintln!("No active receivers to send to");
        }
        Ok(())
    }
    .await;

    if let Err(e) = result {
        eprintln!("Error in decrypt_media_task: {e}");
    }
}

pub async fn reencrypt_media_task(state: AppState, initial_post: Post, post_review: PostReview) {
    let result: Result<(), Box<dyn std::error::Error>> = async {
        let mut tx = state
            .db
            .begin()
            .await
            .map_err(|e| format!("Failed to begin database transaction: {e}"))?;

        // Attempt media re-encryption
        initial_post
            .reencrypt_media_file()
            .await
            .map_err(|e| format!("Failed to re-encrypt media: {e}"))?;

        // Update post status
        initial_post
            .update_status(&mut tx, post_review.status)
            .await
            .map_err(|e| format!("Failed to update post status: {e}"))?;

        // Get updated post
        let updated_post = match Post::select_by_key(&mut tx, &initial_post.key)
            .await
            .map_err(|e| format!("Failed to select updated post by key: {e}"))?
        {
            None => {
                eprintln!("Post does not exist after re-encrypting media");
                return Ok(());
            }
            Some(post) => post,
        };

        tx.commit()
            .await
            .map_err(|e| format!("Failed to commit transaction: {e}"))?;

        // Notify clients
        if state.sender.send(updated_post).is_err() {
            eprintln!("No active receivers to send to");
        }
        Ok(())
    }
    .await;

    if let Err(e) = result {
        eprintln!("Error in reencrypt_media_task: {e}");
    }
}
