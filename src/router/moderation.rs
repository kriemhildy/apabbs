//==================================================================================================
// Admin and Moderator Handlers
//==================================================================================================

use super::*;

/// Processes post moderation actions
///
/// Allows moderators and admins to approve, reject, or ban posts.
pub async fn review_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(key): Path<String>,
    Form(post_review): Form<PostReview>,
) -> Response {
    use AccountRole::*;
    use PostStatus::*;
    use ReviewAction::*;
    use ReviewError::*;

    let mut tx = state.db.begin().await.expect(BEGIN);

    // Initialize user from session
    let (user, jar) = match init_user(jar, &mut tx, method, Some(post_review.session_token)).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };

    // Verify user has moderator privileges
    let account = match user.account {
        None => return unauthorized("not logged in"),
        Some(account) => account,
    };

    match account.role {
        Admin | Mod => (),
        _ => return unauthorized("not an admin or mod"),
    };

    // Get the post to review
    let post = match Post::select_by_key(&mut tx, &key).await {
        None => return not_found("post does not exist"),
        Some(post) => post,
    };

    // Determine appropriate review action
    let review_action = post_review.determine_action(&post, &account.role);

    // Handle various review actions
    let background_task: Option<BoxFuture> = match review_action {
        // Handle errors
        Err(SameStatus) => return bad_request("post already has this status"),
        Err(ReturnToPending) => return bad_request("cannot return post to pending"),
        Err(ModOnly) => return unauthorized("only mods can report posts"),
        Err(AdminOnly) => return unauthorized("only admins can ban or reject posts"),
        Err(RejectedOrBanned) => return bad_request("cannot review a banned or rejected post"),
        Err(RecentOnly) => return unauthorized("mods can only review approved posts for two days"),
        Err(CurrentlyProcessing) => return bad_request("post is currently being processed"),
        Err(ManualProcessing) => return bad_request("cannot manually set post to processing"),

        // Handle media operations
        Ok(DecryptMedia | DeleteEncryptedMedia) => {
            // Do nothing if there is no media file
            if post.media_filename.is_none() {
                None
            } else {
                let encrypted_media_path = post.encrypted_media_path();
                if !encrypted_media_path.exists() {
                    return not_found("encrypted media file does not exist");
                }

                if review_action == Ok(DecryptMedia) {
                    // Create background task for media decryption
                    async fn decrypt_media_task(
                        state: AppState,
                        initial_post: Post,
                        post_review: PostReview,
                        encrypted_media_path: std::path::PathBuf,
                    ) {
                        let mut tx = state.db.begin().await.expect(BEGIN);

                        // Attempt media decryption
                        if let Err(msg) =
                            PostReview::handle_decrypt_media(&mut tx, &initial_post).await
                        {
                            println!("Error decrypting media: {}", msg);
                            return;
                        }

                        // Update post status
                        initial_post
                            .update_status(&mut tx, post_review.status)
                            .await;

                        // Get updated post
                        let updated_post =
                            match Post::select_by_key(&mut tx, &initial_post.key).await {
                                None => {
                                    println!("Post does not exist after decrypting media");
                                    return;
                                }
                                Some(post) => post,
                            };

                        tx.commit().await.expect(COMMIT);

                        // Clean up and notify clients
                        PostReview::delete_upload_key_dir(&encrypted_media_path).await;
                        if state.sender.send(updated_post).is_err() {
                            println!("No active receivers to send to");
                        }
                    }

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
                PostReview::delete_media_key_dir(&post.key).await;
            }

            None
        }

        // Handle media re-encryption
        Ok(ReencryptMedia) => {
            async fn reencrypt_media_task(
                state: AppState,
                initial_post: Post,
                post_review: PostReview,
            ) {
                let mut tx = state.db.begin().await.expect(BEGIN);

                // Attempt media re-encryption
                if let Err(msg) = initial_post.reencrypt_media_file().await {
                    println!("Error re-encrypting media: {}", msg);
                    return;
                }

                // Update post status
                initial_post
                    .update_status(&mut tx, post_review.status)
                    .await;

                // Get updated post
                let updated_post = match Post::select_by_key(&mut tx, &initial_post.key).await {
                    None => {
                        println!("Post does not exist after re-encrypting media");
                        return;
                    }
                    Some(post) => post,
                };

                tx.commit().await.expect(COMMIT);

                // Notify clients
                if state.sender.send(updated_post).is_err() {
                    println!("No active receivers to send to");
                }
            }

            Some(Box::pin(reencrypt_media_task(
                state.clone(),
                post.clone(),
                post_review.clone(),
            )))
        }

        Ok(NoAction) => None,
    };

    // Set appropriate status based on background processing
    let status = if background_task.is_some() {
        Processing
    } else {
        post_review.status
    };

    // Update post status and record review action
    post.update_status(&mut tx, status).await;
    post_review.insert(&mut tx, account.id, post.id).await;

    // Get updated post
    let post = match Post::select_by_key(&mut tx, &key).await {
        None => return not_found("post does not exist"),
        Some(post) => post,
    };

    // Handle banned post cleanup
    if post.status == Banned {
        if let Some(ip_hash) = post.ip_hash.as_ref() {
            ban::insert(&mut tx, ip_hash, post.account_id, Some(account.id)).await;
        }
        post.delete(&mut tx).await;
    }

    // Ensure approved posts have thumbnails if needed
    if post.status == Approved && post.thumb_filename.is_some() && !post.thumbnail_path().exists() {
        return internal_server_error("error setting post thumbnail");
    }

    tx.commit().await.expect(COMMIT);

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

    (jar, response).into_response()
}

/// Serves decrypted media files to moderators
///
/// Allows privileged users to access original media files.
pub async fn decrypt_media(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Path(key): Path<String>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);

    // Initialize user from session
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };

    // Verify user has required privileges
    if !user.mod_or_admin() {
        return unauthorized("not a mod or admin");
    }

    // Get the post
    let post = match Post::select_by_key(&mut tx, &key).await {
        None => return not_found("post does not exist"),
        Some(post) => post,
    };

    // Verify media exists
    if !post.encrypted_media_path().exists() {
        return not_found("encrypted media file does not exist");
    }

    // Get media details
    let media_filename = post.media_filename.as_ref().expect("read media filename");
    let media_bytes = post.decrypt_media_file().await;
    let content_type = post.media_mime_type.expect("read mime type");

    // Set response headers for download
    let headers = [
        (CONTENT_TYPE, &content_type),
        (
            CONTENT_DISPOSITION,
            &format!(r#"inline; filename="{}""#, media_filename),
        ),
    ];

    (jar, headers, media_bytes).into_response()
}
