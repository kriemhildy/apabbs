//! New post submissions
//!
//! This module handles the submission of new posts, including text and media uploads.
//! It validates content, manages user sessions, and handles media encryption.

use axum::{
    extract::{Multipart, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use uuid::Uuid;

use super::{
    ROOT,
    errors::ResponseError,
    helpers::{ban_if_flooding, init_user, is_fetch_request},
};
use crate::{
    AppMessage, AppState,
    ban::{self, Ban},
    post::{
        media::encryption::encrypt_uploaded_file,
        submission::{PostSubmission, generate_key},
    },
};

// Parse multipart form data for post submission
async fn parse_post_submission(mut multipart: Multipart) -> Result<PostSubmission, ResponseError> {
    let mut post_submission = PostSubmission::default();
    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name() {
            Some("session_token") => {
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
            Some("body") => {
                post_submission.body = field.text().await.map_err(|e| {
                    ResponseError::BadRequest(format!("Failed to read post body: {e}"))
                })?;
            }
            Some("media") => {
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
                    "Unexpected field: {}",
                    field.name().unwrap_or_default()
                )));
            }
        }
    }
    Ok(post_submission)
}

/// Handles post submission with optional media attachments.
pub async fn submit_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Parse multipart form data
    let post_submission = parse_post_submission(multipart).await?;

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
    let key = generate_key(&mut tx).await?;
    let post = post_submission.insert(&mut tx, &user, &key).await?;

    // Handle media file encryption if present
    if let Some(bytes) = post_submission.media_bytes {
        encrypt_uploaded_file(&post, bytes).await?;
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
