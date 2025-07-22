//! Post display routes
//!
//! This module provides endpoints for displaying and hiding posts.
//! It supports pagination, single post views, and interim updates.

use super::{
    ROOT,
    errors::ResponseError,
    helpers::{init_post, init_user, is_fetch_request},
};
use crate::{
    AppState,
    post::{Post, PostStatus, submission::PostHiding},
    user::Account,
    utils::{render, utc_hour_timestamp},
};
use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use std::collections::HashMap;

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
// Post Hiding
// =========================

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

//=========================
// Interim Updates
//=========================

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
