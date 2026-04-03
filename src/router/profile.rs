//! User profile and settings routes and handlers.
//!
//! This module provides endpoints for displaying user profiles, managing account settings,
//! updating time zones, and changing passwords. It enforces authentication and input validation.

use super::{
    errors::ResponseError,
    helpers::{add_notice_cookie, init_post, init_user, remove_notice_cookie},
};
use crate::{
    AppState,
    post::Post,
    user::{Account, AccountRole, Credentials, TimeZoneUpdate},
    utils::render,
};
use axum::{
    extract::{Form, Path, State},
    http::{HeaderMap, Method},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use std::collections::HashMap;

// --- Profile display endpoints ----------------------------------------------

// Shows public posts and account info for a given username.
pub async fn user_profile(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(path): Path<HashMap<String, String>>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session (may be anonymous)
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Extract username from path
    let username = match path.get("username") {
        None => {
            return Err(ResponseError::BadRequest(
                "Missing username in path".to_string(),
            ));
        }
        Some(username) => username,
    };

    // Handle pagination parameter if present
    let page_post = match path.get("key") {
        Some(key) => Some(init_post(&mut tx, key, &user).await?),
        None => None,
    };

    // Find account by username (returns NotFound if user does not exist)
    let account = match Account::select_by_username(&mut tx, username).await? {
        None => {
            return Err(ResponseError::NotFound(
                "User account does not exist".to_string(),
            ));
        }
        Some(account) => account,
    };

    // Do not allow profiles for pending accounts
    if account.role == AccountRole::Pending {
        return Err(ResponseError::Unauthorized(
            "Account is pending approval".to_string(),
        ));
    }

    // Get user's public posts
    let page_post_id = page_post.as_ref().map(|p| p.id);
    let mut posts = Post::select_by_author(&mut tx, account.id, page_post_id).await?;

    // Check if there's a next page by seeing if we got more posts than our page size
    let next_page_post = if posts.len() <= crate::per_page() {
        None
    } else {
        posts.pop()
    };

    // Render profile page
    let html = Html(render(
        &state,
        "profile.jinja",
        minijinja::context!(
            dev => crate::dev(),
            prod_host => crate::prod_host(),
            site_name => crate::site_name(),
            user,
            account,
            posts,
            page_post,
            next_page_post,
        ),
    )?);

    Ok((jar, html).into_response())
}

// --- Settings display & update endpoints ------------------------------------

/// Displays the user settings page. Requires the user to be logged in.
pub async fn settings(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session (must be logged in)
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Verify user is logged in
    if user.account.is_none() {
        return Err(ResponseError::Unauthorized("Not logged in".to_string()));
    }

    // Get time zones for selection
    let time_zones = TimeZoneUpdate::select_time_zones(&mut tx).await?;

    // Check for notice messages (e.g., after successful update)
    let (jar, notice) = remove_notice_cookie(jar);

    // Render settings page
    let html = Html(render(
        &state,
        "settings.jinja",
        minijinja::context!(
            dev => crate::dev(),
            prod_host => crate::prod_host(),
            site_name => crate::site_name(),
            user,
            time_zones,
            notice,
        ),
    )?);

    Ok((jar, html).into_response())
}

// --- Settings update handlers -----------------------------------------------

/// Updates a user's time zone preference after validation.
pub async fn update_time_zone(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(time_zone_update): Form<TimeZoneUpdate>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session (must be logged in)
    let (user, jar) = init_user(
        jar,
        &mut tx,
        method,
        &headers,
        Some(time_zone_update.session_token),
    )
    .await?;

    // Verify user is logged in
    let account = match user.account {
        None => {
            return Err(ResponseError::Unauthorized("Not logged in".to_string()));
        }
        Some(account) => account,
    };

    // Validate time zone
    let time_zones = TimeZoneUpdate::select_time_zones(&mut tx).await?;
    if !time_zones.contains(&time_zone_update.time_zone) {
        return Err(ResponseError::BadRequest(
            "Invalid time zone selection".to_string(),
        ));
    }

    // Update time zone preference
    time_zone_update.update(&mut tx, account.id).await?;
    tx.commit().await?;

    // Set confirmation notice
    let jar = add_notice_cookie(jar, "Time zone updated.");
    let redirect = Redirect::to("/settings").into_response();

    Ok((jar, redirect).into_response())
}

/// Updates a user's password after validation.
pub async fn update_password(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(credentials): Form<Credentials>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session (must be logged in)
    let (user, jar) = init_user(
        jar,
        &mut tx,
        method,
        &headers,
        Some(credentials.session_token),
    )
    .await?;

    // Verify user is logged in as the correct user
    match user.account {
        None => {
            return Err(ResponseError::Unauthorized("Not logged in".to_string()));
        }
        Some(account) => {
            if account.username != credentials.username {
                return Err(ResponseError::Unauthorized(
                    "Not logged in as this user".to_string(),
                ));
            }
        }
    };

    // Validate new password
    let errors = credentials.validate();
    if !errors.is_empty() {
        return Err(ResponseError::BadRequest(format!(
            "Password update failed:\n{}",
            errors.join("\n")
        )));
    }

    // Update password
    credentials.update_password(&mut tx).await?;
    tx.commit().await?;

    // Set confirmation notice
    let jar = add_notice_cookie(jar, "Password updated.");
    let redirect = Redirect::to("/settings").into_response();

    Ok((jar, redirect).into_response())
}
