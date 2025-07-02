//! User profile and settings routes and handlers.
//!
//! This module provides endpoints for displaying user profiles, managing account settings,
//! updating time zones, and changing passwords. It enforces authentication and input validation.

// =========================
// Profile Display Endpoints
// =========================

use super::{
    errors::ResponseError::{self, *},
    helpers::{add_notice_cookie, init_user, remove_notice_cookie},
};
use crate::user::TimeZoneUpdate;
use crate::{
    AppState,
    post::Post,
    user::{Account, Credentials},
    utils::{begin_transaction, commit_transaction, render},
};
use axum::{
    extract::{Form, Path, State},
    http::{HeaderMap, Method},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;

pub async fn user_profile(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Result<Response, ResponseError> {
    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session (may be anonymous)
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Find account by username (returns NotFound if user does not exist)
    let account = match Account::select_by_username(&mut tx, &username).await? {
        None => return Err(NotFound("User account does not exist".to_string())),
        Some(account) => account,
    };

    // Get user's public posts
    let posts = Post::select_by_author(&mut tx, account.id).await?;

    // Render profile page
    let html = Html(render(
        &state,
        "profile.jinja",
        minijinja::context!(
            dev => crate::dev(),
            host => crate::host(),
            user,
            account,
            posts,
        ),
    )?);

    Ok((jar, html).into_response())
}

// =========================
// Settings Display & Update
// =========================

/// Displays the user settings page. Requires the user to be logged in.
pub async fn settings(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session (must be logged in)
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Verify user is logged in
    if user.account.is_none() {
        return Err(Unauthorized(
            "You must be logged in to access settings".to_string(),
        ));
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
            host => crate::host(),
            user,
            time_zones,
            notice,
        ),
    )?);

    Ok((jar, html).into_response())
}

// =========================
// Settings Update Handlers
// =========================

/// Updates a user's time zone preference after validation.
pub async fn update_time_zone(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(time_zone_update): Form<TimeZoneUpdate>,
) -> Result<Response, ResponseError> {
    let mut tx = begin_transaction(&state.db).await?;

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
            return Err(Unauthorized(
                "You must be logged in to update your time zone".to_string(),
            ));
        }
        Some(account) => account,
    };

    // Validate time zone
    let time_zones = TimeZoneUpdate::select_time_zones(&mut tx).await?;
    if !time_zones.contains(&time_zone_update.time_zone) {
        return Err(BadRequest("Invalid time zone selection".to_string()));
    }

    // Update time zone preference
    time_zone_update.update(&mut tx, account.id).await?;
    commit_transaction(tx).await?;

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
    let mut tx = begin_transaction(&state.db).await?;

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
            return Err(Unauthorized(
                "You must be logged in to update your password".to_string(),
            ));
        }
        Some(account) => {
            if account.username != credentials.username {
                return Err(Unauthorized(
                    "You are not logged in as this user".to_string(),
                ));
            }
        }
    };

    // Validate new password
    let errors = credentials.validate();
    if !errors.is_empty() {
        return Err(BadRequest(format!(
            "Password update failed:\n{}",
            errors.join("\n")
        )));
    }

    // Update password
    credentials.update_password(&mut tx).await?;
    commit_transaction(tx).await?;

    // Set confirmation notice
    let jar = add_notice_cookie(jar, "Password updated.");
    let redirect = Redirect::to("/settings").into_response();

    Ok((jar, redirect).into_response())
}
