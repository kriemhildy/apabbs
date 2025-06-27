//! User profile and settings routes and handlers.
//!
//! This module provides endpoints for displaying user profiles, managing account settings,
//! updating time zones, and changing passwords. It enforces authentication and input validation.

use super::*;

// =========================
// Profile Display Endpoints
// =========================

/// Displays a user's profile page.
///
/// Shows information about a user and their public posts.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `Path(username)`: Path parameter for the username
/// - `jar`: Cookie jar for session management
/// - `headers`: HTTP headers for user agent analysis
///
/// # Returns
/// A `Response` containing the rendered user profile page, or an error if the user or posts cannot be found.
pub async fn user_profile(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!("Failed to begin database transaction: {:?}", e);
        e
    })?;

    // Initialize user from session (may be anonymous)
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Find account by username (returns NotFound if user does not exist)
    let account = match Account::select_by_username(&mut tx, &username).await? {
        None => return Err(NotFound("User account does not exist".to_owned())),
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
    ));

    Ok((jar, html).into_response())
}

// =========================
// Settings Display & Update
// =========================

/// Displays the user settings page.
///
/// Shows options for account management and preferences. Requires the user to be logged in.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `headers`: HTTP headers for user agent analysis
///
/// # Returns
/// A `Response` containing the rendered settings page, or an error if the user is not logged in.
pub async fn settings(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!("Failed to begin database transaction: {:?}", e);
        e
    })?;

    // Initialize user from session (must be logged in)
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Verify user is logged in
    if user.account.is_none() {
        return Err(Unauthorized(
            "You must be logged in to access settings".to_owned(),
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
    ));

    Ok((jar, html).into_response())
}

// =========================
// Settings Update Handlers
// =========================

/// Updates a user's time zone preference.
///
/// Changes the time zone setting for a logged-in user after validation. Requires authentication and a valid time zone.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `Form(time_zone_update)`: Form data containing the new time zone
///
/// # Returns
/// A `Response` redirecting to the settings page with a confirmation notice, or an error if validation fails.
pub async fn update_time_zone(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(time_zone_update): Form<TimeZoneUpdate>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!("Failed to begin database transaction: {:?}", e);
        e
    })?;

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
                "You must be logged in to update your time zone".to_owned(),
            ));
        }
        Some(account) => account,
    };

    // Validate time zone
    let time_zones = TimeZoneUpdate::select_time_zones(&mut tx).await?;
    if !time_zones.contains(&time_zone_update.time_zone) {
        return Err(BadRequest("Invalid time zone selection".to_owned()));
    }

    // Update time zone preference
    time_zone_update.update(&mut tx, account.id).await?;
    tx.commit().await.map_err(|e| {
        tracing::error!("Failed to commit transaction: {:?}", e);
        e
    })?;

    // Set confirmation notice
    let jar = add_notice_cookie(jar, "Time zone updated.");
    let redirect = Redirect::to("/settings").into_response();

    Ok((jar, redirect).into_response())
}

/// Updates a user's password.
///
/// Changes the password for a logged-in user after validation. Requires authentication and password validation.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `Form(credentials)`: Form data containing the new password and credentials
///
/// # Returns
/// A `Response` redirecting to the settings page with a confirmation notice, or an error if validation fails.
pub async fn update_password(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(credentials): Form<Credentials>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!("Failed to begin database transaction: {:?}", e);
        e
    })?;

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
                "You must be logged in to update your password".to_owned(),
            ));
        }
        Some(account) => {
            if account.username != credentials.username {
                return Err(Unauthorized(
                    "You are not logged in as this user".to_owned(),
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
    tx.commit().await.map_err(|e| {
        tracing::error!("Failed to commit transaction: {:?}", e);
        e
    })?;

    // Set confirmation notice
    let jar = add_notice_cookie(jar, "Password updated.");
    let redirect = Redirect::to("/settings").into_response();

    Ok((jar, redirect).into_response())
}
