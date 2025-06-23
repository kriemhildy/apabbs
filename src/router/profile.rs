//! User profile and settings routes and handlers.
//!
//! This module provides endpoints for displaying user profiles, managing account settings,
//! updating time zones, and changing passwords. It enforces authentication and input validation.

use super::*;

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
/// A `Response` containing the rendered user profile page.
pub async fn user_profile(
    method: Method,
    State(state): State<AppState>,
    Path(username): Path<String>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, None).await?;

    // Find account by username
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
            user_agent => analyze_user_agent(&headers),
            user,
            account,
            posts,
        ),
    ));

    Ok((jar, html).into_response())
}

/// Displays the user settings page.
///
/// Shows options for account management and preferences.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `headers`: HTTP headers for user agent analysis
///
/// # Returns
/// A `Response` containing the rendered settings page.
pub async fn settings(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, None).await?;

    // Verify user is logged in
    if user.account.is_none() {
        return Ok(unauthorized("You must be logged in to access settings"));
    }

    // Get time zones for selection
    let time_zones = TimeZoneUpdate::select_time_zones(&mut tx).await;

    // Check for notice messages
    let (jar, notice) = remove_notice_cookie(jar);

    // Render settings page
    let html = Html(render(
        &state,
        "settings.jinja",
        minijinja::context!(
            dev => crate::dev(),
            host => crate::host(),
            user_agent => analyze_user_agent(&headers),
            user,
            time_zones,
            notice,
        ),
    ));

    Ok((jar, html).into_response())
}

/// Updates a user's time zone preference.
///
/// Changes the time zone setting for a logged-in user after validation.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `Form(time_zone_update)`: Form data containing the new time zone
///
/// # Returns
/// A `Response` redirecting to the settings page with a confirmation notice.
pub async fn update_time_zone(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Form(time_zone_update): Form<TimeZoneUpdate>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, Some(time_zone_update.session_token)).await?;

    // Verify user is logged in
    let account = match user.account {
        None => {
            return Ok(unauthorized(
                "You must be logged in to update your time zone",
            ));
        }
        Some(account) => account,
    };

    // Validate time zone
    let time_zones = TimeZoneUpdate::select_time_zones(&mut tx).await;
    if !time_zones.contains(&time_zone_update.time_zone) {
        return Ok(bad_request("Invalid time zone selection"));
    }

    // Update time zone preference
    time_zone_update.update(&mut tx, account.id).await;
    tx.commit().await?;

    // Set confirmation notice
    let jar = add_notice_cookie(jar, "Time zone updated.");
    let redirect = Redirect::to("/settings").into_response();

    Ok((jar, redirect).into_response())
}

/// Updates a user's password.
///
/// Changes the password for a logged-in user after validation.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `Form(credentials)`: Form data containing the new password and credentials
///
/// # Returns
/// A `Response` redirecting to the settings page with a confirmation notice.
pub async fn update_password(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Form(credentials): Form<Credentials>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, Some(credentials.session_token)).await?;

    // Verify user is logged in as the correct user
    match user.account {
        None => {
            return Ok(unauthorized(
                "You must be logged in to update your password",
            ));
        }
        Some(account) => {
            if account.username != credentials.username {
                return Ok(unauthorized("You are not logged in as this user"));
            }
        }
    };

    // Validate new password
    let errors = credentials.validate();
    if !errors.is_empty() {
        return Ok(bad_request(&format!(
            "Password update failed:\n{}",
            errors.join("\n")
        )));
    }

    // Update password
    credentials.update_password(&mut tx).await;
    tx.commit().await?;

    // Set confirmation notice
    let jar = add_notice_cookie(jar, "Password updated.");
    let redirect = Redirect::to("/settings").into_response();

    Ok((jar, redirect).into_response())
}
