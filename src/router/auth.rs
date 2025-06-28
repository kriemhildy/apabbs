//! Authentication and account management routes and handlers.
//!
//! This module provides endpoints for user login, registration, logout, and account token reset.
//! It handles session management, credential validation, and user authentication flows.

use super::*;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

// ================================================================================================
// Login and Registration Forms
// ================================================================================================

/// Displays the login form for user authentication.
pub async fn login_form(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Render the login form
    let html = Html(render(
        &state,
        "login.jinja",
        minijinja::context!(
            dev => crate::dev(),
            host => crate::host(),
            user,
        ),
    )?);

    Ok((jar, html).into_response())
}

/// Displays the registration form for creating a new account.
pub async fn registration_form(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Render the registration form
    let html = Html(render(
        &state,
        "register.jinja",
        minijinja::context!(
            dev => crate::dev(),
            host => crate::host(),
            user,
        ),
    )?);

    Ok((jar, html).into_response())
}

// ================================================================================================
// Authentication and Account Actions
// ================================================================================================

/// Processes user login attempts and sets session cookies.
pub async fn authenticate(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(credentials): Form<Credentials>,
) -> Result<Response, ResponseError> {
    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session
    let (_user, jar) = init_user(
        jar,
        &mut tx,
        method,
        &headers,
        Some(credentials.session_token),
    )
    .await?;

    // Check if username exists
    if !credentials.username_exists(&mut tx).await? {
        return Err(NotFound("Username does not exist".to_string()));
    }

    // Validate credentials
    let jar = match credentials.authenticate(&mut tx).await? {
        None => return Err(BadRequest("Incorrect password".to_string())),
        Some(account) => add_account_cookie(jar, &account, &credentials),
    };

    let redirect = Redirect::to(ROOT);
    Ok((jar, redirect).into_response())
}

/// Processes account creation requests and creates new user accounts.
pub async fn create_account(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(credentials): Form<Credentials>,
) -> Result<Response, ResponseError> {
    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session
    let (user, jar) = init_user(
        jar,
        &mut tx,
        method,
        &headers,
        Some(credentials.session_token),
    )
    .await?;

    // Check if username is already taken
    if credentials.username_exists(&mut tx).await? {
        return Err(BadRequest("Username is already taken".to_string()));
    }

    // Validate credentials
    let errors = credentials.validate();
    if !errors.is_empty() {
        return Err(BadRequest(format!(
            "Invalid registration data:\n{}",
            errors.join("\n")
        )));
    }

    // Check for existing IP ban
    if let Some(ban_expires_at) = user.ban_expires_at {
        return Err(Forbidden(format!("You are banned until {ban_expires_at}.")));
    }

    // Ban user if they are flooding
    if let Some(expires_at) =
        ban_if_flooding(&mut tx, &user.ip_hash, user.account.as_ref().map(|a| a.id)).await?
    {
        commit_transaction(tx).await?;
        return Err(Forbidden(format!(
            "You have been banned for flooding until {expires_at}."
        )));
    }

    // Create the account
    let account = credentials.register(&mut tx, &user.ip_hash).await?;
    let jar = add_account_cookie(jar, &account, &credentials);

    commit_transaction(tx).await?;

    let redirect = Redirect::to(ROOT);
    Ok((jar, redirect).into_response())
}

// ================================================================================================
// Logout and Token Reset
// ================================================================================================

/// Represents a logout request.
#[derive(Serialize, Deserialize)]
pub struct Logout {
    /// Session token to invalidate during logout
    pub session_token: Uuid,
}

/// Processes user logout requests, clearing authentication cookies and ending the session.
pub async fn logout(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(logout): Form<Logout>,
) -> Result<Response, ResponseError> {
    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, Some(logout.session_token)).await?;

    // Verify user is logged in
    if user.account.is_none() {
        return Err(BadRequest("You must be logged in to log out".to_string()));
    }

    // Clear account cookie and redirect
    let jar = remove_account_cookie(jar);
    let redirect = Redirect::to(ROOT);

    Ok((jar, redirect).into_response())
}

/// Resets a user's authentication token, invalidating all existing sessions.
pub async fn reset_account_token(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(logout): Form<Logout>,
) -> Result<Response, ResponseError> {
    let mut tx = begin_transaction(&state.db).await?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, Some(logout.session_token)).await?;

    // Verify user is logged in and reset token
    let jar = match user.account {
        None => {
            return Err(BadRequest(
                "You must be logged in to reset your token".to_string(),
            ));
        }
        Some(account) => {
            account.reset_token(&mut tx).await?;
            remove_account_cookie(jar)
        }
    };

    commit_transaction(tx).await?;

    let redirect = Redirect::to(ROOT);
    Ok((jar, redirect).into_response())
}
