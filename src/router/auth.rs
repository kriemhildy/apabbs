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

/// Displays the login form.
///
/// Renders the page for user authentication.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state (database, config, etc.)
/// - `jar`: Cookie jar for session management
/// - `headers`: HTTP headers for user agent analysis
///
/// # Returns
/// A rendered login form as a `Response`.
pub async fn login_form(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!("Failed to begin database transaction: {:?}", e);
        InternalServerError("Database transaction error.".to_string())
    })?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None)
        .await
        .map_err(|e| {
            tracing::warn!("Failed to initialize user session: {:?}", e);
            e
        })?;

    // Render the login form
    let html = Html(render(
        &state,
        "login.jinja",
        minijinja::context!(
            dev => crate::dev(),
            host => crate::host(),
            user_agent => analyze_user_agent(&headers),
            user,
        ),
    ));

    Ok((jar, html).into_response())
}

/// Displays the registration form.
///
/// Renders the page for creating a new account.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `headers`: HTTP headers for user agent analysis
///
/// # Returns
/// A rendered registration form as a `Response`.
pub async fn registration_form(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!("Failed to begin database transaction: {:?}", e);
        InternalServerError("Database transaction error.".to_string())
    })?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, None)
        .await
        .map_err(|e| {
            tracing::warn!("Failed to initialize user session: {:?}", e);
            e
        })?;

    // Render the registration form
    let html = Html(render(
        &state,
        "register.jinja",
        minijinja::context!(
            dev => crate::dev(),
            host => crate::host(),
            user_agent => analyze_user_agent(&headers),
            user,
        ),
    ));

    Ok((jar, html).into_response())
}

// ================================================================================================
// Authentication and Account Actions
// ================================================================================================

/// Processes user login attempts.
///
/// Authenticates users with provided credentials and sets session cookies.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `Form(credentials)`: User credentials submitted via form
///
/// # Returns
/// Redirects to the root page on success, or an error response on failure.
pub async fn authenticate(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(credentials): Form<Credentials>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!("Failed to begin database transaction: {:?}", e);
        InternalServerError("Database transaction error.".to_string())
    })?;

    // Initialize user from session
    let (_user, jar) = init_user(
        jar,
        &mut tx,
        method,
        &headers,
        Some(credentials.session_token),
    )
    .await
    .map_err(|e| {
        tracing::warn!("Failed to initialize user session: {:?}", e);
        e
    })?;

    // Check if username exists
    if !credentials.username_exists(&mut tx).await.map_err(|e| {
        tracing::error!("Failed to check username existence: {:?}", e);
        InternalServerError("Failed to check username existence.".to_string())
    })? {
        return Err(NotFound("Username does not exist".to_owned()));
    }

    // Validate credentials
    let jar = match credentials.authenticate(&mut tx).await.map_err(|e| {
        tracing::error!("Failed to authenticate credentials: {:?}", e);
        InternalServerError("Failed to authenticate credentials.".to_string())
    })? {
        None => return Err(BadRequest("Incorrect password".to_owned())),
        Some(account) => add_account_cookie(jar, &account, &credentials),
    };

    let redirect = Redirect::to(ROOT);
    Ok((jar, redirect).into_response())
}

/// Processes account creation requests.
///
/// Validates registration information and creates new user accounts.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `headers`: HTTP headers for IP hash and ban checks
/// - `Form(credentials)`: User credentials submitted via form
///
/// # Returns
/// Redirects to the root page on success, or an error response on failure.
pub async fn create_account(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(credentials): Form<Credentials>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!("Failed to begin database transaction: {:?}", e);
        InternalServerError("Database transaction error.".to_string())
    })?;

    // Initialize user from session
    let (user, jar) = init_user(
        jar,
        &mut tx,
        method,
        &headers,
        Some(credentials.session_token),
    )
    .await
    .map_err(|e| {
        tracing::warn!("Failed to initialize user session: {:?}", e);
        e
    })?;

    // Check if username is already taken
    if credentials.username_exists(&mut tx).await.map_err(|e| {
        tracing::error!("Failed to check username existence: {:?}", e);
        InternalServerError("Failed to check username existence.".to_string())
    })? {
        return Err(BadRequest("Username is already taken".to_owned()));
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
        return Err(Banned(ban_expires_at));
    }

    // Check for flooding attempts
    if ban::flooding(&mut tx, &user.ip_hash).await.map_err(|e| {
        tracing::error!("Failed to check for flooding: {:?}", e);
        InternalServerError("Failed to check for flooding.".to_string())
    })? {
        let ban_expires_at = ban::insert(
            &mut tx,
            &user.ip_hash,
            user.account.as_ref().map(|a| a.id),
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to insert ban: {:?}", e);
            InternalServerError("Failed to insert ban.".to_string())
        })?;
        ban::prune(&mut tx, &user.ip_hash).await.map_err(|e| {
            tracing::error!("Failed to prune old bans: {:?}", e);
            InternalServerError("Failed to prune old bans.".to_string())
        })?;
        tx.commit().await.map_err(|e| {
            tracing::error!("Failed to commit transaction: {:?}", e);
            InternalServerError("Failed to commit transaction.".to_string())
        })?;
        return Err(Banned(ban_expires_at));
    }

    // Create the account
    let account = credentials
        .register(&mut tx, &user.ip_hash)
        .await
        .map_err(|e| {
            tracing::error!("Failed to register account: {:?}", e);
            InternalServerError("Failed to register account.".to_string())
        })?;
    let jar = add_account_cookie(jar, &account, &credentials);

    tx.commit().await.map_err(|e| {
        tracing::error!("Failed to commit transaction: {:?}", e);
        InternalServerError("Failed to commit transaction.".to_string())
    })?;

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

/// Processes user logout requests.
///
/// Clears authentication cookies and ends user session.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `Form(logout)`: Logout request containing session token
///
/// # Returns
/// Redirects to the root page after logout.
pub async fn logout(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(logout): Form<Logout>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!("Failed to begin database transaction: {:?}", e);
        InternalServerError("Database transaction error.".to_string())
    })?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, Some(logout.session_token))
        .await
        .map_err(|e| {
            tracing::warn!("Failed to initialize user session: {:?}", e);
            e
        })?;

    // Verify user is logged in
    if user.account.is_none() {
        return Err(BadRequest("You must be logged in to log out".to_owned()));
    }

    // Clear account cookie and redirect
    let jar = remove_account_cookie(jar);
    let redirect = Redirect::to(ROOT);

    Ok((jar, redirect).into_response())
}

/// Resets a user's authentication token.
///
/// Invalidates all existing sessions for security purposes.
///
/// # Parameters
/// - `method`: HTTP method of the request
/// - `State(state)`: Application state
/// - `jar`: Cookie jar for session management
/// - `Form(logout)`: Logout request containing session token
///
/// # Returns
/// Redirects to the root page after resetting the token.
pub async fn reset_account_token(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(logout): Form<Logout>,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!("Failed to begin database transaction: {:?}", e);
        InternalServerError("Database transaction error.".to_string())
    })?;

    // Initialize user from session
    let (user, jar) = init_user(jar, &mut tx, method, &headers, Some(logout.session_token))
        .await
        .map_err(|e| {
            tracing::warn!("Failed to initialize user session: {:?}", e);
            e
        })?;

    // Verify user is logged in and reset token
    let jar = match user.account {
        None => {
            return Err(BadRequest(
                "You must be logged in to reset your token".to_owned(),
            ));
        }
        Some(account) => {
            account.reset_token(&mut tx).await.map_err(|e| {
                tracing::error!("Failed to reset account token: {:?}", e);
                InternalServerError("Failed to reset account token.".to_string())
            })?;
            remove_account_cookie(jar)
        }
    };

    tx.commit().await.map_err(|e| {
        tracing::error!("Failed to commit transaction: {:?}", e);
        InternalServerError("Failed to commit transaction.".to_string())
    })?;

    let redirect = Redirect::to(ROOT);
    Ok((jar, redirect).into_response())
}
