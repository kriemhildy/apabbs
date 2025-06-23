//! Authentication and account management routes and handlers.
//!
//! This module provides endpoints for user login, registration, logout, and account token reset.
//! It handles session management, credential validation, and user authentication flows.

use super::*;

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
) -> Response {
    let mut tx = state.db.begin().await.expect("begins");

    // Initialize user from session
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };

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

    (jar, html).into_response()
}

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
    Form(credentials): Form<Credentials>,
) -> Response {
    let mut tx = state.db.begin().await.expect("begins");

    // Initialize user from session
    let (_user, jar) = match init_user(jar, &mut tx, method, Some(credentials.session_token)).await
    {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };

    // Check if username exists
    if !credentials.username_exists(&mut tx).await {
        return not_found("Username does not exist");
    }

    // Validate credentials
    let jar = match credentials.authenticate(&mut tx).await {
        None => return bad_request("Incorrect password"),
        Some(account) => add_account_cookie(jar, &account, &credentials),
    };

    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
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
) -> Response {
    let mut tx = state.db.begin().await.expect("begins");

    // Initialize user from session
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };

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

    (jar, html).into_response()
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
) -> Response {
    let mut tx = state.db.begin().await.expect("begins");

    // Initialize user from session
    let (_user, jar) = match init_user(jar, &mut tx, method, Some(credentials.session_token)).await
    {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };

    // Check if username is already taken
    if credentials.username_exists(&mut tx).await {
        return bad_request("Username is already taken");
    }

    // Validate credentials
    let errors = credentials.validate();
    if !errors.is_empty() {
        return bad_request(&format!(
            "Invalid registration data:\n{}",
            errors.join("\n")
        ));
    }

    // Check for IP bans
    let ip_hash = ip_hash(&headers);
    if let Some(response) = check_for_ban(&mut tx, &ip_hash, None, None).await {
        tx.commit().await.expect("commits");
        return response;
    }

    // Create the account
    let account = credentials.register(&mut tx, &ip_hash).await;
    let jar = add_account_cookie(jar, &account, &credentials);

    tx.commit().await.expect("commits");

    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

/// Represents a logout request.
#[derive(serde::Serialize, serde::Deserialize)]
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
    Form(logout): Form<Logout>,
) -> Response {
    let mut tx = state.db.begin().await.expect("begins");

    // Initialize user from session
    let (user, jar) = match init_user(jar, &mut tx, method, Some(logout.session_token)).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };

    // Verify user is logged in
    if user.account.is_none() {
        return bad_request("You must be logged in to log out");
    }

    // Clear account cookie and redirect
    let jar = remove_account_cookie(jar);
    let redirect = Redirect::to(ROOT);

    (jar, redirect).into_response()
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
    Form(logout): Form<Logout>,
) -> Response {
    let mut tx = state.db.begin().await.expect("begins");

    // Initialize user from session
    let (user, jar) = match init_user(jar, &mut tx, method, Some(logout.session_token)).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };

    // Verify user is logged in and reset token
    let jar = match user.account {
        None => return bad_request("You must be logged in to reset your token"),
        Some(account) => {
            account.reset_token(&mut tx).await;
            remove_account_cookie(jar)
        }
    };

    tx.commit().await.expect("commits");

    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}
