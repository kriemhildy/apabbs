//! Router helper functions and utilities.
//!
//! This module provides utilities for HTTP request/response handling, cookie management,
//! user authentication, security checks, template rendering, session management, and browser
//! detection. It also includes functions for managing posts and validating access permissions.

use super::*;
use axum_extra::extract::cookie::{Cookie, SameSite};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use std::error::Error;

//==================================================================================================
// Constants
//==================================================================================================

/// HTTP header name for the client's real IP address, as set by the reverse proxy (e.g., nginx).
pub const X_REAL_IP: &str = "X-Real-IP";
/// HTTP header name for fetch mode, used to distinguish AJAX/fetch requests from navigation.
pub const SEC_FETCH_MODE: &str = "Sec-Fetch-Mode";
/// Cookie name for the user's account authentication token, used for persistent login.
pub const ACCOUNT_COOKIE: &str = "account";
/// Cookie name for the user's session token, used for CSRF protection and session tracking.
pub const SESSION_COOKIE: &str = "session";
/// Cookie name for flash notice messages, used to display one-time notifications to the user.
pub const NOTICE_COOKIE: &str = "notice";

//==================================================================================================
// Security Utilities
//==================================================================================================

/// Generate a hash of the client's IP address for tracking and ban enforcement.
///
/// # Errors
/// Returns a `BadRequest` error if the required header is missing or invalid.
pub fn ip_hash(headers: &HeaderMap) -> Result<String, ResponseError> {
    let ip = headers
        .get(X_REAL_IP)
        .ok_or_else(|| BadRequest("Missing X-Real-IP header".to_string()))?
        .to_str()
        .map_err(|_| BadRequest("X-Real-IP is not UTF-8".to_string()))?;
    Ok(sha256::digest(crate::secret_key() + ip))
}

/// Check if an IP address is flooding. If so, ban the account and prune its content.
pub async fn ban_if_flooding(
    tx: &mut PgConnection,
    ip_hash: &str,
    account_id: Option<i32>,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    if ban::flooding(tx, ip_hash).await? {
        let expires_at = ban::insert(tx, ip_hash, account_id, None).await?;
        ban::prune(tx, ip_hash).await?;
        return Ok(Some(expires_at));
    }
    Ok(None)
}

//==================================================================================================
// Cookie Management
//==================================================================================================

/// Create a cookie with secure, HTTP-only, and SameSite settings.
///
/// This function builds a cookie with the given name and value, sets it to be secure (unless in dev mode),
/// HTTP-only, and SameSite=Lax. If `permanent` is true, the cookie will persist after the browser closes.
///
/// # Arguments
/// * `name` - The name of the cookie.
/// * `value` - The value to store in the cookie.
/// * `permanent` - Whether the cookie should be persistent.
///
/// # Returns
/// A configured `Cookie` instance.
pub fn build_cookie(name: &str, value: &str, permanent: bool) -> Cookie<'static> {
    let mut cookie = Cookie::build((name.to_owned(), value.to_owned()))
        .secure(!crate::dev())
        .http_only(true)
        .path("/")
        .same_site(SameSite::Lax)
        .build();
    if permanent {
        cookie.make_permanent()
    }
    cookie
}

/// Create a cookie for removal by setting its expiration in the past.
///
/// # Arguments
/// * `name` - The name of the cookie to remove.
///
/// # Returns
/// A `Cookie` instance configured for removal.
pub fn removal_cookie(name: &str) -> Cookie<'static> {
    Cookie::build(name.to_owned()).path("/").build()
}

/// Add a notice cookie for flash messages to the cookie jar.
///
/// This function adds a one-time notice message to the user's cookies, which can be displayed on the next page load.
///
/// # Arguments
/// * `jar` - The current `CookieJar`.
/// * `notice` - The notice message to add.
///
/// # Returns
/// The updated `CookieJar` with the notice cookie added.
pub fn add_notice_cookie(jar: CookieJar, notice: &str) -> CookieJar {
    jar.add(build_cookie(NOTICE_COOKIE, notice, false))
}

/// Remove the notice cookie from the jar and extract its value, if present.
///
/// This function removes the notice cookie and returns its value (if any) along with the updated jar.
///
/// # Arguments
/// * `jar` - The current `CookieJar`.
///
/// # Returns
/// A tuple of the updated `CookieJar` and an `Option<String>` containing the notice value.
pub fn remove_notice_cookie(mut jar: CookieJar) -> (CookieJar, Option<String>) {
    let notice = match jar.get(NOTICE_COOKIE) {
        Some(cookie) => {
            let value = cookie.value().to_owned();
            jar = jar.remove(removal_cookie(NOTICE_COOKIE));
            Some(value)
        }
        None => None,
    };
    (jar, notice)
}

/// Add the account token cookie for authentication to the cookie jar.
///
/// This function adds a persistent authentication cookie for the user's account.
///
/// # Arguments
/// * `jar` - The current `CookieJar`.
/// * `account` - The user's account.
/// * `credentials` - The user's credentials (used to determine permanence).
///
/// # Returns
/// The updated `CookieJar` with the account cookie added.
pub fn add_account_cookie(
    jar: CookieJar,
    account: &Account,
    credentials: &Credentials,
) -> CookieJar {
    let cookie = build_cookie(
        ACCOUNT_COOKIE,
        &account.token.to_string(),
        credentials.year_checked(),
    );
    jar.add(cookie)
}

/// Remove the account cookie from the jar for logout.
///
/// # Arguments
/// * `jar` - The current `CookieJar`.
///
/// # Returns
/// The updated `CookieJar` with the account cookie removed.
pub fn remove_account_cookie(jar: CookieJar) -> CookieJar {
    jar.remove(removal_cookie(ACCOUNT_COOKIE))
}

//==================================================================================================
// User and Session Management
//==================================================================================================

/// Initialize a user session from cookies or create a new session if none exists.
///
/// Handles CSRF protection and sets the session time zone.
///
/// # Errors
/// Returns `Unauthorized` for CSRF failures or invalid tokens.
pub async fn init_user(
    mut jar: CookieJar,
    tx: &mut PgConnection,
    method: Method,
    headers: &HeaderMap,
    csrf_token: Option<Uuid>,
) -> Result<(User, CookieJar), ResponseError> {
    let account = match jar.get(ACCOUNT_COOKIE) {
        None => None,
        Some(cookie) => {
            let token = match Uuid::try_parse(cookie.value()) {
                Err(_) => {
                    jar = remove_account_cookie(jar);
                    None
                }
                Ok(uuid) => Some(uuid),
            };
            match token {
                None => None,
                Some(token) => match Account::select_by_token(tx, &token).await? {
                    None => {
                        jar = remove_account_cookie(jar);
                        None
                    }
                    Some(account) => Some(account),
                },
            }
        }
    };
    let session_token = match jar.get(SESSION_COOKIE) {
        None => None,
        Some(cookie) => Uuid::try_parse(cookie.value()).ok(),
    };
    let session_token = match session_token {
        None => {
            let token = Uuid::new_v4();
            jar = jar.add(build_cookie(SESSION_COOKIE, &token.to_string(), false));
            token
        }
        Some(token) => token,
    };
    if method != Method::GET && csrf_token.is_none() {
        return Err(Unauthorized(
            "CSRF token required for non-GET requests".to_owned(),
        ));
    }
    if let Some(csrf_token) = csrf_token {
        if session_token != csrf_token {
            return Err(Unauthorized(
                "CSRF token mismatch: possible forgery attempt".to_owned(),
            ));
        }
    }
    let ip_hash = ip_hash(headers)?;
    let agent = analyze_user_agent(headers);
    let ban_expires_at = ban::exists(tx, &ip_hash, account.as_ref().map(|a| a.id)).await?;
    let user = User {
        account,
        session_token,
        ip_hash,
        agent,
        ban_expires_at,
    };
    set_session_time_zone(tx, user.time_zone()).await?;
    Ok((user, jar))
}

/// Set the PostgreSQL session time zone for the current connection.
///
/// This ensures that all time-related queries use the user's preferred time zone.
pub async fn set_session_time_zone(
    tx: &mut PgConnection,
    time_zone: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    sqlx::query(&format!("SET TIME ZONE '{}'", time_zone))
        .execute(&mut *tx)
        .await
        .map(|_| ())
        .map_err(|e| format!("Failed to set session time zone: {e}").into())
}

//==================================================================================================
// Post and Content Management
//==================================================================================================

/// Retrieve a post by key and validate access permissions for the current user.
///
/// This function fetches a post from the database and checks if the user is allowed to view it.
/// - If the post is reported, rejected, or banned, only admins can view it.
/// - If the post is pending, only the author or a moderator/admin can view it.
///
/// # Arguments
/// * `tx` - A mutable reference to the PostgreSQL connection/transaction.
/// * `key` - The unique key identifying the post.
/// * `user` - The current user making the request.
///
/// # Returns
/// * `Ok(Post)` if the post exists and the user has access.
/// * `Err(NotFound)` if the post does not exist.
/// * `Err(Unauthorized)` if the user is not allowed to view the post.
/// * `Err(sqlx::Error)` if a database error occurs (propagated by `?`).
pub async fn init_post(
    tx: &mut PgConnection,
    key: &str,
    user: &User,
) -> Result<Post, ResponseError> {
    use PostStatus::*;
    match Post::select_by_key(tx, key).await? {
        None => Err(NotFound("Post does not exist".to_owned())),
        Some(post) => {
            if [Reported, Rejected, Banned].contains(&post.status) && !user.admin() {
                return Err(Unauthorized(
                    "Post is reported, rejected, or banned".to_owned(),
                ));
            }
            if post.status == Pending && !(post.author(user) || user.mod_or_admin()) {
                return Err(Unauthorized("Post is pending approval".to_owned()));
            }
            Ok(post)
        }
    }
}

//==================================================================================================
// Templating and Rendering
//==================================================================================================

/// Render a template with the given context using the application's Jinja environment.
///
/// This function acquires a lock on the Jinja environment, reloads templates in development mode,
/// fetches the requested template, and renders it with the provided context.
///
/// # Arguments
/// * `state` - The application state containing the Jinja environment.
/// * `name` - The name of the template to render.
/// * `ctx` - The context to pass to the template.
///
/// # Returns
/// * `Ok(String)` containing the rendered HTML.
/// * `Err(InternalServerError)` if a lock cannot be acquired, the template is missing, or rendering fails.
pub fn render(
    state: &AppState,
    name: &str,
    ctx: minijinja::value::Value,
) -> Result<String, ResponseError> {
    if crate::dev() {
        let mut env = state.jinja.write().map_err(|_| {
            InternalServerError("Failed to acquire write lock for templates".to_string())
        })?;
        env.clear_templates();
    }
    let env = state.jinja.read().map_err(|_| {
        InternalServerError("Failed to acquire read lock for templates".to_string())
    })?;
    let tmpl = env
        .get_template(name)
        .map_err(|_| InternalServerError(format!("Template '{name}' not found")))?;
    tmpl.render(ctx)
        .map_err(|e| InternalServerError(format!("Template render error: {e}")))
}

/// Determine if a request is an AJAX/fetch request (not a navigation).
///
/// Returns `true` if the `Sec-Fetch-Mode` header is present and not equal to "navigate".
pub fn is_fetch_request(headers: &HeaderMap) -> bool {
    headers
        .get(SEC_FETCH_MODE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v != "navigate")
        .unwrap_or(false)
}

//==================================================================================================
// Browser and Client Detection
//==================================================================================================

/// Analyze the User-Agent header to detect platform and browser engine.
///
/// This function inspects the `User-Agent` header to determine if the client is using macOS and/or a Chromium-based browser.
///
/// # Arguments
/// * `headers` - The HTTP headers from the request.
///
/// # Returns
/// * `Some(UserAgent)` if the header is present and parsed.
/// * `None` if the header is missing or invalid.
pub fn analyze_user_agent(headers: &HeaderMap) -> Option<UserAgent> {
    use axum::http::header::USER_AGENT;
    let user_agent_str = match headers.get(USER_AGENT) {
        None => return None,
        Some(header) => match header.to_str() {
            Err(_) => return None,
            Ok(ua) => ua,
        },
    };
    Some(UserAgent {
        mac: user_agent_str.contains("Macintosh"),
        chromium: user_agent_str.contains("Chrome"),
    })
}

/// Generate a UTC timestamp string for the current hour.
///
/// This function queries the database for the current timestamp in UTC, formatted according to the application's settings.
///
/// # Arguments
/// * `tx` - A mutable reference to the PostgreSQL connection/transaction.
///
/// # Returns
/// * `Ok(String)` containing the formatted UTC hour timestamp.
/// * `Err(sqlx::Error)` if the query fails.
pub async fn utc_hour_timestamp(
    tx: &mut PgConnection,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    sqlx::query_scalar("SELECT to_char(current_timestamp AT TIME ZONE 'UTC', $1)")
        .bind(crate::POSTGRES_UTC_HOUR)
        .fetch_one(tx)
        .await
        .map_err(|e| format!("Failed to get UTC hour timestamp: {e}").into())
}

//==================================================================================================
// Database transactions
//==================================================================================================

/// Begin a new database transaction.
pub async fn begin_transaction(
    db: &PgPool,
) -> Result<Transaction<'_, Postgres>, Box<dyn Error + Send + Sync>> {
    db.begin()
        .await
        .map_err(|e| format!("Failed to begin database transaction: {e}").into())
}

/// Commit a database transaction.
pub async fn commit_transaction(
    tx: Transaction<'_, Postgres>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    tx.commit()
        .await
        .map_err(|e| format!("Failed to commit transaction: {e}").into())
}
