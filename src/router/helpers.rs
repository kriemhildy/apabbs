//! Router helper functions and utilities.
//!
//! Common utilities for HTTP request/response handling, cookie management,
//! user authentication, security checks, and template rendering.

use super::*;
use axum_extra::extract::cookie::{Cookie, SameSite};
use sqlx::PgConnection;

// HTTP header constants
pub const X_REAL_IP: &str = "X-Real-IP";
pub const SEC_FETCH_MODE: &str = "Sec-Fetch-Mode";

// Cookie name constants
pub const ACCOUNT_COOKIE: &str = "account";
pub const SESSION_COOKIE: &str = "session";
pub const NOTICE_COOKIE: &str = "notice";

//==================================================================================================
// Response Helpers
//==================================================================================================

/// Create an HTTP response with the specified status code and message.
fn http_status(status: StatusCode, msg: &str) -> Response {
    (
        status,
        format!(
            "{} {}\n\n{}",
            status.as_str(),
            status.canonical_reason().unwrap_or("Unknown Status"),
            msg
        ),
    )
        .into_response()
}

/// 400 Bad Request response.
pub fn bad_request(msg: &str) -> Response {
    http_status(StatusCode::BAD_REQUEST, &format!("Bad Request: {msg}"))
}

/// 401 Unauthorized response.
pub fn unauthorized(msg: &str) -> Response {
    http_status(StatusCode::UNAUTHORIZED, &format!("Unauthorized: {msg}"))
}

/// 403 Forbidden response.
pub fn forbidden(msg: &str) -> Response {
    http_status(StatusCode::FORBIDDEN, &format!("Forbidden: {msg}"))
}

/// 404 Not Found response.
pub fn not_found(msg: &str) -> Response {
    http_status(StatusCode::NOT_FOUND, &format!("Not Found: {msg}"))
}

/// 500 Internal Server Error response.
pub fn internal_server_error(msg: &str) -> Response {
    http_status(
        StatusCode::INTERNAL_SERVER_ERROR,
        &format!("Internal Server Error: {msg}"),
    )
}

/// 403 Forbidden response for banned users with ban expiration info.
pub fn ban_message(expires_at_str: &str) -> Response {
    forbidden(&format!("Banned until {expires_at_str}"))
}

//==================================================================================================
// Security Utilities
//==================================================================================================

/// Generate a hash of the client's IP address for tracking.
pub fn ip_hash(headers: &HeaderMap) -> String {
    let ip = headers
        .get(X_REAL_IP)
        .expect("Missing X-Real-IP header")
        .to_str()
        .expect("X-Real-IP header is not valid UTF-8");
    sha256::digest(apabbs::secret_key() + ip)
}

/// Determine if a request is an AJAX/Fetch request (not navigation).
pub fn is_fetch_request(headers: &HeaderMap) -> bool {
    headers
        .get(SEC_FETCH_MODE)
        .map(|v| {
            v.to_str()
                .expect("Sec-Fetch-Mode header is not valid UTF-8")
        })
        .is_some_and(|v| v != "navigate")
}

/// Check if a user is banned or rate-limited, returning a response if so.
pub async fn check_for_ban(
    tx: &mut PgConnection,
    ip_hash: &str,
    banned_account_id: Option<i32>,
    admin_account_id: Option<i32>,
) -> Option<Response> {
    if let Some(expires_at_str) = ban::exists(tx, ip_hash, banned_account_id).await {
        return Some(ban_message(&expires_at_str));
    }
    if ban::flooding(tx, ip_hash).await {
        let expires_at_str = ban::insert(tx, ip_hash, banned_account_id, admin_account_id).await;
        ban::prune(tx, ip_hash).await;
        return Some(ban_message(&expires_at_str));
    }
    None
}

//==================================================================================================
// Cookie Management
//==================================================================================================

/// Create a cookie with secure, HTTP-only, and SameSite settings.
pub fn build_cookie(name: &str, value: &str, permanent: bool) -> Cookie<'static> {
    let mut cookie = Cookie::build((name.to_owned(), value.to_owned()))
        .secure(!apabbs::dev())
        .http_only(true)
        .path("/")
        .same_site(SameSite::Lax)
        .build();
    if permanent {
        cookie.make_permanent()
    }
    cookie
}

/// Create a cookie for removal (expiration).
pub fn removal_cookie(name: &str) -> Cookie<'static> {
    Cookie::build(name.to_owned()).path("/").build()
}

/// Add a notice cookie for flash messages.
pub fn add_notice_cookie(jar: CookieJar, notice: &str) -> CookieJar {
    jar.add(build_cookie(NOTICE_COOKIE, notice, false))
}

/// Remove the notice cookie and extract its value.
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

/// Add the account token cookie for authentication.
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

/// Remove the account cookie for logout.
pub fn remove_account_cookie(jar: CookieJar) -> CookieJar {
    jar.remove(removal_cookie(ACCOUNT_COOKIE))
}

//==================================================================================================
// User and Session Management
//==================================================================================================

/// Initialize a user session from cookies or create a new session.
/// Handles authentication, CSRF protection, and timezone settings.
pub async fn init_user(
    mut jar: CookieJar,
    tx: &mut PgConnection,
    method: Method,
    csrf_token: Option<Uuid>,
) -> Result<(User, CookieJar), Response> {
    // Account cookie
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
                Some(token) => match Account::select_by_token(tx, &token).await {
                    None => {
                        jar = remove_account_cookie(jar);
                        None
                    }
                    Some(account) => Some(account),
                },
            }
        }
    };
    // Session cookie
    let session_token = match jar.get(SESSION_COOKIE) {
        None => None,
        Some(cookie) => match Uuid::try_parse(cookie.value()) {
            Err(_) => None,
            Ok(uuid) => Some(uuid),
        },
    };
    let session_token = match session_token {
        None => {
            let token = Uuid::new_v4();
            jar = jar.add(build_cookie(SESSION_COOKIE, &token.to_string(), false));
            token
        }
        Some(token) => token,
    };
    // CSRF protection
    if method != Method::GET && csrf_token.is_none() {
        return Err(unauthorized("CSRF token is required for this request"));
    }
    if let Some(csrf_token) = csrf_token {
        if session_token != csrf_token {
            return Err(unauthorized(
                "CSRF token mismatch: possible forgery attempt",
            ));
        }
    }
    let user = User {
        account,
        session_token,
    };
    set_session_time_zone(tx, user.time_zone()).await;
    Ok((user, jar))
}

/// Set the PostgreSQL session time zone to match the user preference.
pub async fn set_session_time_zone(tx: &mut PgConnection, time_zone: &str) {
    sqlx::query(&format!("SET TIME ZONE '{}'", time_zone))
        .execute(&mut *tx)
        .await
        .expect("Failed to set session time zone");
}

//==================================================================================================
// Post and Content Management
//==================================================================================================

/// Retrieve a post and validate access permissions.
pub async fn init_post(tx: &mut PgConnection, key: &str, user: &User) -> Result<Post, Response> {
    use PostStatus::*;
    match Post::select_by_key(tx, &key).await {
        None => Err(not_found("Post does not exist")),
        Some(post) => {
            if [Reported, Rejected, Banned].contains(&post.status) && !user.admin() {
                return Err(unauthorized("Post is reported, rejected, or banned"));
            }
            if post.status == Pending && !(post.author(user) || user.mod_or_admin()) {
                return Err(unauthorized("Post is pending approval"));
            }
            Ok(post)
        }
    }
}

//==================================================================================================
// Templating and Rendering
//==================================================================================================

/// Render a template with the given context.
pub fn render(state: &AppState, name: &str, ctx: minijinja::value::Value) -> String {
    if apabbs::dev() {
        let mut env = state
            .jinja
            .write()
            .expect("Failed to acquire write lock for Jinja env");
        env.clear_templates();
    }
    let env = state
        .jinja
        .read()
        .expect("Failed to acquire read lock for Jinja env");
    let tmpl = env
        .get_template(name)
        .expect("Template not found in Jinja environment");
    tmpl.render(ctx).expect("Failed to render template")
}

//==================================================================================================
// Browser and Client Detection
//==================================================================================================

/// Information about the user's browser derived from the User-Agent header.
#[derive(serde::Serialize)]
pub struct UserAgent {
    pub mac: bool,
    pub chromium: bool,
}

/// Analyze the User-Agent header to extract browser information.
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

/// Returns a UTC timestamp string formatted as "YYYY-MM-DD-HH".
pub async fn utc_hour_timestamp(tx: &mut PgConnection) -> String {
    sqlx::query_scalar::<_, String>("SELECT to_char(current_timestamp AT TIME ZONE 'UTC', $1)")
        .bind(apabbs::POSTGRES_UTC_HOUR)
        .fetch_one(tx)
        .await
        .expect("Failed to fetch UTC timestamp from database")
}
