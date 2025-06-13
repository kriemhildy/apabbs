//! Router helper functions and utilities.
//!
//! This module provides common utilities for HTTP request/response handling,
//! cookie management, user authentication, security checks, and template rendering.

use super::{
    Account, AppState, CookieJar, Credentials, HeaderMap, IntoResponse, Method, Post, PostStatus,
    Response, StatusCode, User, Uuid, ban,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use sqlx::PgConnection;

/// HTTP header for the client's real IP address (when behind a proxy)
pub const X_REAL_IP: &str = "X-Real-IP";

/// HTTP header for Fetch metadata, indicating request mode (navigation vs. fetch)
pub const SEC_FETCH_MODE: &str = "Sec-Fetch-Mode";

/// Cookie name for storing the user's account authentication token
pub const ACCOUNT_COOKIE: &str = "account";

/// Cookie name for storing the user's session token
pub const SESSION_COOKIE: &str = "session";

/// Cookie name for storing temporary notification messages
pub const NOTICE_COOKIE: &str = "notice";

//==================================================================================================
// Response Helpers
//==================================================================================================

/// Creates an HTTP response with the specified status code and message.
///
/// Formats the response body with the status code, reason phrase, and message.
///
/// # Parameters
/// - `status`: The HTTP status code for the response
/// - `msg`: The message to include in the response body
///
/// # Returns
/// An HTTP response with the formatted body
fn http_status(status: StatusCode, msg: &str) -> Response {
    (
        status,
        format!(
            "{} {}\n\n{}",
            status.as_str(),
            status.canonical_reason().expect("status reason"),
            msg
        ),
    )
        .into_response()
}

/// Creates a 400 Bad Request response with the given message.
pub fn bad_request(msg: &str) -> Response {
    http_status(StatusCode::BAD_REQUEST, msg)
}

/// Creates a 401 Unauthorized response with the given message.
pub fn unauthorized(msg: &str) -> Response {
    http_status(StatusCode::UNAUTHORIZED, msg)
}

/// Creates a 403 Forbidden response with the given message.
pub fn forbidden(msg: &str) -> Response {
    http_status(StatusCode::FORBIDDEN, msg)
}

/// Creates a 404 Not Found response with the given message.
pub fn not_found(msg: &str) -> Response {
    http_status(StatusCode::NOT_FOUND, msg)
}

/// Creates a 500 Internal Server Error response with the given message.
pub fn internal_server_error(msg: &str) -> Response {
    http_status(StatusCode::INTERNAL_SERVER_ERROR, msg)
}

/// Creates a 403 Forbidden response for banned users with ban expiration information.
///
/// # Parameters
/// - `expires_at_str`: A formatted string indicating when the ban expires
///
/// # Returns
/// A 403 Forbidden response with the ban message
pub fn ban_message(expires_at_str: &str) -> Response {
    let msg = format!("Banned until {expires_at_str}");
    forbidden(&msg)
}

//==================================================================================================
// Security Utilities
//==================================================================================================

/// Generates a hash of the client's IP address for tracking purposes.
///
/// Combines the application secret key with the client IP for a secure hash.
///
/// # Parameters
/// - `headers`: HTTP headers containing the client IP
///
/// # Returns
/// A secure hash of the client's IP address
pub fn ip_hash(headers: &HeaderMap) -> String {
    let ip = headers
        .get(X_REAL_IP)
        .expect("get IP header")
        .to_str()
        .expect("convert header to str");
    sha256::digest(apabbs::secret_key() + ip)
}

/// Determines if a request is an AJAX/Fetch request rather than a page navigation.
///
/// Used to provide appropriate response types (JSON vs HTML redirect).
///
/// # Parameters
/// - `headers`: HTTP headers from the client request
///
/// # Returns
/// `true` if the request is an AJAX/Fetch request, `false` otherwise
pub fn is_fetch_request(headers: &HeaderMap) -> bool {
    headers
        .get(SEC_FETCH_MODE)
        .map(|v| v.to_str().expect("convert header to str"))
        .is_some_and(|v| v != "navigate")
}

/// Checks if a user is banned and handles ban enforcement.
///
/// Verifies if the IP or account is banned, and also checks for
/// request rate limiting to prevent flooding.
///
/// # Parameters
/// - `tx`: Database transaction for queries
/// - `ip_hash`: Hash of the client's IP address
/// - `banned_account_id_opt`: Optional account ID to check for bans
/// - `admin_account_id_opt`: Optional admin ID applying the ban
///
/// # Returns
/// `Some(Response)` with a ban message if banned, `None` otherwise
pub async fn check_for_ban(
    tx: &mut PgConnection,
    ip_hash: &str,
    banned_account_id_opt: Option<i32>,
    admin_account_id_opt: Option<i32>,
) -> Option<Response> {
    // Check for existing ban
    if let Some(expires_at_str) = ban::exists(tx, ip_hash, banned_account_id_opt).await {
        return Some(ban_message(&expires_at_str));
    }

    // Check for rate limiting/flooding
    if ban::flooding(tx, ip_hash).await {
        let expires_at_str =
            ban::insert(tx, ip_hash, banned_account_id_opt, admin_account_id_opt).await;
        ban::prune(tx, ip_hash).await;
        return Some(ban_message(&expires_at_str));
    }

    None
}

//==================================================================================================
// Cookie Management
//==================================================================================================

/// Creates a cookie with appropriate security settings.
///
/// # Parameters
/// - `name`: The cookie's name
/// - `value`: The cookie's value
/// - `permanent`: Whether the cookie should be persistent or session-only
///
/// # Returns
/// A configured cookie with appropriate security settings
pub fn build_cookie(name: &str, value: &str, permanent: bool) -> Cookie<'static> {
    let mut cookie = Cookie::build((name.to_owned(), value.to_owned()))
        .secure(!apabbs::dev()) // Secure in production, not in development
        .http_only(true) // Not accessible via JavaScript
        .path("/") // Available on all paths
        .same_site(SameSite::Lax) // Prevents CSRF while allowing linking
        .build();

    if permanent {
        cookie.make_permanent() // Extends expiration for long-term cookies
    }

    cookie
}

/// Creates a cookie for removal (expiration).
///
/// # Parameters
/// - `name`: The name of the cookie to remove
///
/// # Returns
/// A cookie configured for removal
pub fn removal_cookie(name: &str) -> Cookie<'static> {
    Cookie::build(name.to_owned()).path("/").build()
}

/// Adds a notice cookie with a temporary message.
///
/// Used for flash messages that display once after a redirect.
///
/// # Parameters
/// - `jar`: The cookie jar to add to
/// - `notice`: The message to store in the cookie
///
/// # Returns
/// Updated cookie jar containing the notice cookie
pub fn add_notice_cookie(jar: CookieJar, notice: &str) -> CookieJar {
    jar.add(build_cookie(NOTICE_COOKIE, notice, false))
}

/// Removes the notice cookie and extracts its value.
///
/// # Parameters
/// - `jar`: The cookie jar to remove from
///
/// # Returns
/// A tuple containing the updated cookie jar and the optional notice message
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

/// Adds the account token cookie for authentication.
///
/// # Parameters
/// - `jar`: The cookie jar to add to
/// - `account`: The account information to store
/// - `credentials`: The credentials used for login, determining persistence
///
/// # Returns
/// Updated cookie jar containing the account cookie
pub fn add_account_cookie(
    jar: CookieJar,
    account: &Account,
    credentials: &Credentials,
) -> CookieJar {
    let cookie = build_cookie(
        ACCOUNT_COOKIE,
        &account.token.to_string(),
        credentials.year_checked(), // Long-term cookie if user checked "remember me"
    );

    jar.add(cookie)
}

/// Removes the account cookie for logout.
///
/// # Parameters
/// - `jar`: The cookie jar to remove from
///
/// # Returns
/// Updated cookie jar with the account cookie removed
pub fn remove_account_cookie(jar: CookieJar) -> CookieJar {
    jar.remove(removal_cookie(ACCOUNT_COOKIE))
}

//==================================================================================================
// User and Session Management
//==================================================================================================

/// Initializes a user session from cookies or creates a new session.
///
/// Handles authentication, CSRF protection, and timezone settings.
///
/// # Parameters
/// - `jar`: Cookie jar from the request
/// - `tx`: Database transaction for queries
/// - `method`: HTTP method of the request
/// - `csrf_token`: Optional CSRF token from form submission
///
/// # Returns
/// A Result containing either the user and updated cookie jar, or an error response
pub async fn init_user(
    mut jar: CookieJar,
    tx: &mut PgConnection,
    method: Method,
    csrf_token: Option<Uuid>,
) -> Result<(User, CookieJar), Response> {
    // Process account cookie if present
    let account_opt = match jar.get(ACCOUNT_COOKIE) {
        None => None,
        Some(cookie) => {
            // Parse UUID from cookie value
            let token = match Uuid::try_parse(cookie.value()) {
                Err(_) => {
                    jar = remove_account_cookie(jar);
                    None
                }
                Ok(uuid) => Some(uuid),
            };

            // Look up account by token
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

    // Process session cookie or create new session
    let session_token_opt = match jar.get(SESSION_COOKIE) {
        None => None,
        Some(cookie) => match Uuid::try_parse(cookie.value()) {
            Err(_) => None,
            Ok(uuid) => Some(uuid),
        },
    };

    let session_token = match session_token_opt {
        None => {
            // Create new session if none exists
            let token = Uuid::new_v4();
            jar = jar.add(build_cookie(SESSION_COOKIE, &token.to_string(), false));
            token
        }
        Some(token) => token,
    };

    // CSRF protection for non-GET requests
    if method != Method::GET && csrf_token.is_none() {
        return Err(unauthorized("CSRF token required"));
    }

    if let Some(csrf_token) = csrf_token {
        if session_token != csrf_token {
            return Err(unauthorized("CSRF token mismatch"));
        }
    }

    // Create user object and set timezone
    let user = User {
        account_opt,
        session_token,
    };

    set_session_time_zone(tx, user.time_zone()).await;

    Ok((user, jar))
}

/// Sets the PostgreSQL session time zone to match the user preference.
///
/// # Parameters
/// - `tx`: Database transaction
/// - `time_zone`: Time zone identifier to set
pub async fn set_session_time_zone(tx: &mut PgConnection, time_zone: &str) {
    // Cannot pass $1 variables to this command, but the value should be safe
    // as it's validated against a list of known time zones when stored
    sqlx::query(&format!("SET TIME ZONE '{}'", time_zone))
        .execute(&mut *tx)
        .await
        .expect("set time zone");
}

//==================================================================================================
// Post and Content Management
//==================================================================================================

/// Retrieves a post and validates access permissions.
///
/// Ensures users can only view posts they are authorized to see based on
/// post status and user roles.
///
/// # Parameters
/// - `tx`: Database transaction
/// - `key`: Unique identifier for the post
/// - `user`: Current user making the request
///
/// # Returns
/// Either the requested post or an error response
pub async fn init_post(tx: &mut PgConnection, key: &str, user: &User) -> Result<Post, Response> {
    use PostStatus::*;

    match Post::select_by_key(tx, &key).await {
        None => return Err(not_found("post does not exist")),
        Some(post) => {
            // Check permission based on post status
            if [Reported, Rejected, Banned].contains(&post.status) && !user.admin() {
                return Err(unauthorized("post is reported, rejected, or banned"));
            }

            if post.status == Pending && !(post.author(user) || user.mod_or_admin()) {
                return Err(unauthorized("post is pending approval"));
            }

            Ok(post)
        }
    }
}

//==================================================================================================
// Templating and Rendering
//==================================================================================================

/// Renders a template with the given context.
///
/// In development mode, clears the template cache on each request.
///
/// # Parameters
/// - `state`: Application state containing the template engine
/// - `name`: Template name to render
/// - `ctx`: Context data to pass to the template
///
/// # Returns
/// The rendered template as a string
pub fn render(state: &AppState, name: &str, ctx: minijinja::value::Value) -> String {
    // In development mode, reload templates on each request
    if apabbs::dev() {
        let mut env = state.jinja.write().expect("write jinja env");
        env.clear_templates();
    }

    // Render the template with the provided context
    let env = state.jinja.read().expect("read jinja env");
    let tmpl = env.get_template(name).expect("get jinja template");
    tmpl.render(ctx).expect("render template")
}

//==================================================================================================
// Browser and Client Detection
//==================================================================================================

/// Information about the user's browser derived from the User-Agent header.
#[derive(serde::Serialize)]
pub struct UserAgent {
    /// Whether the client is on a Mac
    pub mac: bool,
    /// Whether the client is using a Chromium-based browser
    pub chromium: bool,
}

/// Analyzes the User-Agent header to extract browser information.
///
/// # Parameters
/// - `headers`: HTTP headers from the client request
///
/// # Returns
/// Optional UserAgent information if available
pub fn analyze_user_agent(headers: &HeaderMap) -> Option<UserAgent> {
    use axum::http::header::USER_AGENT;

    // Extract and parse User-Agent header
    let user_agent_str = match headers.get(USER_AGENT) {
        None => return None,
        Some(header) => match header.to_str() {
            Err(_) => return None,
            Ok(ua) => ua,
        },
    };

    // Determine browser characteristics
    Some(UserAgent {
        mac: user_agent_str.contains("Macintosh"),
        chromium: user_agent_str.contains("Chrome"),
    })
}

pub async fn generate_screenshot() {
    use headless_chrome::{Browser, LaunchOptions, types::Bounds};

    // Launch headless Chromium
    let browser = Browser::new(LaunchOptions {
        headless: true,
        path: None, // Auto-detect Chromium/Chrome; specify path if needed
        args: vec![
            std::ffi::OsStr::new("--enable-features=WebContentsForceDark"),
            std::ffi::OsStr::new("--hide-scrollbars"),
        ],
        ..Default::default()
    })
    .expect("launch browser");

    // Create a new tab
    let tab = browser.new_tab().expect("new tab");

    // Set custom viewport size
    tab.set_bounds(Bounds::Normal {
        width: Some(1600.0),
        height: Some(1080.0),
        left: None,
        top: None,
    })
    .expect("set bounds");

    // Navigate to your homepage
    let url = if apabbs::dev() {
        "http://localhost"
    } else {
        &format!("https://{}", apabbs::host())
    };
    tab.navigate_to(url).expect("navigate to homepage");
    tab.wait_until_navigated().expect("wait until navigated");

    // Capture a full-page screenshot
    let screenshot = tab
        .capture_screenshot(
            headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Webp,
            Some(80), // Quality (0-100)
            None,     // No clipping region
            true,     // Capture full page
        )
        .expect("capture screenshot");

    // Save the screenshot
    std::fs::write("pub/screenshot.webp", screenshot).expect("write screenshot");
    println!("Screenshot saved as pub/screenshot.webp");
}
