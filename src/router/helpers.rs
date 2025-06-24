//! Router helper functions and utilities.
//!
//! This module provides utilities for HTTP request/response handling, cookie management,
//! user authentication, security checks, template rendering, session management, and browser
//! detection. It also includes functions for managing posts and validating access permissions.

use super::*;
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::Serialize;
use sqlx::PgConnection;

//==================================================================================================
// Constants
//==================================================================================================

/// HTTP header name for the client's real IP address.
pub const X_REAL_IP: &str = "X-Real-IP";
/// HTTP header name for fetch mode.
pub const SEC_FETCH_MODE: &str = "Sec-Fetch-Mode";
/// Cookie name for the user's account authentication token.
pub const ACCOUNT_COOKIE: &str = "account";
/// Cookie name for the user's session token.
pub const SESSION_COOKIE: &str = "session";
/// Cookie name for flash notice messages.
pub const NOTICE_COOKIE: &str = "notice";

//==================================================================================================
// Security Utilities
//==================================================================================================

/// Generate a hash of the client's IP address.
pub fn ip_hash(headers: &HeaderMap) -> String {
    let ip = headers
        .get(X_REAL_IP)
        .expect("has X-Real-IP")
        .to_str()
        .expect("is utf-8");
    sha256::digest(crate::secret_key() + ip)
}

/// Check if a request is an AJAX/Fetch request.
pub fn is_fetch_request(headers: &HeaderMap) -> bool {
    headers
        .get(SEC_FETCH_MODE)
        .map(|v| v.to_str().expect("is utf-8"))
        .is_some_and(|v| v != "navigate")
}

/// Check if a user is banned or rate-limited.
pub async fn check_for_ban(
    tx: &mut PgConnection,
    ip_hash: &str,
    banned_account_id: Option<i32>,
    admin_account_id: Option<i32>,
) -> Option<String> {
    if let Some(expires_at_str) = ban::exists(tx, ip_hash, banned_account_id).await {
        return Some(expires_at_str);
    }
    if ban::flooding(tx, ip_hash).await {
        let expires_at_str = ban::insert(tx, ip_hash, banned_account_id, admin_account_id).await;
        ban::prune(tx, ip_hash).await;
        return Some(expires_at_str);
    }
    None
}

//==================================================================================================
// Cookie Management
//==================================================================================================

/// Create a cookie with secure, HTTP-only, and SameSite settings.
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

/// Create a cookie for removal.
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
pub async fn init_user(
    mut jar: CookieJar,
    tx: &mut PgConnection,
    method: Method,
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
    let user = User {
        account,
        session_token,
    };
    set_session_time_zone(tx, user.time_zone()).await;
    Ok((user, jar))
}

/// Set the PostgreSQL session time zone.
pub async fn set_session_time_zone(tx: &mut PgConnection, time_zone: &str) {
    sqlx::query(&format!("SET TIME ZONE '{}'", time_zone))
        .execute(&mut *tx)
        .await
        .expect("query succeeds");
}

//==================================================================================================
// Post and Content Management
//==================================================================================================

/// Retrieve a post and validate access permissions.
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

/// Render a template with the given context.
pub fn render(state: &AppState, name: &str, ctx: minijinja::value::Value) -> String {
    if crate::dev() {
        let mut env = state.jinja.write().expect("gets write lock");
        env.clear_templates();
    }
    let env = state.jinja.read().expect("gets read lock");
    let tmpl = env.get_template(name).expect("gets template");
    tmpl.render(ctx).expect("renders")
}

//==================================================================================================
// Browser and Client Detection
//==================================================================================================

/// Information about the user's browser.
#[derive(Serialize)]
pub struct UserAgent {
    pub mac: bool,
    pub chromium: bool,
}

/// Analyze the User-Agent header.
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

/// Generate a UTC timestamp string.
pub async fn utc_hour_timestamp(tx: &mut PgConnection) -> String {
    sqlx::query_scalar("SELECT to_char(current_timestamp AT TIME ZONE 'UTC', $1)")
        .bind(crate::POSTGRES_UTC_HOUR)
        .fetch_one(tx)
        .await
        .expect("query succeeds")
}
