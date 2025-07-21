//! Router helper functions and utilities.
//!
//! This module provides utilities for HTTP request/response handling, cookie management,
//! user authentication, security checks, template rendering, session management, and browser
//! detection. It also includes functions for managing posts and validating access permissions.

use super::{ROOT, errors::ResponseError};
use crate::{
    ban::{self, Ban},
    post::{Post, PostStatus},
    user::{Account, Credentials, User, UserAgent},
    utils::set_session_time_zone,
};
use axum::http::{HeaderMap, Method};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use sqlx::PgConnection;
use std::error::Error;
use uuid::Uuid;

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
pub fn ip_hash(headers: &HeaderMap) -> Result<String, ResponseError> {
    let ip = headers
        .get(X_REAL_IP)
        .ok_or_else(|| ResponseError::BadRequest("Missing X-Real-IP header".to_string()))?
        .to_str()
        .map_err(|_| ResponseError::BadRequest("X-Real-IP is not UTF-8".to_string()))?;
    Ok(sha256::digest(crate::secret_key() + ip))
}

/// Check if an IP address is flooding and ban if necessary.
pub async fn ban_if_flooding(
    tx: &mut PgConnection,
    ip_hash: &str,
    account_id: Option<i32>,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    if ban::flooding(tx, ip_hash).await? {
        let ban = Ban {
            ip_hash: ip_hash.to_string(),
            banned_account_id: account_id,
            ..Ban::default()
        };
        let expires_at = ban.insert(tx).await?;
        ban::prune(tx, ip_hash).await?;
        return Ok(Some(expires_at));
    }
    Ok(None)
}

//==================================================================================================
// Cookie Management
//==================================================================================================

/// Create a cookie with secure, HTTP-only, and SameSite settings.
pub fn build_cookie(name: &str, value: &str, permanent: bool) -> Cookie<'static> {
    let mut cookie = Cookie::build((name.to_string(), value.to_string()))
        .secure(!crate::dev())
        .http_only(true)
        .path(ROOT)
        .same_site(SameSite::Lax)
        .build();
    if permanent {
        cookie.make_permanent()
    }
    cookie
}

/// Create a cookie for removal by setting its expiration in the past.
pub fn removal_cookie(name: &str) -> Cookie<'static> {
    Cookie::build(name.to_string()).path(ROOT).build()
}

/// Add a notice cookie for flash messages to the cookie jar.
pub fn add_notice_cookie(jar: CookieJar, notice: &str) -> CookieJar {
    jar.add(build_cookie(NOTICE_COOKIE, notice, false))
}

/// Remove the notice cookie from the jar and extract its value, if present.
pub fn remove_notice_cookie(mut jar: CookieJar) -> (CookieJar, Option<String>) {
    let notice = match jar.get(NOTICE_COOKIE) {
        Some(cookie) => {
            let value = cookie.value().to_string();
            jar = jar.remove(removal_cookie(NOTICE_COOKIE));
            Some(value)
        }
        None => None,
    };
    (jar, notice)
}

/// Add the account token cookie for authentication to the cookie jar.
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
pub fn remove_account_cookie(jar: CookieJar) -> CookieJar {
    jar.remove(removal_cookie(ACCOUNT_COOKIE))
}

//==================================================================================================
// User and Session Management
//==================================================================================================

/// Initialize a user session from cookies or create a new session if none exists.
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
    if ![Method::GET, Method::HEAD].contains(&method) && csrf_token.is_none() {
        return Err(ResponseError::Unauthorized(
            "CSRF token required for state-changing requests".to_string(),
        ));
    }
    if let Some(csrf_token) = csrf_token {
        if session_token != csrf_token {
            return Err(ResponseError::Unauthorized(
                "CSRF token mismatch: possible forgery attempt".to_string(),
            ));
        }
    }
    let ip_hash = ip_hash(headers)?;
    let agent = analyze_user_agent(headers);
    let mut user = User {
        account,
        session_token,
        ip_hash,
        agent,
        ..User::default()
    };
    set_session_time_zone(tx, user.time_zone()).await?;
    user.ban_expires_at =
        Ban::exists(tx, &user.ip_hash, user.account.as_ref().map(|a| a.id)).await?;
    Ok((user, jar))
}

//==================================================================================================
// Post and Content Management
//==================================================================================================

/// Retrieve a post by key and validate access permissions for the current user.
pub async fn init_post(
    tx: &mut PgConnection,
    key: &str,
    user: &User,
) -> Result<Post, ResponseError> {
    match Post::select_by_key(tx, key).await? {
        None => Err(ResponseError::NotFound("Post does not exist".to_string())),
        Some(post) => {
            if [
                PostStatus::Reported,
                PostStatus::Rejected,
                PostStatus::Banned,
            ]
            .contains(&post.status)
                && !user.admin()
            {
                return Err(ResponseError::Unauthorized(
                    "Post is reported, rejected, or banned".to_string(),
                ));
            }
            if post.status == PostStatus::Pending && !(post.author(user) || user.mod_or_admin()) {
                return Err(ResponseError::Unauthorized(
                    "Post is pending approval".to_string(),
                ));
            }
            Ok(post)
        }
    }
}

//===================================================================================================
// Request and Response Utilities
//==================================================================================================

/// Determine if a request is an AJAX/fetch request (not a navigation).
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
