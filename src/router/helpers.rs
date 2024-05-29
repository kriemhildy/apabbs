///////////////////////////////////////////////////////////////////////////////////////////////////
// router helper functions and macros
///////////////////////////////////////////////////////////////////////////////////////////////////

use super::{HeaderMap, IntoResponse, Response};
use crate::{Arc, Environment, RwLock};
use axum::http::StatusCode;
use axum_extra::extract::cookie::{Cookie, SameSite};

pub const OLD_USER_COOKIE: &'static str = "user"; // temporary for migration period

pub fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, format!("400 Bad Request\n\n{msg}")).into_response()
}

pub fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "401 Unauthorized").into_response()
}

pub fn forbidden(msg: &str) -> Response {
    (StatusCode::FORBIDDEN, format!("403 Forbidden\n\n{msg}")).into_response()
}

pub fn ip_hash(headers: &HeaderMap) -> String {
    let ip = headers
        .get("X-Real-IP")
        .expect("get IP header")
        .to_str()
        .expect("convert header to str");
    let ip_salt = std::env::var("IP_SALT").expect("read IP_SALT env");
    if ip_salt.len() < 16 {
        panic!("IP_SALT env must be at least 16 chars");
    }
    sha256::digest(ip_salt + ip)
}

pub fn site_name() -> String {
    std::env::var("SITE_NAME").expect("read SITE_NAME env")
}

pub fn dev() -> bool {
    std::env::var("DEV").is_ok_and(|v| v == "1")
}

pub fn build_cookie(name: &str, value: &str) -> Cookie<'static> {
    Cookie::build((name.to_owned(), value.to_owned()))
        .secure(!dev())
        .http_only(true)
        .same_site(SameSite::Lax) // Strict prevents linking to our site (yes really)
        .permanent()
        .build()
}

pub fn render(
    lock: Arc<RwLock<Environment<'_>>>,
    name: &str,
    ctx: minijinja::value::Value,
) -> String {
    if dev() {
        let mut env = lock.write().expect("write jinja env");
        env.clear_templates();
    }
    let env = lock.read().expect("read jinja env");
    let tmpl = env.get_template(name).expect("get jinja template");
    tmpl.render(ctx).expect("render template")
}

// temporary for migration period
macro_rules! migrate_user_cookie {
    ($jar:expr) => {{
        match $jar.get(OLD_USER_COOKIE) {
            Some(cookie) => {
                let cookie = build_cookie(ACCOUNT_COOKIE, cookie.value());
                $jar = $jar.add(cookie);
                $jar = $jar.remove(OLD_USER_COOKIE);
            }
            None => (),
        };
    }};
}
pub(super) use migrate_user_cookie;

macro_rules! user {
    ($jar:expr, $tx:expr) => {{
        let account = match $jar.get(ACCOUNT_COOKIE) {
            Some(cookie) => match Account::select_by_token(&mut $tx, cookie.value()).await {
                Some(account) => Some(account),
                None => return bad_request(ACCOUNT_NOT_FOUND),
            },
            None => None,
        };
        let anon_token = match $jar.get(ANON_COOKIE) {
            Some(cookie) => match uuid::Uuid::try_parse(cookie.value()) {
                Ok(uuid) => uuid.hyphenated().to_string(),
                Err(_) => return bad_request("invalid anon UUID"),
            },
            None => uuid::Uuid::new_v4().hyphenated().to_string(),
        };
        User {
            account,
            anon_token,
        }
    }};
}
pub(super) use user;

macro_rules! check_for_ban {
    ($tx:expr, $ip_hash:expr) => {
        if ban::exists(&mut $tx, $ip_hash).await {
            return forbidden("ip was auto-banned due to flooding");
        }
        if ban::flooding(&mut $tx, $ip_hash).await {
            ban::insert(&mut $tx, $ip_hash).await;
            ban::prune(&mut $tx, $ip_hash).await;
            $tx.commit().await.expect(COMMIT);
            return forbidden("ip is flooding and has been auto-banned");
        }
    };
}
pub(super) use check_for_ban;

macro_rules! require_admin {
    ($jar:expr, $tx:expr) => {
        let user = user!($jar, $tx);
        if !user.admin() {
            return unauthorized();
        }
    };
}
pub(super) use require_admin;
