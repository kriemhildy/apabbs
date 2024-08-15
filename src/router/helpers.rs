///////////////////////////////////////////////////////////////////////////////////////////////////
// router helper functions and macros
///////////////////////////////////////////////////////////////////////////////////////////////////

use super::{HeaderMap, IntoResponse, Response};
use crate::{Arc, Environment, RwLock};
use axum::http::StatusCode;
use axum_extra::extract::cookie::{Cookie, SameSite};

pub const X_REAL_IP: &'static str = "X-Real-IP";

pub fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, format!("400 Bad Request\n\n{msg}")).into_response()
}

pub fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "401 Unauthorized").into_response()
}

pub fn forbidden(msg: &str) -> Response {
    (StatusCode::FORBIDDEN, format!("403 Forbidden\n\n{msg}")).into_response()
}

pub fn ban_message(expires_at: &str) -> Response {
    let msg = format!("IP has been auto-banned due to flooding until {expires_at}");
    forbidden(&msg)
}

pub fn ip_hash(headers: &HeaderMap) -> String {
    let ip = headers
        .get(X_REAL_IP)
        .expect("get IP header")
        .to_str()
        .expect("convert header to str");
    let secret_key = std::env::var("SECRET_KEY").expect("read SECRET_KEY env");
    sha256::digest(secret_key + ip)
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
            Some(cookie) => match Uuid::try_parse(cookie.value()) {
                Ok(uuid) => uuid.hyphenated().to_string(),
                Err(_) => return bad_request("invalid anon UUID"),
            },
            None => Uuid::new_v4().hyphenated().to_string(),
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
        match ban::exists(&mut $tx, $ip_hash).await {
            Some(expires_at) => return ban_message(&expires_at),
            None => (),
        };
        if ban::flooding(&mut $tx, $ip_hash).await {
            let expires_at = ban::insert(&mut $tx, $ip_hash).await;
            ban::prune(&mut $tx, $ip_hash).await;
            $tx.commit().await.expect(COMMIT);
            return ban_message(&expires_at);
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
