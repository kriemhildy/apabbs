//-------------------------------------------------------------------------------------------------
// router helper functions and macros
//-------------------------------------------------------------------------------------------------

use super::{
    Account, AppState, CookieJar, Credentials, HeaderMap, IntoResponse, Method, Post, PostStatus,
    Response, StatusCode, User, Uuid, ban,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use sqlx::PgConnection;

pub const X_REAL_IP: &'static str = "X-Real-IP";
pub const ACCOUNT_COOKIE: &'static str = "account";
pub const SESSION_COOKIE: &'static str = "session";
pub const NOTICE_COOKIE: &'static str = "notice";

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

pub fn bad_request(msg: &str) -> Response {
    http_status(StatusCode::BAD_REQUEST, msg)
}

pub fn unauthorized(msg: &str) -> Response {
    http_status(StatusCode::UNAUTHORIZED, msg)
}

pub fn forbidden(msg: &str) -> Response {
    http_status(StatusCode::FORBIDDEN, msg)
}

pub fn not_found(msg: &str) -> Response {
    http_status(StatusCode::NOT_FOUND, msg)
}

pub fn internal_server_error(msg: &str) -> Response {
    http_status(StatusCode::INTERNAL_SERVER_ERROR, msg)
}

pub fn ban_message(expires_at_str: &str) -> Response {
    let msg = format!("Banned until {expires_at_str}");
    forbidden(&msg)
}

pub fn ip_hash(headers: &HeaderMap) -> String {
    let ip = headers
        .get(X_REAL_IP)
        .expect("get IP header")
        .to_str()
        .expect("convert header to str");
    sha256::digest(apabbs::secret_key() + ip)
}

pub fn is_fetch_request(headers: &HeaderMap) -> bool {
    headers
        .get("Sec-Fetch-Mode")
        .map(|v| v.to_str().expect("convert header to str"))
        .is_some_and(|v| v != "navigate")
}

pub fn build_cookie(name: &str, value: &str, permanent: bool) -> Cookie<'static> {
    let mut cookie = Cookie::build((name.to_owned(), value.to_owned()))
        .secure(!apabbs::dev())
        .http_only(true)
        .path("/")
        .same_site(SameSite::Lax) // Strict prevents linking to our site (yes really)
        .build();
    if permanent {
        cookie.make_permanent()
    }
    cookie
}

pub fn removal_cookie(name: &str) -> Cookie<'static> {
    Cookie::build(name.to_owned()).path("/").build()
}

pub fn render(state: &AppState, name: &str, ctx: minijinja::value::Value) -> String {
    if apabbs::dev() {
        let mut env = state.jinja.write().expect("write jinja env");
        env.clear_templates();
    }
    let env = state.jinja.read().expect("read jinja env");
    let tmpl = env.get_template(name).expect("get jinja template");
    tmpl.render(ctx).expect("render template")
}

pub async fn set_session_time_zone(tx: &mut PgConnection, time_zone: &str) {
    // cannot pass $1 variables to this command, but the value should be safe
    sqlx::query(&format!("SET TIME ZONE '{}'", time_zone))
        .execute(&mut *tx)
        .await
        .expect("set time zone");
}

pub async fn init_user(
    mut jar: CookieJar,
    tx: &mut PgConnection,
    method: Method,
    csrf_token: Option<Uuid>,
) -> Result<(User, CookieJar), Response> {
    let account_opt = match jar.get(ACCOUNT_COOKIE) {
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
    let session_token_opt = match jar.get(SESSION_COOKIE) {
        None => None,
        Some(cookie) => match Uuid::try_parse(cookie.value()) {
            Err(_) => None,
            Ok(uuid) => Some(uuid),
        },
    };
    let session_token = match session_token_opt {
        None => {
            let token = Uuid::new_v4();
            jar = jar.add(build_cookie(SESSION_COOKIE, &token.to_string(), false));
            token
        }
        Some(token) => token,
    };
    if method != Method::GET && csrf_token.is_none() {
        return Err(unauthorized("CSRF token required"));
    }
    if let Some(csrf_token) = csrf_token {
        if session_token != csrf_token {
            return Err(unauthorized("CSRF token mismatch"));
        }
    }
    let user = User {
        account_opt,
        session_token,
    };
    set_session_time_zone(tx, user.time_zone()).await;
    Ok((user, jar))
}

pub async fn check_for_ban(
    tx: &mut PgConnection,
    ip_hash: &str,
    banned_account_id_opt: Option<i32>,
    admin_account_id_opt: Option<i32>,
) -> Option<Response> {
    if let Some(expires_at_str) = ban::exists(tx, ip_hash, banned_account_id_opt).await {
        return Some(ban_message(&expires_at_str));
    }
    if ban::flooding(tx, ip_hash).await {
        let expires_at_str =
            ban::insert(tx, ip_hash, banned_account_id_opt, admin_account_id_opt).await;
        ban::prune(tx, ip_hash).await;
        return Some(ban_message(&expires_at_str));
    }
    None
}

pub fn add_notice_cookie(jar: CookieJar, notice: &str) -> CookieJar {
    jar.add(build_cookie(NOTICE_COOKIE, notice, false))
}

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

pub fn remove_account_cookie(jar: CookieJar) -> CookieJar {
    jar.remove(removal_cookie(ACCOUNT_COOKIE))
}

pub async fn init_post(tx: &mut PgConnection, key: &str, user: &User) -> Result<Post, Response> {
    use PostStatus::*;
    match Post::select_by_key(tx, &key).await {
        None => return Err(not_found("post does not exist")),
        Some(post) => {
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

#[derive(serde::Serialize)]
pub struct UserAgent {
    pub mac: bool,
    pub chromium: bool,
}

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
