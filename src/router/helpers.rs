///////////////////////////////////////////////////////////////////////////////////////////////////
// router helper functions and macros
///////////////////////////////////////////////////////////////////////////////////////////////////

use super::{
    ban, init, Account, AppState, CookieJar, HeaderMap, IntoResponse, Post, PostMessage, Response,
    User, Uuid, ACCOUNT_COOKIE, ACCOUNT_NOT_FOUND, ANON_COOKIE, CSRF_COOKIE,
};
use axum::http::StatusCode;
use axum_extra::extract::cookie::{Cookie, SameSite};
use sqlx::PgConnection;

pub const X_REAL_IP: &'static str = "X-Real-IP";

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
    let msg = format!("IP has been banned until {expires_at_str}");
    forbidden(&msg)
}

pub fn ip_hash(headers: &HeaderMap) -> String {
    let ip = headers
        .get(X_REAL_IP)
        .expect("get IP header")
        .to_str()
        .expect("convert header to str");
    sha256::digest(init::secret_key() + ip)
}

pub fn is_fetch_request(headers: &HeaderMap) -> bool {
    headers
        .get("Sec-Fetch-Mode")
        .map(|v| v.to_str().expect("convert header to str"))
        .is_some_and(|v| v != "navigate")
}

pub fn build_cookie(name: &str, value: &str, permanent: bool) -> Cookie<'static> {
    let mut cookie = Cookie::build((name.to_owned(), value.to_owned()))
        .secure(!init::dev())
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
    if init::dev() {
        let mut env = state.jinja.write().expect("write jinja env");
        env.clear_templates();
    }
    let env = state.jinja.read().expect("read jinja env");
    let tmpl = env.get_template(name).expect("get jinja template");
    tmpl.render(ctx).expect("render template")
}

pub fn send_post_to_web_socket(state: &AppState, post: Post) {
    for admin in [true, false] {
        let html = render(
            state,
            "post.jinja",
            minijinja::context!(post, admin, csrf_token => "<CSRF_TOKEN>"),
        );
        let msg = PostMessage {
            post: post.clone(),
            html,
            admin,
        };
        state.sender.send(msg).ok();
    }
}

pub async fn set_session_time_zone(tx: &mut PgConnection, time_zone: &str) {
    // cannot pass $1 variables to this command, but the value should be safe
    sqlx::query(&format!("SET TIME ZONE '{}'", time_zone))
        .execute(&mut *tx)
        .await
        .expect("set time zone");
}

pub fn ensure_csrf_token(mut jar: CookieJar) -> Result<(Uuid, CookieJar), Response> {
    let csrf_token = match jar.get(CSRF_COOKIE) {
        Some(cookie) => match Uuid::try_parse(cookie.value()) {
            Ok(uuid) => uuid,
            Err(_) => return Err(bad_request("invalid CSRF token uuid")),
        },
        None => {
            let csrf_token = Uuid::new_v4();
            let cookie = build_cookie(CSRF_COOKIE, &csrf_token.to_string(), false);
            jar = jar.add(cookie);
            csrf_token
        }
    };
    Ok((csrf_token, jar))
}

pub async fn init_user(
    mut jar: CookieJar,
    tx: &mut PgConnection,
) -> Result<(User, CookieJar), Response> {
    let account = match jar.get(ACCOUNT_COOKIE) {
        Some(cookie) => {
            let token = match Uuid::try_parse(cookie.value()) {
                Ok(uuid) => uuid,
                Err(_) => return Err(bad_request("invalid account token uuid")),
            };
            match Account::select_by_token(tx, &token).await {
                Some(account) => Some(account),
                None => return Err(bad_request(ACCOUNT_NOT_FOUND)),
            }
        }
        None => None,
    };
    let anon_token = match jar.get(ANON_COOKIE) {
        Some(cookie) => match Uuid::try_parse(cookie.value()) {
            Ok(uuid) => uuid,
            Err(_) => return Err(bad_request("invalid anon token uuid")),
        },
        None => {
            let anon_token = Uuid::new_v4();
            let cookie = build_cookie(ANON_COOKIE, &anon_token.to_string(), false);
            jar = jar.add(cookie);
            anon_token
        }
    };
    let (csrf_token, jar) = match ensure_csrf_token(jar) {
        Ok((csrf_token, jar)) => (csrf_token, jar),
        Err(response) => return Err(response),
    };
    let user = User {
        account,
        anon_token,
        csrf_token,
    };
    set_session_time_zone(tx, user.time_zone()).await;
    Ok((user, jar))
}

pub async fn check_for_ban(tx: &mut PgConnection, ip_hash: &str) -> Option<Response> {
    if let Some(expires_at_str) = ban::exists(tx, ip_hash).await {
        return Some(ban_message(&expires_at_str));
    }
    if ban::flooding(tx, ip_hash).await {
        let expires_at_str = ban::insert(tx, ip_hash).await;
        ban::prune(tx, ip_hash).await;
        return Some(ban_message(&expires_at_str));
    }
    None
}
