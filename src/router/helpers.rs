///////////////////////////////////////////////////////////////////////////////////////////////////
// router helper functions and macros
///////////////////////////////////////////////////////////////////////////////////////////////////

use super::{AppState, HeaderMap, IntoResponse, Post, PostMessage, Response, UPLOADS_DIR};
use axum::http::StatusCode;
use axum_extra::extract::cookie::{Cookie, SameSite};
use sqlx::PgConnection;
use std::path::PathBuf;

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
    let secret_key = std::env::var("SECRET_KEY").expect("read SECRET_KEY env");
    sha256::digest(secret_key + ip)
}

pub fn is_fetch_request(headers: &HeaderMap) -> bool {
    headers
        .get("Sec-Fetch-Mode")
        .map(|v| v.to_str().expect("convert header to str"))
        .is_some_and(|v| v != "navigate")
}

pub fn site_name() -> String {
    format!(
        "{}{}",
        if dev() { "[dev] " } else { "" },
        std::env::var("SITE_NAME").expect("read SITE_NAME env")
    )
}

pub fn dev() -> bool {
    std::env::var("DEV").is_ok_and(|v| v == "1")
}

pub fn per_page() -> usize {
    match std::env::var("PER_PAGE") {
        Ok(per_page) => per_page.parse().expect("parse PER_PAGE env"),
        Err(_) => 1000,
    }
}

pub fn build_cookie(name: &str, value: &str) -> Cookie<'static> {
    Cookie::build((name.to_owned(), value.to_owned()))
        .secure(!dev())
        .http_only(true)
        .same_site(SameSite::Lax) // Strict prevents linking to our site (yes really)
        .permanent()
        .build()
}

pub fn render(state: &AppState, name: &str, ctx: minijinja::value::Value) -> String {
    if dev() {
        let mut env = state.jinja.write().expect("write jinja env");
        env.clear_templates();
    }
    let env = state.jinja.read().expect("read jinja env");
    let tmpl = env.get_template(name).expect("get jinja template");
    tmpl.render(ctx).expect("render template")
}

pub async fn decrypt_media_file(encrypted_file_path: &PathBuf) -> Vec<u8> {
    let output = tokio::process::Command::new("gpg")
        .args(["--batch", "--decrypt", "--passphrase-file", "gpg.key"])
        .arg(&encrypted_file_path)
        .output()
        .await
        .expect("decrypt media file");
    output.stdout
}

pub fn send_post_to_web_socket(state: &AppState, post: Post) {
    for admin in [true, false] {
        let html = render(state, "post.jinja", minijinja::context!(post, admin));
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

macro_rules! user {
    ($jar:expr, $tx:expr) => {{
        let account = match $jar.get(ACCOUNT_COOKIE) {
            Some(cookie) => {
                let token = match Uuid::try_parse(cookie.value()) {
                    Ok(uuid) => uuid,
                    Err(_) => return bad_request("invalid account token"),
                };
                match Account::select_by_token(&mut $tx, &token).await {
                    Some(account) => Some(account),
                    None => return bad_request(ACCOUNT_NOT_FOUND),
                }
            }
            None => None,
        };
        let anon_token = match $jar.get(ANON_COOKIE) {
            Some(cookie) => match Uuid::try_parse(cookie.value()) {
                Ok(uuid) => uuid,
                Err(_) => return bad_request("invalid anon token"),
            },
            None => Uuid::new_v4(),
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
        if let Some(expires_at_str) = ban::exists(&mut $tx, $ip_hash).await {
            return ban_message(&expires_at_str);
        }
        if ban::flooding(&mut $tx, $ip_hash).await {
            let expires_at_str = ban::insert(&mut $tx, $ip_hash).await;
            ban::prune(&mut $tx, $ip_hash).await;
            $tx.commit().await.expect(COMMIT);
            return ban_message(&expires_at_str);
        }
    };
}
pub(super) use check_for_ban;

macro_rules! require_admin {
    ($jar:expr, $tx:expr) => {
        let user = user!($jar, $tx);
        if !user.admin() {
            return unauthorized("not an admin");
        }
    };
}
pub(super) use require_admin;
