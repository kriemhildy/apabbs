use std::sync::{Arc, RwLock};

#[derive(Clone)]
struct AppState {
    db: sqlx::PgPool,
    jinja: Arc<RwLock<minijinja::Environment<'static>>>,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let state = {
        let db = {
            let url = std::env::var("DATABASE_URL").expect("read DATABASE_URL env");
            sqlx::PgPool::connect(&url).await.expect("connect postgres")
        };
        let jinja = {
            let mut env = minijinja::Environment::new();
            env.set_loader(minijinja::path_loader("templates"));
            env.add_filter("repeat", str::repeat);
            Arc::new(RwLock::new(env))
        };
        AppState { db, jinja }
    };
    let router = router(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:7878")
        .await
        .expect("listen on 7878");
    axum::serve(listener, router).await.expect("serve axum")
}

fn router(state: AppState) -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/", get(index))
        .route("/submit-post", post(submit_post))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/new-hash", post(new_hash))
        .route("/hide-rejected-post", post(hide_rejected_post))
        .route("/admin/update-post-status", post(update_post_status))
        .layer(trace())
        .with_state(state)
}

use tower_http::{
    classify::{ServerErrorsAsFailures, SharedClassifier},
    trace::TraceLayer,
};

fn trace() -> TraceLayer<SharedClassifier<ServerErrorsAsFailures>> {
    use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse};
    use tracing::Level;
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();
    TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::DEBUG))
        .on_response(DefaultOnResponse::new().level(Level::DEBUG))
}

// individual http request handlers follow

fn dev() -> bool {
    std::env::var("DEV").is_ok_and(|v| v == "1")
}

fn render(
    lock: Arc<RwLock<minijinja::Environment<'_>>>,
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

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, format!("400 Bad Request\n\n{msg}")).into_response()
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "401 Unauthorized").into_response()
}

fn forbidden(msg: &str) -> Response {
    (StatusCode::FORBIDDEN, format!("403 Forbidden\n\n{msg}")).into_response()
}

use axum::http::header::HeaderMap;

fn ip(headers: &HeaderMap) -> &str {
    headers
        .get("X-Real-IP")
        .expect("gets header")
        .to_str()
        .expect("converts header to str")
}

const ANON_COOKIE: &'static str = "anon";
const USER_COOKIE: &'static str = "user";
const COOKIE_NOT_FOUND: &'static str = "cookie not found";
const USER_NOT_FOUND: &'static str = "user not found";
const BEGIN: &'static str = "begin transaction";
const COMMIT: &'static str = "commit transaction";
const ROOT: &'static str = "/";

fn build_cookie(name: &str, value: &str) -> Cookie<'static> {
    Cookie::build((name.to_owned(), value.to_owned()))
        .secure(!dev())
        .http_only(true)
        .same_site(SameSite::Lax)
        .permanent()
        .build()
}

mod user;
use user::{Credentials, User};
mod post;
use post::{Post, PostHiding, PostModeration, PostSubmission};
mod ban;
mod validation;

use axum::{extract::State, response::Html};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

macro_rules! user {
    ($jar:expr, $tx:expr) => {
        match $jar.get(USER_COOKIE) {
            Some(cookie) => match User::select_by_token(&mut $tx, cookie.value()).await {
                Some(user) => Some(user),
                None => return bad_request(USER_NOT_FOUND),
            },
            None => None,
        }
    };
}

macro_rules! anon_uuid {
    ($jar:expr) => {
        match $jar.get(ANON_COOKIE) {
            Some(cookie) => match uuid::Uuid::try_parse(cookie.value()) {
                Ok(uuid) => uuid.hyphenated().to_string(),
                Err(_) => return bad_request("invalid anon UUID"),
            },
            None => {
                let anon_uuid = uuid::Uuid::new_v4().hyphenated().to_string();
                let cookie = build_cookie(ANON_COOKIE, &anon_uuid);
                $jar = $jar.add(cookie);
                anon_uuid
            }
        }
    };
}

macro_rules! check_for_ban {
    ($tx:expr, $ip:expr, $module:ident) => {
        if ban::exists(&mut $tx, $ip).await {
            return forbidden(&format!("ip {} was auto-banned due to flooding", $ip));
        }
        if $module::flooding(&mut $tx, $ip).await {
            ban::insert(&mut $tx, $ip).await;
            ban::prune(&mut $tx, $ip).await;
            $tx.commit().await.expect(COMMIT);
            return forbidden(&format!("ip {} is flooding and has been auto-banned", $ip));
        }
    };
}

async fn index(State(state): State<AppState>, mut jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    let anon_uuid = anon_uuid!(jar);
    let posts = match &user {
        Some(user) => match user.admin {
            true => Post::select_latest_as_admin(&mut tx, user).await,
            false => Post::select_latest_as_user(&mut tx, user).await,
        },
        None => Post::select_latest_as_anon(&mut tx, &anon_uuid).await,
    };
    tx.commit().await.expect(COMMIT);
    let anon_hash = post::anon_hash(&anon_uuid); // for display
    let html = Html(render(
        state.jinja,
        "index.jinja",
        minijinja::context!(user, posts, anon_hash),
    ));
    (jar, html).into_response()
}

use axum::{response::Redirect, Form};

async fn submit_post(
    State(state): State<AppState>,
    mut jar: CookieJar,
    headers: HeaderMap,
    Form(post_submission): Form<PostSubmission>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    let anon_uuid = anon_uuid!(jar);
    let ip = ip(&headers);
    check_for_ban!(tx, ip, post);
    let _post_id = match user {
        Some(user) => post_submission.insert_as_user(&mut tx, user, ip).await,
        None => {
            post_submission
                .insert_as_anon(&mut tx, &anon_uuid, ip)
                .await
        }
    };
    tx.commit().await.expect(COMMIT);
    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

async fn login(
    State(state): State<AppState>,
    mut jar: CookieJar,
    headers: HeaderMap,
    Form(credentials): Form<Credentials>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    if credentials.username_exists(&mut tx).await {
        match credentials.authenticate(&mut tx).await {
            Some(user) => {
                let cookie = build_cookie(USER_COOKIE, &user.token);
                jar = jar.add(cookie);
            }
            None => return bad_request("username exists but password is wrong"),
        }
    } else {
        if let Err(errors) = credentials.validate() {
            let msg = errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<String>>()
                .join("\n");
            return bad_request(&msg);
        }
        match jar.get(USER_COOKIE) {
            Some(_cookie) => return bad_request("log out before registering"),
            None => {
                let ip = ip(&headers);
                check_for_ban!(tx, ip, user);
                let user = credentials.register(&mut tx, ip).await;
                let cookie = build_cookie(USER_COOKIE, &user.token);
                jar = jar.add(cookie);
            }
        }
    }
    tx.commit().await.expect(COMMIT);
    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

async fn logout(State(state): State<AppState>, mut jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    match jar.get(USER_COOKIE) {
        Some(cookie) => match User::select_by_token(&mut tx, cookie.value()).await {
            Some(_user) => jar = jar.remove(USER_COOKIE),
            None => return bad_request(USER_NOT_FOUND),
        },
        None => return bad_request(COOKIE_NOT_FOUND),
    };
    tx.commit().await.expect(COMMIT);
    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

async fn new_hash(mut jar: CookieJar) -> Response {
    jar = jar.remove(ANON_COOKIE);
    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

async fn hide_rejected_post(
    State(state): State<AppState>,
    mut jar: CookieJar,
    Form(post_hiding): Form<PostHiding>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    let anon_uuid = anon_uuid!(jar);
    let post = match Post::select(&mut tx, post_hiding.id).await {
        Some(post) => post,
        None => return bad_request("post does not exist"),
    };
    let wrote_post = match user {
        Some(user) => post.user_id.is_some_and(|id| id == user.id),
        None => post.anon_uuid.is_some_and(|uuid| uuid == anon_uuid),
    };
    if !wrote_post {
        return bad_request("not post author");
    }
    if post.status != "rejected" {
        return bad_request("post is not rejected");
    }
    post_hiding.hide_post(&mut tx).await;
    tx.commit().await.expect(COMMIT);
    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

// admin handlers follow

macro_rules! require_admin {
    ($jar:expr, $tx:expr) => {
        let user = user!($jar, $tx);
        if !user.is_some_and(|u| u.admin) {
            return unauthorized();
        }
    };
}

async fn update_post_status(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(post_moderation): Form<PostModeration>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    require_admin!(jar, tx);
    post_moderation.update_status(&mut tx).await;
    tx.commit().await.expect(COMMIT);
    Redirect::to(ROOT).into_response()
}
