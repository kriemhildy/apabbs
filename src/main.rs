use std::sync::{Arc, RwLock};
use tokio::sync::broadcast::Sender;

#[derive(Clone)]
struct AppState {
    db: sqlx::PgPool,
    jinja: Arc<RwLock<minijinja::Environment<'static>>>,
    sender: Arc<Sender<PostMessage>>,
}

async fn init_db() -> sqlx::PgPool {
    let url = std::env::var("DATABASE_URL").expect("read DATABASE_URL env");
    sqlx::PgPool::connect(&url).await.expect("connect postgres")
}

mod ban;

async fn init_cron_jobs() {
    use tokio_cron_scheduler::{Job, JobScheduler};
    let sched = JobScheduler::new().await.expect("make new job scheduler");
    // sec   min   hour   day of month   month   day of week   year
    // *     *     *      *              *       *             *
    let job = Job::new_async("0 0 * * * * *", |_uuid, _l| {
        Box::pin(async move {
            let db = init_db().await;
            let mut tx = db.begin().await.expect(BEGIN);
            ban::scrub(&mut tx).await;
            tx.commit().await.expect(COMMIT);
            println!("old IP hashes scrubbed");
        })
    })
    .expect("make new job");
    sched.add(job).await.expect("add job to schedule");
    sched.start().await.expect("start scheduler");
}

fn init_jinja() -> Arc<RwLock<minijinja::Environment<'static>>> {
    let mut env = minijinja::Environment::new();
    env.set_loader(minijinja::path_loader("templates"));
    env.set_keep_trailing_newline(true);
    env.set_lstrip_blocks(true);
    env.set_trim_blocks(true);
    env.add_filter("repeat", str::repeat);
    Arc::new(RwLock::new(env))
}

fn init_sender() -> Arc<Sender<PostMessage>> {
    Arc::new(tokio::sync::broadcast::channel(100).0)
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

fn router(state: AppState) -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/", get(index))
        .route("/submit-post", post(submit_post))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/new-hash", post(new_hash))
        .route("/hide-rejected-post", post(hide_rejected_post))
        .route("/web-socket", get(web_socket))
        .route("/admin/update-post-status", post(update_post_status))
        .layer(trace())
        .with_state(state)
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let state = {
        let (db, _) = tokio::join!(init_db(), init_cron_jobs());
        let jinja = init_jinja();
        let sender = init_sender();
        AppState { db, jinja, sender }
    };
    let router = router(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:7878")
        .await
        .expect("listen on 7878");
    axum::serve(listener, router).await.expect("serve axum")
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
mod crypto;

fn ip_hash(headers: &HeaderMap) -> String {
    use crypto::{convert_b64_salt, hash_password};
    let ip = headers
        .get("X-Real-IP")
        .expect("gets header")
        .to_str()
        .expect("converts header to str");
    let b64_salt = std::env::var("B64_SALT").expect("read B64_SALT env");
    let phc_salt_string = convert_b64_salt(&b64_salt);
    hash_password(ip, &phc_salt_string)
}

fn is_admin(user: &Option<User>) -> bool {
    user.as_ref().is_some_and(|u| u.admin)
}

fn is_author(
    user: &Option<User>,
    anon_uuid: &str,
    post_user_id: Option<i32>,
    post_anon_uuid: &Option<String>,
) -> bool {
    match user {
        Some(user) => post_user_id.is_some_and(|id| id == user.id),
        None => post_anon_uuid
            .as_ref()
            .is_some_and(|uuid| uuid == anon_uuid),
    }
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
        .same_site(SameSite::Lax) // Strict prevents linking to our site (yes really)
        .permanent()
        .build()
}

mod user;
use user::{Credentials, User};
mod post;
use post::{Post, PostHiding, PostMessage, PostReview, PostSubmission};
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
            None => uuid::Uuid::new_v4().hyphenated().to_string(),
        }
    };
}

macro_rules! check_for_ban {
    ($tx:expr, $ip_hash:expr, $module:ident) => {
        if ban::exists(&mut $tx, $ip_hash).await {
            return forbidden("ip was auto-banned due to flooding");
        }
        if $module::flooding(&mut $tx, $ip_hash).await {
            ban::insert(&mut $tx, $ip_hash).await;
            ban::prune(&mut $tx, $ip_hash).await;
            $tx.commit().await.expect(COMMIT);
            return forbidden("ip is flooding and has been auto-banned");
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
    let admin = is_admin(&user);
    let html = Html(render(
        state.jinja,
        "index.jinja",
        minijinja::context!(user, posts, anon_hash, admin),
    ));
    if jar.get(ANON_COOKIE).is_none() {
        let cookie = build_cookie(ANON_COOKIE, &anon_uuid);
        jar = jar.add(cookie);
    }
    (jar, html).into_response()
}

use axum::{response::Redirect, Form};

async fn submit_post(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(post_submission): Form<PostSubmission>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    let anon_uuid = anon_uuid!(jar);
    let ip_hash = ip_hash(&headers);
    check_for_ban!(tx, &ip_hash, post);
    let post = match &user {
        Some(user) => {
            post_submission
                .insert_as_user(&mut tx, user, &ip_hash)
                .await
        }
        None => {
            post_submission
                .insert_as_anon(&mut tx, &anon_uuid, &ip_hash)
                .await
        }
    };
    tx.commit().await.expect(COMMIT);
    let html = render(
        state.jinja,
        "post.jinja",
        minijinja::context!(post, admin => true),
    );
    let msg = PostMessage::new(post, html);
    state.sender.send(msg).expect("broadcast pending post");
    Redirect::to(ROOT).into_response()
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
                let ip_hash = ip_hash(&headers);
                check_for_ban!(tx, &ip_hash, user);
                let user = credentials.register(&mut tx, &ip_hash).await;
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
    jar: CookieJar,
    Form(post_hiding): Form<PostHiding>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    let anon_uuid = anon_uuid!(jar);
    let post = match Post::select(&mut tx, post_hiding.id).await {
        Some(post) => post,
        None => return bad_request("post does not exist"),
    };
    if !is_author(&user, &anon_uuid, post.user_id, &post.anon_uuid) {
        return bad_request("not post author");
    }
    if post.status != "rejected" {
        return bad_request("post is not rejected");
    }
    post_hiding.hide_post(&mut tx).await;
    tx.commit().await.expect(COMMIT);
    Redirect::to(ROOT).into_response()
}

use axum::extract::WebSocketUpgrade;

async fn web_socket(
    State(state): State<AppState>,
    jar: CookieJar,
    upgrade: WebSocketUpgrade,
) -> Response {
    use axum::extract::ws::{Message, WebSocket};
    use tokio::sync::broadcast::Receiver;
    async fn watch_receiver(
        mut socket: WebSocket,
        mut receiver: Receiver<PostMessage>,
        user: Option<User>,
        anon_uuid: String,
    ) {
        while let Ok(msg) = receiver.recv().await {
            let should_send = match msg.status.as_str() {
                "pending" => is_admin(&user),
                "rejected" => is_author(&user, &anon_uuid, msg.user_id, &msg.anon_uuid),
                "approved" => true,
                _ => panic!("invalid post status"),
            };
            if !should_send {
                continue;
            }
            let json = serde_json::to_string(&msg).expect("convert PostMessage to json");
            if socket.send(Message::Text(json)).await.is_err() {
                break; // client disconnect
            }
        }
    }
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    let anon_uuid = anon_uuid!(jar);
    tx.commit().await.expect(COMMIT);
    let receiver = state.sender.subscribe();
    upgrade.on_upgrade(move |socket| watch_receiver(socket, receiver, user, anon_uuid))
}

// admin handlers follow

macro_rules! require_admin {
    ($jar:expr, $tx:expr) => {
        let user = user!($jar, $tx);
        if !is_admin(&user) {
            return unauthorized();
        }
    };
}

async fn update_post_status(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(post_review): Form<PostReview>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    require_admin!(jar, tx);
    let post = Post::select(&mut tx, post_review.id).await;
    match post {
        Some(post) => {
            if post.status != "pending" {
                return bad_request("cannot update non-pending post");
            }
        }
        None => return bad_request("post does not exist"),
    }
    post_review.update_status(&mut tx).await;
    let post = Post::select(&mut tx, post_review.id).await.unwrap();
    tx.commit().await.expect(COMMIT);
    let html = render(
        state.jinja,
        "post.jinja",
        minijinja::context!(post, admin => false),
    );
    let msg = PostMessage::new(post, html);
    state.sender.send(msg).expect("broadcast reviewed post");
    Redirect::to(ROOT).into_response()
}
