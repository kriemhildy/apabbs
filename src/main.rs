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
            let url = std::env::var("PG_URL").expect("read PG_URL env");
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

fn http_code(code: StatusCode, msg: &str) -> Response {
    (code, msg.to_owned()).into_response()
}

fn bad_request(msg: &str) -> Response {
    http_code(StatusCode::BAD_REQUEST, msg)
}

fn conflict(msg: &str) -> Response {
    http_code(StatusCode::CONFLICT, msg)
}

fn unauthorized() -> Response {
    http_code(StatusCode::UNAUTHORIZED, "unauthorized")
}

const USER_COOKIE: &'static str = "user";
const SCHEME_HEADER: &'static str = "X-Forwarded-Proto";

mod user;
use user::User;
mod post;
use post::Post;

use axum::{extract::State, http::HeaderMap, response::Html};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

async fn index(State(state): State<AppState>, headers: HeaderMap, mut jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect("begin transaction");
    // let user = match jar.get(USER_COOKIE) {
    //     Some(cookie) => match User::select(&mut tx, cookie.value()).await {
    //         Some(user) => user,
    //         None => return bad_request("user not found"),
    //     },
    //     None => {
    //         // should probably only create user and cookie on post attempt.
    //         // if it's merely a "session", they should be separate records.
    //         // otherwise we will have to replace the current user with another one upon login.
    //         // we don't need session storage until they log in or post, basically.
    //         // a logged-out user's post should not be connected to a logged-in user.
    //         // we will have to limit it to one pending post per session though.
    //         let user = User::insert(&mut tx).await;
    //         let scheme = headers
    //             .get(SCHEME_HEADER)
    //             .expect("get scheme header")
    //             .as_bytes();
    //         let cookie = Cookie::build((USER_COOKIE, user.token.clone()))
    //             .secure(scheme == b"https")
    //             .http_only(true)
    //             .same_site(SameSite::Strict)
    //             .permanent()
    //             .build();
    //         jar = jar.add(cookie);
    //         user
    //     }
    // };
    let user: Option<User> = None;
    let posts = Post::select_latest_approved_100(&mut tx).await;
    tx.commit().await.expect("commit transaction");
    let html = Html(render(state.jinja, "index.jinja", minijinja::context!(user, posts)));
    (jar, html).into_response()
}

macro_rules! user {
    ($tx:expr, $jar:expr) => {
        match $jar.get(USER_COOKIE) {
            Some(cookie) => match User::select(&mut $tx, cookie.value()).await {
                Some(user) => user,
                None => return bad_request("user not found"),
            },
            None => return bad_request("no user cookie"),
        }
    };
}
