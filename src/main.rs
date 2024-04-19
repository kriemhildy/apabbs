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
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
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

// fn unauthorized() -> Response {
//     http_code(StatusCode::UNAUTHORIZED, "unauthorized")
// }

const USER_COOKIE: &'static str = "user";

fn build_cookie(token: &str) -> Cookie<'static> {
    Cookie::build((USER_COOKIE, token.to_owned()))
        .secure(!dev())
        .http_only(true)
        .same_site(SameSite::Strict)
        .permanent()
        .build()
}

mod user;
use user::{Credentials, User};
mod post;
use post::{Post, PostInput};

use axum::{extract::State, response::Html};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

async fn index(State(state): State<AppState>, jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect("begin transaction");
    // check for user cookie
    let user = match jar.get(USER_COOKIE) {
        Some(cookie) => match User::select_by_token(&mut tx, cookie.value()).await {
            Some(user) => Some(user),
            None => return bad_request("cookie user not found"),
        },
        None => None,
    };
    let posts = match user.as_ref().is_some_and(|u| u.admin) {
        true => Post::select_latest_admin(&mut tx).await,
        false => Post::select_latest_approved(&mut tx).await,
    };
    tx.commit().await.expect("commit transaction");
    let html = Html(render(
        state.jinja,
        "index.jinja",
        minijinja::context!(user, posts),
    ));
    (jar, html).into_response()
}

use axum::{response::Redirect, Form};

async fn submit_post(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(post_input): Form<PostInput>,
) -> Response {
    let mut tx = state.db.begin().await.expect("begin transaction");
    let user_id: Option<i32> = match jar.get(USER_COOKIE) {
        Some(cookie) => match User::select_by_token(&mut tx, cookie.value()).await {
            Some(user) => Some(user.id),
            None => return bad_request("cookie user not found"),
        },
        None => None,
    };
    post_input.insert(&mut tx, user_id).await;
    tx.commit().await.expect("commit transaction");
    Redirect::to("/").into_response()
}

async fn register(
    State(state): State<AppState>,
    mut jar: CookieJar,
    Form(credentials): Form<Credentials>,
) -> Response {
    let mut tx = state.db.begin().await.expect("begin transaction");
    if credentials.username_taken(&mut tx).await {
        return conflict("username already taken");
    }
    if !credentials.acceptable_username() {
        return conflict("unacceptable username");
    }
    if !credentials.acceptable_password() {
        return conflict("unacceptable password");
    }
    match jar.get(USER_COOKIE) {
        Some(_cookie) => return bad_request("log out before registering"),
        None => {
            let user = credentials.register(&mut tx).await;
            let cookie = build_cookie(&user.token);
            jar = jar.add(cookie);
        }
    };
    tx.commit().await.expect("commit transaction");
    let redirect = Redirect::to("/");
    (jar, redirect).into_response()
}

async fn login(
    State(state): State<AppState>,
    mut jar: CookieJar,
    Form(credentials): Form<Credentials>,
) -> Response {
    let mut tx = state.db.begin().await.expect("begin transaction");
    match credentials.authenticate(&mut tx).await {
        Some(user) => {
            let cookie = build_cookie(&user.token);
            jar = jar.add(cookie);
        }
        None => {
            return bad_request("incorrect credentials");
        }
    }
    tx.commit().await.expect("commit transaction");
    let redirect = Redirect::to("/");
    (jar, redirect).into_response()
}

async fn logout(State(state): State<AppState>, mut jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect("begin transaction");
    match jar.get(USER_COOKIE) {
        Some(cookie) => match User::select_by_token(&mut tx, cookie.value()).await {
            Some(_user) => jar = jar.remove(USER_COOKIE),
            None => return bad_request("cookie user not found"),
        },
        None => return bad_request("no user cookie found"),
    };
    jar = jar.remove(USER_COOKIE);
    tx.commit().await.expect("commit transaction");
    let redirect = Redirect::to("/");
    (jar, redirect).into_response()
}
