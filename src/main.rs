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
        .route("/submit-post", post(submit_post))
        .route("/register", post(register))
        .route("/authenticate", post(authenticate))
        .route("/deauthenticate", post(deauthenticate))
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
const SCHEME_HEADER: &'static str = "X-Forwarded-Proto";

fn build_cookie(headers: HeaderMap, token: String) -> Cookie<'static> {
    let scheme = headers
        .get(SCHEME_HEADER)
        .expect("get scheme header")
        .as_bytes();
    Cookie::build((USER_COOKIE, token))
        .secure(scheme == b"https")
        .http_only(true)
        .same_site(SameSite::Strict)
        .permanent()
        .build()
}

mod user;
use user::User;
mod post;
use post::Post;

use axum::{extract::State, http::HeaderMap, response::Html};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

async fn index(State(state): State<AppState>, jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect("begin transaction");
    // check for user cookie
    let user = match jar.get(USER_COOKIE) {
        Some(cookie) => match User::select(&mut tx, cookie.value()).await {
            Some(user) => match &user.name {
                Some(_name) => Some(user),
                None => None,
            },
            None => return bad_request("cookie user not found"),
        },
        None => None,
    };
    let posts = Post::select_latest_approved_100(&mut tx).await;
    tx.commit().await.expect("commit transaction");
    let html = Html(render(
        state.jinja,
        "index.jinja",
        minijinja::context!(user, posts),
    ));
    (jar, html).into_response()
}

// macro_rules! user {
//     ($tx:expr, $jar:expr) => {
//         match $jar.get(USER_COOKIE) {
//             Some(cookie) => match User::select(&mut $tx, cookie.value()).await {
//                 Some(user) => user,
//                 None => return bad_request("cookie user not found"),
//             },
//             None => return bad_request("no user cookie"),
//         }
//     };
// }

use axum::response::Redirect;
use axum::Form;

async fn submit_post(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(post): Form<Post>,
) -> Response {
    let mut tx = state.db.begin().await.expect("begin transaction");
    let user_id_option: Option<i32> = match jar.get(USER_COOKIE) {
        Some(cookie) => match User::select(&mut tx, cookie.value()).await {
            Some(user) => Some(user.id),
            None => return bad_request("cookie user not found"),
        },
        None => None,
    };
    post.insert(&mut tx, user_id_option).await;
    tx.commit().await.expect("commit transaction");
    Redirect::to("/").into_response()
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut jar: CookieJar,
    Form(form_user): Form<User>,
) -> Response {
    let mut tx = state.db.begin().await.expect("begin transaction");
    // check that username is not already taken
    let form_username = form_user.name.expect("read username");
    if User::name_taken(&mut tx, form_username.as_str()).await {
        return conflict("username already taken");
    }
    // we also need to validate the username in other ways (TBD)
    // check that password is acceptable
    let form_password = form_user.password;
    if !User::acceptable_password(form_username.as_str(), form_password.as_str()) {
        return conflict("unacceptable password");
    }
    // check if cookie is set from anon user
    // or insert anon user and set cookie if necessary
    match jar.get(USER_COOKIE) {
        Some(_cookie) => return bad_request("log out before registering"),
        None => {
            let user = User::register(&mut tx, form_username.as_str(), form_password.as_str()).await;
            let cookie = build_cookie(headers, user.token.clone());
            jar = jar.add(cookie);
        }
    };
    tx.commit().await.expect("commit transaction");
    let redirect = Redirect::to("/");
    (jar, redirect).into_response()
}

async fn authenticate(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut jar: CookieJar,
    Form(form_user): Form<User>,
) -> Response {
    let mut tx = state.db.begin().await.expect("begin transaction");
    match form_user.authenticate(&mut tx).await {
        Some(user) => {
            let cookie = build_cookie(headers, user.token.clone());
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

async fn deauthenticate(State(state): State<AppState>, mut jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect("begin transaction");
    match jar.get(USER_COOKIE) {
        Some(cookie) => match User::select(&mut tx, cookie.value()).await {
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
