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
        .route("/register-user", post(register_user))
        .route("/authenticate-user", post(authenticate_user))
        .route("/deauthenticate-user", post(deauthenticate_user))
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
    headers: HeaderMap,
    mut jar: CookieJar,
    Form(post): Form<Post>,
) -> Response {
    let mut tx = state.db.begin().await.expect("begin transaction");
    // create an anon user and a cookie here, if one is not already set.
    // posting is a first act of 'registration'.
    let user = match jar.get(USER_COOKIE) {
        Some(cookie) => match User::select(&mut tx, cookie.value()).await {
            Some(user) => user,
            None => return bad_request("cookie user not found"),
        },
        None => {
            // should probably only create user and cookie on post attempt.
            // if it's merely a "session", they should be separate records.
            // otherwise we will have to replace the current user with another one upon login.
            // we don't need session storage until they log in or post, basically.
            // a logged-out user's post should not be connected to a logged-in user.
            // we will have to limit it to one pending post per session though.
            let user = User::insert_anon(&mut tx).await;
            let cookie = build_cookie(headers, user.token.clone());
            jar = jar.add(cookie);
            user
        }
    };
    post.insert(&mut tx, user.id).await;
    tx.commit().await.expect("commit transaction");
    let redirect = Redirect::to("/");
    (jar, redirect).into_response()
}

// do we want one users table, or separate ones for anon and authed?
// one is simpler, but more wasted storage space.
// probably way more anon accounts than authed accounts. 100x.
// ipaddr on each post. not on users.
// unless you want to track all actions, like logins and logouts; which you should.
// but not on first implementation.
// should we use "flash" messaging?
// having one table means 'name' is 'not null', and many other fields expected of authed users.
// perhaps: anon_users and authed_users.
// just simpler as one table, though. simple is best.
async fn register_user(
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
    let anon_user = match jar.get(USER_COOKIE) {
        Some(cookie) => match User::select(&mut tx, cookie.value()).await {
            Some(user) => user,
            None => return bad_request("cookie user not found"),
        },
        None => {
            let user = User::insert_anon(&mut tx).await;
            let cookie = build_cookie(headers, user.token.clone());
            jar = jar.add(cookie);
            user
        }
    };
    // update anon user to registered user
    anon_user
        .register(&mut tx, form_username.as_str(), form_password.as_str())
        .await;
    tx.commit().await.expect("commit transaction");
    let redirect = Redirect::to("/");
    (jar, redirect).into_response()
}

async fn authenticate_user(
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

async fn deauthenticate_user(State(state): State<AppState>, mut jar: CookieJar) -> Response {
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
