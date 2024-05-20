const OLD_USER_COOKIE: &'static str = "user"; // temporary for migration period
const ACCOUNT_COOKIE: &'static str = "account";
const ACCOUNT_NOT_FOUND: &'static str = "account not found";
const ANON_COOKIE: &'static str = "anon";
const ROOT: &'static str = "/";

use crate::{
    post::{Post, PostHiding, PostReview, PostStatus, PostSubmission},
    user::{Account, Credentials, User},
    *,
};
use axum::{
    extract::{State, WebSocketUpgrade},
    http::{header::HeaderMap, StatusCode},
    response::{Form, Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, format!("400 Bad Request\n\n{msg}")).into_response()
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "401 Unauthorized").into_response()
}

fn forbidden(msg: &str) -> Response {
    (StatusCode::FORBIDDEN, format!("403 Forbidden\n\n{msg}")).into_response()
}

fn ip_hash(headers: &HeaderMap) -> String {
    let ip = headers
        .get("X-Real-IP")
        .expect("get IP header")
        .to_str()
        .expect("convert header to str");
    let ip_salt = std::env::var("IP_SALT").expect("read IP_SALT env");
    if ip_salt.len() < 16 {
        panic!("IP_SALT env must be at least 16 chars");
    }
    sha256::digest(ip_salt + ip)
}

fn site_name() -> String {
    std::env::var("SITE_NAME").expect("read SITE_NAME env")
}

fn dev() -> bool {
    std::env::var("DEV").is_ok_and(|v| v == "1")
}

fn build_cookie(name: &str, value: &str) -> Cookie<'static> {
    Cookie::build((name.to_owned(), value.to_owned()))
        .secure(!dev())
        .http_only(true)
        .same_site(SameSite::Lax) // Strict prevents linking to our site (yes really)
        .permanent()
        .build()
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

// temporary for migration period
macro_rules! migrate_user_cookie {
    ($jar:expr) => {{
        match $jar.get(OLD_USER_COOKIE) {
            Some(cookie) => {
                let cookie = build_cookie(ACCOUNT_COOKIE, cookie.value());
                $jar = $jar.add(cookie);
                $jar = $jar.remove(OLD_USER_COOKIE);
            }
            None => (),
        };
    }};
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
            Some(cookie) => match uuid::Uuid::try_parse(cookie.value()) {
                Ok(uuid) => uuid.hyphenated().to_string(),
                Err(_) => return bad_request("invalid anon UUID"),
            },
            None => uuid::Uuid::new_v4().hyphenated().to_string(),
        };
        User {
            account,
            anon_token,
        }
    }};
}

macro_rules! check_for_ban {
    ($tx:expr, $ip_hash:expr) => {
        if ban::exists(&mut $tx, $ip_hash).await {
            return forbidden("ip was auto-banned due to flooding");
        }
        if ban::flooding(&mut $tx, $ip_hash).await {
            ban::insert(&mut $tx, $ip_hash).await;
            ban::prune(&mut $tx, $ip_hash).await;
            $tx.commit().await.expect(COMMIT);
            return forbidden("ip is flooding and has been auto-banned");
        }
    };
}

macro_rules! require_admin {
    ($jar:expr, $tx:expr) => {
        let user = user!($jar, $tx);
        if !user.admin() {
            return unauthorized();
        }
    };
}

pub async fn index(State(state): State<AppState>, mut jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    migrate_user_cookie!(jar);
    let user = user!(jar, tx);
    let posts = Post::select_latest(&mut tx, &user).await;
    tx.commit().await.expect(COMMIT);
    let html = Html(render(
        state.jinja,
        "index.jinja",
        minijinja::context!(
            title => site_name(),
            posts,
            logged_in => user.account.is_some(),
            username => user.username(),
            anon_hash => user.anon_hash(),
            admin => user.admin(),
            anon => user.anon()
        ),
    ));
    if jar.get(ANON_COOKIE).is_none() {
        let cookie = build_cookie(ANON_COOKIE, &user.anon_token);
        jar = jar.add(cookie);
    }
    (jar, html).into_response()
}

pub async fn submit_post(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(post_submission): Form<PostSubmission>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    let ip_hash = ip_hash(&headers);
    check_for_ban!(tx, &ip_hash);
    let user = user.update_anon(&mut tx, post_submission.anon()).await;
    let post = post_submission.insert(&mut tx, &user, &ip_hash).await;
    tx.commit().await.expect(COMMIT);
    let html = render(
        state.jinja,
        "post.jinja",
        minijinja::context!(post, admin => true),
    );
    let msg = PostMessage { post, html };
    state.sender.send(msg).ok();
    Redirect::to(ROOT).into_response()
}

pub async fn login_form(State(state): State<AppState>) -> Html<String> {
    Html(render(
        state.jinja,
        "login.jinja",
        minijinja::context!(title => site_name()),
    ))
}

pub async fn authenticate(
    State(state): State<AppState>,
    mut jar: CookieJar,
    Form(credentials): Form<Credentials>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    if jar.get(ACCOUNT_COOKIE).is_some() {
        return bad_request("already logged in");
    }
    if !credentials.username_exists(&mut tx).await {
        return bad_request("username does not exist");
    }
    match credentials.authenticate(&mut tx).await {
        Some(account) => {
            let cookie = build_cookie(ACCOUNT_COOKIE, &account.token);
            jar = jar.add(cookie);
        }
        None => return bad_request("password is wrong"),
    }
    tx.commit().await.expect(COMMIT);
    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

pub async fn registration_form(State(state): State<AppState>) -> Html<String> {
    Html(render(
        state.jinja,
        "register.jinja",
        minijinja::context!(title => site_name()),
    ))
}

pub async fn create_account(
    State(state): State<AppState>,
    mut jar: CookieJar,
    headers: HeaderMap,
    Form(credentials): Form<Credentials>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    if credentials.username_exists(&mut tx).await {
        return bad_request("username is taken");
    }
    let errors = credentials.validate();
    if !errors.is_empty() {
        return bad_request(&errors.join("\n"));
    }
    match jar.get(ACCOUNT_COOKIE) {
        Some(_cookie) => return bad_request("log out before registering"),
        None => {
            let ip_hash = ip_hash(&headers);
            check_for_ban!(tx, &ip_hash);
            let account = credentials.register(&mut tx, &ip_hash).await;
            let cookie = build_cookie(ACCOUNT_COOKIE, &account.token);
            jar = jar.add(cookie);
        }
    }
    tx.commit().await.expect(COMMIT);
    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

pub async fn logout(State(state): State<AppState>, mut jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    match jar.get(ACCOUNT_COOKIE) {
        Some(cookie) => match Account::select_by_token(&mut tx, cookie.value()).await {
            Some(_account) => jar = jar.remove(ACCOUNT_COOKIE),
            None => return bad_request(ACCOUNT_NOT_FOUND),
        },
        None => return bad_request("cookie not found"),
    };
    tx.commit().await.expect(COMMIT);
    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

pub async fn new_hash(mut jar: CookieJar) -> Response {
    jar = jar.remove(ANON_COOKIE);
    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

pub async fn hide_rejected_post(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(post_hiding): Form<PostHiding>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    let post = match Post::select_by_uuid(&mut tx, &post_hiding.uuid).await {
        Some(post) => post,
        None => return bad_request("post does not exist"),
    };
    if !post.authored_by(&user) {
        return bad_request("not post author");
    }
    if post.status != PostStatus::Rejected {
        return bad_request("post is not rejected");
    }
    post_hiding.hide_post(&mut tx).await;
    tx.commit().await.expect(COMMIT);
    Redirect::to(ROOT).into_response()
}

pub async fn web_socket(
    State(state): State<AppState>,
    jar: CookieJar,
    upgrade: WebSocketUpgrade,
) -> Response {
    use axum::extract::ws::{Message, WebSocket};
    use tokio::sync::broadcast::Receiver;
    async fn watch_receiver(
        mut socket: WebSocket,
        mut receiver: Receiver<PostMessage>,
        user: User,
    ) {
        while let Ok(msg) = receiver.recv().await {
            let should_send = match msg.post.status {
                PostStatus::Pending => user.admin(),
                PostStatus::Rejected => msg.post.authored_by(&user),
                PostStatus::Approved => true,
            };
            if !should_send {
                continue;
            }
            let json = serde_json::json!({"uuid": msg.post.uuid, "html": msg.html}).to_string();
            if socket.send(Message::Text(json)).await.is_err() {
                break; // client disconnect
            }
        }
    }
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    tx.commit().await.expect(COMMIT);
    let receiver = state.sender.subscribe();
    upgrade.on_upgrade(move |socket| watch_receiver(socket, receiver, user))
}

// admin handlers follow

pub async fn update_post_status(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(post_review): Form<PostReview>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    require_admin!(jar, tx);
    let post = Post::select_by_uuid(&mut tx, &post_review.uuid).await;
    match post {
        Some(post) => {
            if post.status != PostStatus::Pending {
                return bad_request("cannot update non-pending post");
            }
        }
        None => return bad_request("post does not exist"),
    }
    post_review.update_status(&mut tx).await;
    let post = Post::select_by_uuid(&mut tx, &post_review.uuid)
        .await
        .expect("assume post exists");
    tx.commit().await.expect(COMMIT);
    let html = render(
        state.jinja,
        "post.jinja",
        minijinja::context!(post, admin => false),
    );
    let msg = PostMessage { post, html };
    state.sender.send(msg).ok();
    Redirect::to(ROOT).into_response()
}
