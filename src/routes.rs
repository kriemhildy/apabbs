const USER_COOKIE: &'static str = "user";
const USER_NOT_FOUND: &'static str = "user not found";
const ANON_COOKIE: &'static str = "anon";
const ROOT: &'static str = "/";

use crate::{
    post::{Post, PostHiding, PostReview, PostSubmission},
    user::{is_admin, Credentials, User},
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
    let b64_salt = std::env::var("IP_SALT").expect("read IP_SALT env");
    let phc_salt_string = crypto::convert_b64_salt(&b64_salt);
    crypto::hash_password(ip, &phc_salt_string)
}

fn build_cookie(name: &str, value: &str) -> Cookie<'static> {
    Cookie::build((name.to_owned(), value.to_owned()))
        .secure(!dev())
        .http_only(true)
        .same_site(SameSite::Lax) // Strict prevents linking to our site (yes really)
        .permanent()
        .build()
}

macro_rules! cookies {
    ($jar:expr, $tx:expr) => {{
        let user = match $jar.get(USER_COOKIE) {
            Some(cookie) => match User::select_by_token(&mut $tx, cookie.value()).await {
                Some(user) => Some(user),
                None => return bad_request(USER_NOT_FOUND),
            },
            None => None,
        };
        let anon_uuid = match $jar.get(ANON_COOKIE) {
            Some(cookie) => match uuid::Uuid::try_parse(cookie.value()) {
                Ok(uuid) => uuid.hyphenated().to_string(),
                Err(_) => return bad_request("invalid anon UUID"),
            },
            None => uuid::Uuid::new_v4().hyphenated().to_string(),
        };
        (user, anon_uuid)
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
        let (user, _anon_uuid) = cookies!($jar, $tx);
        if !is_admin(&user) {
            return unauthorized();
        }
    };
}

pub async fn index(State(state): State<AppState>, mut jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, anon_uuid) = cookies!(jar, tx);
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

pub async fn submit_post(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(post_submission): Form<PostSubmission>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, anon_uuid) = cookies!(jar, tx);
    let ip_hash = ip_hash(&headers);
    check_for_ban!(tx, &ip_hash);
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
    let msg = PostMessage { post, html };
    state.sender.send(msg).expect("broadcast pending post");
    Redirect::to(ROOT).into_response()
}

pub async fn login(
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
                check_for_ban!(tx, &ip_hash);
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

pub async fn logout(State(state): State<AppState>, mut jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    match jar.get(USER_COOKIE) {
        Some(cookie) => match User::select_by_token(&mut tx, cookie.value()).await {
            Some(_user) => jar = jar.remove(USER_COOKIE),
            None => return bad_request(USER_NOT_FOUND),
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
    let (user, anon_uuid) = cookies!(jar, tx);
    let post = match Post::select(&mut tx, post_hiding.id).await {
        Some(post) => post,
        None => return bad_request("post does not exist"),
    };
    if !post.authored_by(&user, &anon_uuid) {
        return bad_request("not post author");
    }
    if post.status != "rejected" {
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
        user: Option<User>,
        anon_uuid: String,
    ) {
        while let Ok(msg) = receiver.recv().await {
            let should_send = match msg.post.status.as_str() {
                "pending" => is_admin(&user),
                "rejected" => msg.post.authored_by(&user, &anon_uuid),
                "approved" => true,
                _ => panic!("invalid post status"),
            };
            if !should_send {
                continue;
            }
            let json = serde_json::json!({"id": msg.post.id, "html": msg.html}).to_string();
            if socket.send(Message::Text(json)).await.is_err() {
                break; // client disconnect
            }
        }
    }
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, anon_uuid) = cookies!(jar, tx);
    tx.commit().await.expect(COMMIT);
    let receiver = state.sender.subscribe();
    upgrade.on_upgrade(move |socket| watch_receiver(socket, receiver, user, anon_uuid))
}

// admin handlers follow

pub async fn update_post_status(
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
    let msg = PostMessage { post, html };
    state.sender.send(msg).expect("broadcast reviewed post");
    Redirect::to(ROOT).into_response()
}
