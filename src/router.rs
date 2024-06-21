mod helpers;

use crate::{
    ban, init,
    post::{Post, PostHiding, PostReview, PostStatus, PostSubmission},
    user::{Account, Credentials, User},
    AppState, PostMessage, BEGIN, COMMIT,
};
use axum::{
    extract::{Multipart, State, WebSocketUpgrade},
    http::header::HeaderMap,
    response::{Form, Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use helpers::*;
use std::{fs::File, io::prelude::*, path::Path};

const ACCOUNT_COOKIE: &'static str = "account";
const ACCOUNT_NOT_FOUND: &'static str = "account not found";
const ANON_COOKIE: &'static str = "anon";
const ROOT: &'static str = "/";
const UPLOADS_DIR: &'static str = "uploads";

///////////////////////////////////////////////////////////////////////////////////////////////////
/// URL path router
///////////////////////////////////////////////////////////////////////////////////////////////////

pub fn router(state: AppState) -> axum::Router {
    use axum::{
        extract::DefaultBodyLimit,
        routing::{get, post},
    };
    axum::Router::new()
        .route("/", get(index))
        .route("/post", post(submit_post))
        .route("/login", get(login_form).post(authenticate))
        .route("/register", get(registration_form).post(create_account))
        .route("/logout", post(logout))
        .route("/hash", post(new_hash))
        .route("/hide-rejected-post", post(hide_rejected_post))
        .route("/web-socket", get(web_socket))
        .route("/admin/update-post-status", post(update_post_status))
        .layer(init::trace_layer())
        .layer(DefaultBodyLimit::max(10_000_000))
        .with_state(state)
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// route handlers
///////////////////////////////////////////////////////////////////////////////////////////////////

async fn index(State(state): State<AppState>, mut jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
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

async fn submit_post(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    let ip_hash = ip_hash(&headers);
    check_for_ban!(tx, &ip_hash);
    let mut post_submission = PostSubmission {
        body: String::default(),
        anon: None,
    };
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        match name.as_str() {
            "body" => post_submission.body = field.text().await.unwrap(),
            "anon" => post_submission.anon = Some(field.text().await.unwrap()),
            "image" => {
                // https://github.com/tokio-rs/axum/blob/main/examples/stream-to-file/src/main.rs
                let file_name = match field.file_name() {
                    Some(file_name) => file_name.to_owned(),
                    None => return bad_request("image has no filename"),
                };
                let path = Path::new(UPLOADS_DIR).join(&file_name);
                let mut file = File::create(path).expect("create file");
                file.write_all(&field.bytes().await.unwrap())
                    .expect("write to file");
            }
            _ => return bad_request(&format!("unexpected field: {name}")),
        };
    }
    if post_submission.body.is_empty() {
        return bad_request("post cannot be empty");
    }
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

async fn login_form(State(state): State<AppState>) -> Html<String> {
    Html(render(
        state.jinja,
        "login.jinja",
        minijinja::context!(title => site_name()),
    ))
}

async fn authenticate(
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

async fn registration_form(State(state): State<AppState>) -> Html<String> {
    Html(render(
        state.jinja,
        "register.jinja",
        minijinja::context!(title => site_name()),
    ))
}

async fn create_account(
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

async fn logout(State(state): State<AppState>, mut jar: CookieJar) -> Response {
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

// admin handlers

async fn update_post_status(
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
