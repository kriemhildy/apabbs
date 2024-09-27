mod helpers;
#[cfg(test)]
mod tests;

use crate::{
    ban, init,
    post::{Post, PostHiding, PostReview, PostStatus, PostSubmission},
    user::{Account, Credentials, User},
    AppState, PostMessage, BEGIN, COMMIT,
};
use axum::{
    extract::{
        ws::{Message, WebSocket},
        DefaultBodyLimit, Multipart, Path, Query, State, WebSocketUpgrade,
    },
    http::header::{HeaderMap, CONTENT_DISPOSITION, CONTENT_TYPE},
    response::{Form, Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use cocoon::Cocoon;
use helpers::*;
use std::fs::File;
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;

const ACCOUNT_COOKIE: &'static str = "account";
const ACCOUNT_NOT_FOUND: &'static str = "account not found";
const ANON_COOKIE: &'static str = "anon";
const ROOT: &'static str = "/";
const UPLOADS_DIR: &'static str = "uploads";
const MEDIA_DIR: &'static str = "pub/media";

///////////////////////////////////////////////////////////////////////////////////////////////////
/// URL path router
///////////////////////////////////////////////////////////////////////////////////////////////////

pub fn router(state: AppState, trace: bool) -> axum::Router {
    use axum::routing::{get, post};
    let router = axum::Router::new()
        .route("/", get(index))
        .route("/post", post(submit_post))
        .route("/login", get(login_form).post(authenticate))
        .route("/register", get(registration_form).post(create_account))
        .route("/logout", post(logout))
        .route("/hash", post(new_hash))
        .route("/hide-rejected-post", post(hide_rejected_post))
        .route("/web-socket", get(web_socket))
        .route("/admin/review-post", post(review_post))
        .route("/admin/decrypt-media/:uuid", get(decrypt_media))
        .layer(DefaultBodyLimit::max(20_000_000));
    let router = match trace {
        true => router.layer(init::trace_layer()),
        false => router,
    };
    router.with_state(state)
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// route handlers
///////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(serde::Deserialize)]
struct IndexQuery {
    uuid: Option<Uuid>,
    alone: Option<String>,
}

async fn index(
    State(state): State<AppState>,
    mut jar: CookieJar,
    query: Query<IndexQuery>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    let query_post = match query.uuid {
        Some(uuid) => Some(match Post::select_by_uuid(&mut tx, &uuid).await {
            Some(post) => post,
            None => return bad_request("post does not exist"),
        }),
        None => None,
    };
    let query_post_id = match &query_post {
        Some(post) => Some(post.id),
        None => None,
    };
    let alone = query.alone.as_ref().is_some_and(|a| a == "1");
    let posts = match alone {
        true => match &query_post {
            Some(post) => vec![post.clone()],
            None => return bad_request("no post to show alone"),
        },
        false => Post::select_latest(&mut tx, &user, query_post_id, per_page() as i32).await,
    };
    let posts_before_last = match posts.len() < per_page() {
        true => Vec::new(),
        false => {
            let last_post = posts.last().expect("read last post");
            let post_id_before_last = last_post.id - 1;
            Post::select_latest(&mut tx, &user, Some(post_id_before_last), 1).await
        }
    };
    let prior_page_post = posts_before_last.first();
    tx.commit().await.expect(COMMIT);
    let html = Html(render(
        &state,
        "index.jinja",
        minijinja::context!(
            title => site_name(),
            posts,
            logged_in => user.account.is_some(),
            username => user.username(),
            anon_hash => user.anon_hash(),
            admin => user.admin(),
            anon => user.anon(),
            query_post,
            prior_page_post,
            alone,
        ),
    ));
    if jar.get(ANON_COOKIE).is_none() {
        let cookie = build_cookie(ANON_COOKIE, &user.anon_token.to_string());
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
        media_file_name: None,
        uuid: Uuid::new_v4(),
    };
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        match name.as_str() {
            "body" => post_submission.body = field.text().await.unwrap(),
            "anon" => post_submission.anon = Some(field.text().await.unwrap()),
            "media" => {
                if post_submission.media_file_name.is_some() {
                    return bad_request("only upload one media file");
                }
                let file_name = match field.file_name() {
                    Some(file_name) => file_name.to_owned(),
                    None => return bad_request("media file has no file_name"),
                };
                if file_name.is_empty() {
                    continue;
                }
                let cocoon_file_name = file_name.clone() + ".cocoon";
                let cocoon_path = std::path::Path::new(UPLOADS_DIR)
                    .join(&post_submission.uuid.to_string())
                    .join(&cocoon_file_name);
                let cocoon_uuid_dir = cocoon_path.parent().unwrap();
                std::fs::create_dir(cocoon_uuid_dir).expect("create cocoon uuid dir");
                let mut file = File::create(&cocoon_path).expect("create file");
                let data = field.bytes().await.unwrap().to_vec();
                let secret_key = std::env::var("SECRET_KEY").expect("read SECRET_KEY env");
                let mut cocoon = Cocoon::new(secret_key.as_bytes());
                cocoon.dump(data, &mut file).expect("dump cocoon to file");
                post_submission.media_file_name = Some(file_name);
                println!(
                    "file uploaded and encrypted as: {}",
                    cocoon_path.to_str().unwrap()
                );
            }
            _ => return bad_request(&format!("unexpected field: {name}")),
        };
    }
    if post_submission.body.is_empty() && post_submission.media_file_name.is_none() {
        return bad_request("post cannot be empty unless there is a media file");
    }
    let user = user.update_anon(&mut tx, post_submission.anon()).await;
    let post = post_submission.insert(&mut tx, &user, &ip_hash).await;
    tx.commit().await.expect(COMMIT);
    send_post_to_web_socket(&state, post);
    Redirect::to(ROOT).into_response()
}

async fn login_form(State(state): State<AppState>) -> Html<String> {
    Html(render(
        &state,
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
            let cookie = build_cookie(ACCOUNT_COOKIE, &account.token.to_string());
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
        &state,
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
            let cookie = build_cookie(ACCOUNT_COOKIE, &account.token.to_string());
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
        Some(cookie) => {
            let token = match Uuid::try_parse(cookie.value()) {
                Ok(uuid) => uuid,
                Err(_) => return bad_request("invalid account token"),
            };
            match Account::select_by_token(&mut tx, &token).await {
                Some(_account) => jar = jar.remove(ACCOUNT_COOKIE),
                None => return bad_request(ACCOUNT_NOT_FOUND),
            }
        }
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
        if user.admin() {
            return Redirect::to(ROOT).into_response();
        }
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
    async fn watch_receiver(
        mut socket: WebSocket,
        mut receiver: Receiver<PostMessage>,
        user: User,
    ) {
        use PostStatus::*;
        while let Ok(msg) = receiver.recv().await {
            let should_send = match msg.admin {
                true => user.admin(),
                false => {
                    !user.admin()
                        && match msg.post.status {
                            Pending | Rejected | Banned => msg.post.authored_by(&user),
                            Approved => true,
                        }
                }
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

async fn review_post(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(post_review): Form<PostReview>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    require_admin!(jar, tx);
    let post = match Post::select_by_uuid(&mut tx, &post_review.uuid).await {
        Some(post) => post,
        None => return bad_request("post does not exist"),
    };
    if post.status != PostStatus::Pending {
        return bad_request("cannot update non-pending post");
    }
    if let Some(media_file_name) = post.media_file_name {
        let cocoon_file_name = media_file_name.clone() + ".cocoon";
        let uuid_string = post_review.uuid.to_string();
        let cocoon_path = std::path::Path::new(UPLOADS_DIR)
            .join(&uuid_string)
            .join(&cocoon_file_name);
        if !cocoon_path.exists() {
            return bad_request("cocoon file does not exist");
        }
        if post_review.status == PostStatus::Approved {
            let mut file = File::open(&cocoon_path).expect("open file");
            let secret_key = std::env::var("SECRET_KEY").expect("read SECRET_KEY env");
            let cocoon = Cocoon::new(secret_key.as_bytes());
            let data = cocoon.parse(&mut file).expect("decrypt cocoon file");
            let media_path = std::path::Path::new(MEDIA_DIR)
                .join(&uuid_string)
                .join(&media_file_name);
            let media_uuid_dir = media_path.parent().unwrap();
            std::fs::create_dir(media_uuid_dir).expect("create media uuid dir");
            std::fs::write(&media_path, data).expect("write media file");
        }
        let uploads_uuid_dir = cocoon_path.parent().unwrap();
        std::fs::remove_file(&cocoon_path).expect("remove cocoon file");
        std::fs::remove_dir(&uploads_uuid_dir).expect("remove uploads uuid dir");
    }
    post_review.update_status(&mut tx).await;
    let post = Post::select_by_uuid(&mut tx, &post_review.uuid)
        .await
        .expect("select post");
    if post.status == PostStatus::Banned {
        let ip_hash = post.ip_hash.as_ref().expect("read ip_hash");
        ban::insert(&mut tx, ip_hash).await;
        post.delete(&mut tx).await;
    }
    tx.commit().await.expect(COMMIT);
    send_post_to_web_socket(&state, post);
    Redirect::to(ROOT).into_response()
}

async fn decrypt_media(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(uuid): Path<Uuid>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    require_admin!(jar, tx);
    let post = Post::select_by_uuid(&mut tx, &uuid)
        .await
        .expect("select post");
    let media_file_name = post.media_file_name.expect("read media file_name");
    let cocoon_file_name = media_file_name.clone() + ".cocoon";
    let path = std::path::Path::new(UPLOADS_DIR)
        .join(&uuid.to_string())
        .join(&cocoon_file_name);
    let mut cocoon_file = match File::open(&path) {
        Ok(file) => file,
        Err(_) => return not_found(),
    };
    let secret_key = std::env::var("SECRET_KEY").expect("read SECRET_KEY env");
    let cocoon = Cocoon::new(secret_key.as_bytes());
    let data = cocoon.parse(&mut cocoon_file).expect("decrypt cocoon file");
    let content_type = post.media_mime_type.expect("read mime type");
    let headers = [
        (CONTENT_TYPE, &content_type),
        (
            CONTENT_DISPOSITION,
            &format!(r#"inline; file_name="{}""#, &media_file_name),
        ),
    ];
    (headers, data).into_response()
}
