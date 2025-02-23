mod helpers;
#[cfg(test)]
mod tests;

use crate::{
    ban, init,
    post::{Post, PostHiding, PostMediaCategory, PostReview, PostStatus, PostSubmission},
    user::{Account, Credentials, TimeZoneUpdate, User},
    AppState, PostMessage, BEGIN, COMMIT,
};
use axum::{
    extract::{
        ws::{Message, Utf8Bytes, WebSocket},
        DefaultBodyLimit, Multipart, Path, State, WebSocketUpgrade,
    },
    http::{
        header::{HeaderMap, CONTENT_DISPOSITION, CONTENT_TYPE},
        StatusCode, Uri,
    },
    response::{Form, Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use helpers::*;
use std::collections::HashMap;
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;

const ACCOUNT_COOKIE: &'static str = "account";
const ACCOUNT_NOT_FOUND: &'static str = "account not found";
const ANON_COOKIE: &'static str = "anon";
const NOTICE_COOKIE: &'static str = "notice";
const ROOT: &'static str = "/";

///////////////////////////////////////////////////////////////////////////////////////////////////
/// URL path router
///////////////////////////////////////////////////////////////////////////////////////////////////

pub fn router(state: AppState, trace: bool) -> axum::Router {
    use axum::routing::{get, post};
    let router = axum::Router::new()
        .route("/", get(index))
        .route("/page/{key}", get(index))
        .route("/submit-post", post(submit_post))
        .route("/login", get(login_form).post(authenticate))
        .route("/register", get(registration_form).post(create_account))
        .route(
            "/hide-rejected-post",
            post(hide_rejected_post).patch(hide_rejected_post),
        )
        .route("/web-socket", get(web_socket))
        .route("/interim/{key}", get(interim))
        .route("/user/{username}", get(user_profile))
        .route("/settings", get(settings))
        .route("/settings/logout", post(logout))
        .route("/settings/update-time-zone", post(update_time_zone))
        .route("/settings/update-password", post(update_password))
        .route(
            "/admin/review-post",
            post(review_post).patch(review_post).delete(review_post),
        )
        .route("/admin/decrypt-media/{key}", get(decrypt_media))
        .route("/{key}", get(index))
        .layer(DefaultBodyLimit::max(20_000_000));
    let router = if trace {
        router.layer(init::trace_layer())
    } else {
        router
    };
    router.with_state(state)
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// route handlers
///////////////////////////////////////////////////////////////////////////////////////////////////

async fn index(
    State(state): State<AppState>,
    mut jar: CookieJar,
    key: Uri,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    set_session_time_zone(&mut tx, user.time_zone()).await;
    let query_post = match params.get("key") {
        Some(key) => {
            set_session_time_zone(&mut tx, user.time_zone()).await;
            match Post::select_by_key(&mut tx, &key).await {
                Some(post) => Some(post),
                None => return not_found("post does not exist"),
            }
        }
        None => None,
    };
    let query_post_id = match &query_post {
        Some(post) => Some(post.id),
        None => None,
    };
    let solo = query_post.is_some() && !key.path().contains("/page/");
    let mut posts = if solo {
        match &query_post {
            Some(post) => vec![post.clone()],
            None => return bad_request("no post to show solo"),
        }
    } else {
        Post::select(&mut tx, &user, query_post_id, false).await
    };
    let prior_page_post = if posts.len() <= init::per_page() {
        None
    } else {
        posts.pop()
    };
    tx.commit().await.expect(COMMIT);
    let html = Html(render(
        &state,
        "index.jinja",
        minijinja::context!(
            title => init::site_name(),
            nav => !solo,
            posts,
            username => user.username(),
            admin => user.admin(),
            query_post,
            prior_page_post,
            solo,
        ),
    ));
    if jar.get(ANON_COOKIE).is_none() {
        let cookie = build_cookie(ANON_COOKIE, &user.anon_token.to_string(), true);
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
    set_session_time_zone(&mut tx, user.time_zone()).await;
    check_for_ban!(tx, &ip_hash);
    let mut post_submission = PostSubmission {
        body: String::default(),
        media_file_name: None,
        media_bytes: None,
    };
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        match name.as_str() {
            "body" => post_submission.body = field.text().await.unwrap(),
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
                post_submission.media_file_name = Some(file_name);
                post_submission.media_bytes = Some(field.bytes().await.unwrap().to_vec());
            }
            _ => return bad_request(&format!("unexpected field: {name}")),
        };
    }
    if post_submission.body.is_empty() && post_submission.media_file_name.is_none() {
        return bad_request("post cannot be empty unless there is a media file");
    }
    let post = post_submission.insert(&mut tx, &user, &ip_hash).await;
    if post_submission.media_file_name.is_some() {
        if let Err(msg) = post_submission.save_encrypted_media_file(&post.key).await {
            return internal_server_error(&msg);
        }
    }
    tx.commit().await.expect(COMMIT);
    send_post_to_web_socket(&state, post);
    if is_fetch_request(&headers) {
        StatusCode::CREATED.into_response()
    } else {
        Redirect::to(ROOT).into_response()
    }
}

async fn login_form(State(state): State<AppState>) -> Html<String> {
    Html(render(
        &state,
        "login.jinja",
        minijinja::context!(title => init::site_name()),
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
        return not_found("username does not exist");
    }
    match credentials.authenticate(&mut tx).await {
        Some(account) => {
            let cookie = build_cookie(ACCOUNT_COOKIE, &account.token.to_string(), true);
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
        minijinja::context!(title => init::site_name()),
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
            set_session_time_zone(&mut tx, "UTC").await;
            check_for_ban!(tx, &ip_hash);
            let account = credentials.register(&mut tx, &ip_hash).await;
            let cookie = build_cookie(ACCOUNT_COOKIE, &account.token.to_string(), true);
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
                Some(_account) => jar = jar.remove(removal_cookie(ACCOUNT_COOKIE)),
                None => return bad_request(ACCOUNT_NOT_FOUND),
            };
        }
        None => return bad_request("cookie not found"),
    };
    tx.commit().await.expect(COMMIT);
    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

async fn hide_rejected_post(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(post_hiding): Form<PostHiding>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    let post = match Post::select_by_key(&mut tx, &post_hiding.key).await {
        Some(post) => post,
        None => return not_found("post does not exist"),
    };
    if !post.author(&user) {
        if user.admin() {
            return Redirect::to(ROOT).into_response();
        }
        return unauthorized("not post author");
    }
    if post.status != PostStatus::Rejected {
        return bad_request("post is not rejected");
    }
    post_hiding.hide_post(&mut tx).await;
    tx.commit().await.expect(COMMIT);
    if is_fetch_request(&headers) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        Redirect::to(ROOT).into_response()
    }
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
            let should_send = if msg.admin {
                user.admin()
            } else {
                !user.admin()
                    && match msg.post.status {
                        Pending | Rejected | Banned => msg.post.author(&user),
                        Approved => true,
                    }
            };
            if !should_send {
                continue;
            }
            let json_utf8 = Utf8Bytes::from(
                serde_json::json!({"key": msg.post.key, "html": msg.html}).to_string(),
            );
            if socket.send(Message::Text(json_utf8)).await.is_err() {
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

async fn interim(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(key): Path<String>,
) -> Response {
    println!("interim key: {}", key);
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    let since_post = match Post::select_by_key(&mut tx, &key).await {
        Some(post) => post,
        None => return not_found("post does not exist"),
    };
    let new_posts = Post::select(&mut tx, &user, Some(since_post.id), true).await;
    tx.commit().await.expect(COMMIT);
    let mut json_posts: Vec<serde_json::Value> = Vec::new();
    for post in new_posts {
        let html = render(
            &state,
            "post.jinja",
            minijinja::context!(post, admin => user.admin()),
        );
        json_posts.push(serde_json::json!({
            "key": post.key,
            "html": html
        }));
    }
    serde_json::json!({"posts": json_posts})
        .to_string()
        .into_response()
}

async fn user_profile(
    State(state): State<AppState>,
    Path(username): Path<String>,
    jar: CookieJar,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    set_session_time_zone(&mut tx, user.time_zone()).await;
    let account = match Account::select_by_username(&mut tx, &username).await {
        Some(account) => account,
        None => return not_found("account does not exist"),
    };
    let posts = Post::select_by_author(&mut tx, account.id).await;
    tx.commit().await.expect(COMMIT);
    Html(render(
        &state,
        "user.jinja",
        minijinja::context!(
            title => init::site_name(),
            account,
            username => user.username(),
            posts,
        ),
    )).into_response()
}

async fn settings(State(state): State<AppState>, mut jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    if user.account.is_none() {
        return unauthorized("not logged in");
    }
    set_session_time_zone(&mut tx, user.time_zone()).await;
    let account = &user.account;
    let time_zones = TimeZoneUpdate::select_time_zones(&mut tx).await;
    tx.commit().await.expect(COMMIT);
    let notice = match jar.get(NOTICE_COOKIE) {
        Some(cookie) => {
            let value = cookie.value().to_owned();
            jar = jar.remove(removal_cookie(NOTICE_COOKIE));
            Some(value)
        }
        None => None,
    };
    let html = Html(render(
        &state,
        "settings.jinja",
        minijinja::context!(
            title => init::site_name(),
            account,
            username => user.username(),
            time_zones,
            notice,
        ),
    ));
    (jar, html).into_response()
}

async fn update_time_zone(
    State(state): State<AppState>,
    mut jar: CookieJar,
    Form(time_zone_update): Form<TimeZoneUpdate>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    if user.username() != Some(&time_zone_update.username) {
        return unauthorized("not your account");
    }
    let time_zones = TimeZoneUpdate::select_time_zones(&mut tx).await;
    if !time_zones.contains(&time_zone_update.time_zone) {
        return bad_request("invalid time zone");
    }
    time_zone_update.update(&mut tx).await;
    tx.commit().await.expect(COMMIT);
    let cookie = build_cookie(NOTICE_COOKIE, "Time zone updated.", false);
    jar = jar.add(cookie);
    let redirect = Redirect::to("/settings").into_response();
    (jar, redirect).into_response()
}

async fn update_password(
    State(state): State<AppState>,
    mut jar: CookieJar,
    Form(credentials): Form<Credentials>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    if user.username() != Some(&credentials.username) {
        return unauthorized("not your account");
    }
    let errors = credentials.validate();
    if !errors.is_empty() {
        return bad_request(&errors.join("\n"));
    }
    credentials.update_password(&mut tx).await;
    tx.commit().await.expect(COMMIT);
    let cookie = build_cookie(NOTICE_COOKIE, "Password updated.", false);
    jar = jar.add(cookie);
    let redirect = Redirect::to("/settings").into_response();
    (jar, redirect).into_response()
}

// admin handlers

async fn review_post(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(post_review): Form<PostReview>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    require_admin!(jar, tx);
    let post = match Post::select_by_key(&mut tx, &post_review.key).await {
        Some(post) => post,
        None => return not_found("post does not exist"),
    };
    match post.status {
        PostStatus::Pending => {
            if let Some(media_file_name) = post.media_file_name.as_ref() {
                let encrypted_media_path = post.encrypted_media_path();
                if !encrypted_media_path.exists() {
                    return not_found("encrypted media file does not exist");
                }
                if post_review.status == PostStatus::Approved {
                    let media_bytes = post.decrypt_media_file().await;
                    let published_media_path = post.published_media_path();
                    let media_key_dir = published_media_path.parent().unwrap();
                    std::fs::create_dir(media_key_dir).expect("create media key dir");
                    std::fs::write(&published_media_path, media_bytes).expect("write media file");
                    let media_path_str = published_media_path.to_str().expect("media path to str");

                    // generate webp thumbnail for images
                    if post
                        .media_category
                        .is_some_and(|c| c == PostMediaCategory::Image)
                    {
                        println!("generating thumbnail for {media_path_str}");
                        PostReview::generate_thumbnail(media_path_str).await;
                        let thumbnail_path = post_review.thumbnail_path(media_file_name);
                        if !thumbnail_path.exists() {
                            return internal_server_error("thumbnail not created successfully");
                        }
                        let thumbnail_len = thumbnail_path.metadata().unwrap().len();
                        let media_file_len = published_media_path.metadata().unwrap().len();
                        if thumbnail_len > media_file_len {
                            std::fs::remove_file(&thumbnail_path).expect("remove thumbnail file");
                        } else {
                            post_review.update_thumbnail(&mut tx, media_file_name).await;
                        }
                    }
                }
                let uploads_key_dir = encrypted_media_path.parent().unwrap();
                std::fs::remove_file(&encrypted_media_path).expect("remove encrypted media file");
                std::fs::remove_dir(&uploads_key_dir).expect("remove uploads key dir");
            }
        }
        PostStatus::Approved => (),
        _ => return bad_request("post must be pending or approved"),
    }
    post_review.update_status(&mut tx).await;
    let post = Post::select_by_key(&mut tx, &post_review.key)
        .await
        .expect("select post");
    if post.status == PostStatus::Banned {
        if let Some(ip_hash) = post.ip_hash.as_ref() {
            ban::insert(&mut tx, ip_hash).await;
        }
        post.delete(&mut tx).await;
    }
    if post.thumbnail_file_name.is_some() && !post.thumbnail_path().exists() {
        return internal_server_error("error setting post thumbnail");
    }
    tx.commit().await.expect(COMMIT);
    send_post_to_web_socket(&state, post);
    if is_fetch_request(&headers) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        Redirect::to(ROOT).into_response()
    }
}

async fn decrypt_media(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(key): Path<String>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    require_admin!(jar, tx);
    let post = match Post::select_by_key(&mut tx, &key).await {
        Some(post) => post,
        None => return not_found("post does not exist"),
    };
    if !post.encrypted_media_path().exists() {
        return not_found("encrypted media file does not exist");
    }
    let media_file_name = post.media_file_name.as_ref().expect("read media file_name");
    let media_bytes = post.decrypt_media_file().await;
    let content_type = post.media_mime_type.expect("read mime type");
    let headers = [
        (CONTENT_TYPE, &content_type),
        (
            CONTENT_DISPOSITION,
            &format!(r#"inline; file_name="{}""#, media_file_name),
        ),
    ];
    (headers, media_bytes).into_response()
}
