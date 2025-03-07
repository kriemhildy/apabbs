mod helpers;
#[cfg(test)]
mod tests;

use crate::{
    ban, init,
    post::{
        Post, PostHiding, PostMediaCategory, PostReview, PostStatus, PostSubmission, ReviewAction,
    },
    user::{Account, AccountRole, Credentials, Logout, TimeZoneUpdate, User},
    AppState, BEGIN, COMMIT,
};
use axum::{
    extract::{
        ws::{Message, Utf8Bytes, WebSocket},
        DefaultBodyLimit, Multipart, Path, State, WebSocketUpgrade,
    },
    http::{
        header::{HeaderMap, CONTENT_DISPOSITION, CONTENT_TYPE},
        Method, StatusCode, Uri,
    },
    response::{Form, Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use helpers::*;
use std::collections::HashMap;
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;

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
        .route("/hide-post", post(hide_post).patch(hide_post))
        .route("/web-socket", get(web_socket))
        .route("/interim/{key}", get(interim))
        .route("/user/{username}", get(user_profile))
        .route("/settings", get(settings))
        .route("/settings/logout", post(logout))
        .route("/settings/reset-account-token", post(reset_account_token))
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
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    uri: Uri,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    let query_post = match params.get("key") {
        Some(key) => match Post::select_by_key(&mut tx, &key).await {
            None => return not_found("post does not exist"),
            Some(post) => {
                if [PostStatus::Rejected, PostStatus::Banned].contains(&post.status) {
                    return unauthorized("post is rejected or banned");
                }
                Some(post)
            }
        },
        None => None,
    };
    let query_post_id = match query_post {
        Some(ref post) => Some(post.id),
        None => None,
    };
    let solo = query_post.is_some() && !uri.path().starts_with("/page/");
    let mut posts = if solo {
        match query_post {
            None => return bad_request("no post to show"),
            Some(ref post) => {
                if post.status == PostStatus::Pending
                    && !(user.mod_or_admin() || post.author(&user))
                {
                    return unauthorized("post is pending approval");
                }
                vec![post.clone()]
            }
        }
    } else {
        Post::select(&mut tx, &user, query_post_id, false).await
    };
    let prior_page_post = if posts.len() <= init::per_page() {
        None
    } else {
        posts.pop()
    };
    let html = Html(render(
        &state,
        "index.jinja",
        minijinja::context!(
            title => init::site_name(),
            nav => !solo,
            user,
            posts,
            query_post,
            prior_page_post,
            solo,
        ),
    ));
    (jar, html).into_response()
}

async fn submit_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let ip_hash = ip_hash(&headers);
    if let Some(response) = check_for_ban(&mut tx, &ip_hash).await {
        tx.commit().await.expect(COMMIT);
        return response;
    }
    let mut post_submission = PostSubmission::default();
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        match name.as_str() {
            "session_token" => {
                post_submission.session_token = match Uuid::try_parse(&field.text().await.unwrap())
                {
                    Err(_) => return bad_request("invalid session token"),
                    Ok(uuid) => uuid,
                };
            }
            "body" => post_submission.body = field.text().await.unwrap(),
            "media" => {
                if post_submission.media_file_name.is_some() {
                    return bad_request("only upload one media file");
                }
                let file_name = match field.file_name() {
                    None => return bad_request("media file has no file_name"),
                    Some(file_name) => file_name.to_owned(),
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
    let (user, jar) =
        match init_user(jar, &mut tx, method, Some(post_submission.session_token)).await {
            Err(response) => return response,
            Ok(tuple) => tuple,
        };
    if post_submission.body.is_empty() && post_submission.media_file_name.is_none() {
        return bad_request("post cannot be empty unless there is a media file");
    }
    let post = post_submission.insert(&mut tx, &user, &ip_hash).await;
    if post_submission.media_file_name.is_some() {
        if let Err(msg) = post_submission.encrypt_uploaded_file(&post).await {
            return internal_server_error(&msg);
        }
    }
    tx.commit().await.expect(COMMIT);
    state.sender.send(post).ok();
    let response = if is_fetch_request(&headers) {
        StatusCode::CREATED.into_response()
    } else {
        Redirect::to(ROOT).into_response()
    };
    (jar, response).into_response()
}

async fn login_form(method: Method, State(state): State<AppState>, jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    let html = Html(render(
        &state,
        "login.jinja",
        minijinja::context!(title => init::site_name(), user),
    ));
    (jar, html).into_response()
}

async fn authenticate(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Form(credentials): Form<Credentials>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (_user, jar) = match init_user(jar, &mut tx, method, Some(credentials.session_token)).await
    {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    if !credentials.username_exists(&mut tx).await {
        return not_found("username does not exist");
    }
    let jar = match credentials.authenticate(&mut tx).await {
        None => return bad_request("password is wrong"),
        Some(account) => add_account_cookie(jar, &account, &credentials),
    };
    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

async fn registration_form(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    let html = Html(render(
        &state,
        "register.jinja",
        minijinja::context!(title => init::site_name(), user),
    ));
    (jar, html).into_response()
}

async fn create_account(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(credentials): Form<Credentials>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (_user, jar) = match init_user(jar, &mut tx, method, Some(credentials.session_token)).await
    {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    if credentials.username_exists(&mut tx).await {
        return bad_request("username is taken");
    }
    let errors = credentials.validate();
    if !errors.is_empty() {
        return bad_request(&errors.join("\n"));
    }
    let ip_hash = ip_hash(&headers);
    if let Some(response) = check_for_ban(&mut tx, &ip_hash).await {
        tx.commit().await.expect(COMMIT);
        return response;
    }
    let account = credentials.register(&mut tx, &ip_hash).await;
    let jar = add_account_cookie(jar, &account, &credentials);
    tx.commit().await.expect(COMMIT);
    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

async fn logout(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Form(logout): Form<Logout>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, Some(logout.session_token)).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    if user.account.is_none() {
        return bad_request("not logged in");
    }
    let jar = remove_account_cookie(jar);
    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

async fn reset_account_token(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Form(logout): Form<Logout>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, Some(logout.session_token)).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    let jar = match user.account {
        None => return bad_request("not logged in"),
        Some(account) => {
            account.reset_token(&mut tx).await;
            remove_account_cookie(jar)
        }
    };
    tx.commit().await.expect(COMMIT);
    let redirect = Redirect::to(ROOT);
    (jar, redirect).into_response()
}

async fn hide_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(post_hiding): Form<PostHiding>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, Some(post_hiding.session_token)).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    if let Some(post) = Post::select_by_key(&mut tx, &post_hiding.key).await {
        if !post.author(&user) {
            return unauthorized("not post author");
        }
        match post.status {
            PostStatus::Rejected => {
                post_hiding.hide_post(&mut tx).await;
                tx.commit().await.expect(COMMIT);
            }
            PostStatus::Reported | PostStatus::Banned => (),
            _ => return bad_request("post is not rejected, reported nor banned"),
        }
    };
    let response = if is_fetch_request(&headers) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        Redirect::to(ROOT).into_response()
    };
    (jar, response).into_response()
}

async fn web_socket(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    upgrade: WebSocketUpgrade,
) -> Response {
    async fn watch_receiver(
        State(state): State<AppState>,
        mut socket: WebSocket,
        mut receiver: Receiver<Post>,
        user: User,
    ) {
        use AccountRole::*;
        use PostStatus::*;
        while let Ok(post) = receiver.recv().await {
            let should_send = post.author(&user)
                || match user.account {
                    None => post.status == Approved,
                    Some(ref account) => match account.role {
                        Admin => true,
                        Mod => [Pending, Approved, Delisted, Reported].contains(&post.status),
                        Member | Novice => post.status == Approved,
                    },
                };
            if !should_send {
                continue;
            }
            let html = render(&state, "post.jinja", minijinja::context!(post, user));
            let json_utf8 =
                Utf8Bytes::from(serde_json::json!({"key": post.key, "html": html}).to_string());
            if socket.send(Message::Text(json_utf8)).await.is_err() {
                break; // client disconnect
            }
        }
    }
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, _jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    let receiver = state.sender.subscribe();
    upgrade.on_upgrade(move |socket| watch_receiver(State(state), socket, receiver, user))
}

async fn interim(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Path(key): Path<String>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    let since_post = match Post::select_by_key(&mut tx, &key).await {
        None => return not_found("post does not exist"),
        Some(post) => post,
    };
    let new_posts = Post::select(&mut tx, &user, Some(since_post.id), true).await;
    let mut json_posts: Vec<serde_json::Value> = Vec::new();
    for post in new_posts {
        let html = render(&state, "post.jinja", minijinja::context!(post, user));
        json_posts.push(serde_json::json!({
            "key": post.key,
            "html": html
        }));
    }
    let json = serde_json::json!({"posts": json_posts}).to_string();
    (jar, json).into_response()
}

async fn user_profile(
    method: Method,
    State(state): State<AppState>,
    Path(username): Path<String>,
    jar: CookieJar,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    let account = match Account::select_by_username(&mut tx, &username).await {
        None => return not_found("account does not exist"),
        Some(account) => account,
    };
    let posts = Post::select_by_author(&mut tx, account.id).await;
    let html = Html(render(
        &state,
        "profile.jinja",
        minijinja::context!(
            title => init::site_name(),
            user,
            account,
            posts,
        ),
    ));
    (jar, html).into_response()
}

async fn settings(method: Method, State(state): State<AppState>, jar: CookieJar) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    if user.account.is_none() {
        return unauthorized("not logged in");
    }
    let time_zones = TimeZoneUpdate::select_time_zones(&mut tx).await;
    let (jar, notice) = remove_notice_cookie(jar);
    let html = Html(render(
        &state,
        "settings.jinja",
        minijinja::context!(
            title => init::site_name(),
            user,
            time_zones,
            notice,
        ),
    ));
    (jar, html).into_response()
}

async fn update_time_zone(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Form(time_zone_update): Form<TimeZoneUpdate>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) =
        match init_user(jar, &mut tx, method, Some(time_zone_update.session_token)).await {
            Err(response) => return response,
            Ok(tuple) => tuple,
        };
    let account = match user.account {
        None => return unauthorized("not logged in"),
        Some(account) => account,
    };
    let time_zones = TimeZoneUpdate::select_time_zones(&mut tx).await;
    if !time_zones.contains(&time_zone_update.time_zone) {
        return bad_request("invalid time zone");
    }
    time_zone_update.update(&mut tx, account.id).await;
    tx.commit().await.expect(COMMIT);
    let jar = add_notice_cookie(jar, "Time zone updated.");
    let redirect = Redirect::to("/settings").into_response();
    (jar, redirect).into_response()
}

async fn update_password(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Form(credentials): Form<Credentials>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, Some(credentials.session_token)).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    match user.account {
        None => return unauthorized("not logged in"),
        Some(account) => {
            if account.username != credentials.username {
                return unauthorized("not logged in as this user");
            }
        }
    };
    let errors = credentials.validate();
    if !errors.is_empty() {
        return bad_request(&errors.join("\n"));
    }
    credentials.update_password(&mut tx).await;
    tx.commit().await.expect(COMMIT);
    let jar = add_notice_cookie(jar, "Password updated.");
    let redirect = Redirect::to("/settings").into_response();
    (jar, redirect).into_response()
}

// admin handlers

async fn review_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(post_review): Form<PostReview>,
) -> Response {
    use AccountRole::*;
    use PostStatus::*;
    use ReviewAction::*;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, Some(post_review.session_token)).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    let account = match user.account {
        None => return unauthorized("not logged in"),
        Some(account) => account,
    };
    match account.role {
        Admin | Mod => (),
        _ => return unauthorized("not an admin or mod"),
    };
    let post = match Post::select_by_key(&mut tx, &post_review.key).await {
        None => return not_found("post does not exist"),
        Some(post) => post,
    };
    let review_action = match post.status {
        Pending => match post_review.status {
            Pending => return bad_request("cannot set pending post to pending"),
            Approved | Delisted => DecryptMedia,
            Reported => Nothing,
            Rejected | Banned => DeleteEncryptedMedia,
        },
        Approved | Delisted => match post_review.status {
            Pending => return bad_request("post cannot return to pending"),
            Approved | Delisted => Nothing,
            Reported => {
                if account.role != Mod {
                    return unauthorized("only mods can report posts");
                }
                ReencryptMedia
            }
            Rejected | Banned => DeletePublishedMedia,
        },
        Reported => {
            if account.role != Admin {
                return unauthorized("only admins can review reported posts");
            }
            match post_review.status {
                Pending => return bad_request("post cannot return to pending"),
                Approved | Delisted => DecryptMedia,
                Rejected | Banned => DeleteEncryptedMedia,
                Reported => return bad_request("cannot set reported post to reported"),
            }
        }
        Rejected | Banned => return bad_request("post cannot be rejected or banned"),
    };
    if [DecryptMedia, DeleteEncryptedMedia].contains(&review_action) {
        if let Some(media_file_name) = post.media_file_name.as_ref() {
            let encrypted_media_path = post.encrypted_media_path();
            if !encrypted_media_path.exists() {
                return not_found("encrypted media file does not exist");
            }
            if review_action == DecryptMedia {
                let media_bytes = post.decrypt_media_file().await;
                let published_media_path = post.published_media_path();
                let media_key_dir = published_media_path.parent().unwrap();
                std::fs::create_dir(media_key_dir).expect("create media key dir");
                std::fs::write(&published_media_path, media_bytes).expect("write media file");
                let media_path_str = published_media_path.to_str().expect("media path to str");
                // generate webp thumbnail for images
                if post
                    .media_category
                    .as_ref()
                    .is_some_and(|c| *c == PostMediaCategory::Image)
                {
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
    if review_action == DeletePublishedMedia {
        if account.role != Admin {
            return unauthorized("only admins can ban or reject posts");
        }
        if post.media_file_name.as_ref().is_some() && post.published_media_path().exists() {
            PostReview::delete_media_dir(&post.key);
        }
    } else if review_action == ReencryptMedia {
        if let Err(msg) = PostReview::reencrypt_media_file(&post).await {
            return internal_server_error(msg);
        }
    }
    post_review.update_status(&mut tx).await;
    post_review.insert(&mut tx, account.id, post.id).await;
    let post = Post::select_by_key(&mut tx, &post_review.key)
        .await
        .expect("select post");
    if post.status == Banned {
        if let Some(ip_hash) = post.ip_hash.as_ref() {
            ban::insert(&mut tx, ip_hash).await;
        }
        post.delete(&mut tx).await;
    }
    if post.status == Approved
        && post.thumbnail_file_name.is_some()
        && !post.thumbnail_path().exists()
    {
        return internal_server_error("error setting post thumbnail");
    }
    tx.commit().await.expect(COMMIT);
    state.sender.send(post).ok();
    let response = if is_fetch_request(&headers) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        Redirect::to(ROOT).into_response()
    };
    (jar, response).into_response()
}

async fn decrypt_media(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Path(key): Path<String>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    if !user.mod_or_admin() {
        return unauthorized("not a mod or admin");
    }
    let post = match Post::select_by_key(&mut tx, &key).await {
        None => return not_found("post does not exist"),
        Some(post) => post,
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
    (jar, headers, media_bytes).into_response()
}
