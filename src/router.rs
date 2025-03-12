mod helpers;
#[cfg(test)]
mod tests;

use crate::{
    ban, init, post,
    post::{Post, PostHiding, PostReview, PostSubmission},
    user,
    user::{Account, Credentials, Logout, TimeZoneUpdate, User},
    AppState, BEGIN, COMMIT,
};
use axum::{
    extract::{
        ws::{Message, Utf8Bytes, WebSocket},
        DefaultBodyLimit, Multipart, Path, State, WebSocketUpgrade,
    },
    http::{
        header::{HeaderMap, CONTENT_DISPOSITION, CONTENT_TYPE},
        Method, StatusCode,
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
        .route("/hide-post", post(hide_post))
        .route("/web-socket", get(web_socket))
        .route("/interim/{key}", get(interim))
        .route("/user/{username}", get(user_profile))
        .route("/settings", get(settings))
        .route("/settings/logout", post(logout))
        .route("/settings/reset-account-token", post(reset_account_token))
        .route("/settings/update-time-zone", post(update_time_zone))
        .route("/settings/update-password", post(update_password))
        .route("/review/{key}", post(review_post))
        .route("/decrypt-media/{key}", get(decrypt_media))
        .route("/{key}", get(solo_post))
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
    Path(path): Path<HashMap<String, String>>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    let page_post = match path.get("key") {
        Some(key) => match init_post(&mut tx, key, &user).await {
            Err(response) => return response,
            Ok(post) => Some(post),
        },
        None => None,
    };
    let page_post_id_opt = page_post.as_ref().map(|p| p.id);
    let mut posts = Post::select(&mut tx, &user, page_post_id_opt, false).await;
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
            nav => true,
            user,
            posts,
            page_post,
            prior_page_post,
            solo => false
        ),
    ));
    (jar, html).into_response()
}

async fn solo_post(
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
    let post = match init_post(&mut tx, &key, &user).await {
        Err(response) => return response,
        Ok(post) => post,
    };
    let html = Html(render(
        &state,
        "solo.jinja",
        minijinja::context!(title => init::site_name(), user, post, solo => true),
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
    let ip_hash = ip_hash(&headers);
    let (user, jar) =
        match init_user(jar, &mut tx, method, Some(post_submission.session_token)).await {
            Err(response) => return response,
            Ok(tuple) => tuple,
        };
    if let Some(response) =
        check_for_ban(&mut tx, &ip_hash, user.account.as_ref().map(|a| a.id), None).await
    {
        tx.commit().await.expect(COMMIT);
        return response;
    }
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
    if let Some(response) = check_for_ban(&mut tx, &ip_hash, None, None).await {
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
    use post::PostStatus::*;
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
            Rejected => {
                post_hiding.hide_post(&mut tx).await;
                tx.commit().await.expect(COMMIT);
            }
            Reported | Banned => (),
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
        use post::PostStatus::*;
        use user::AccountRole::*;
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
    let since_post = match init_post(&mut tx, &key, &user).await {
        Err(response) => return response,
        Ok(post) => post,
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

// admin and mod handlers

async fn review_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(key): Path<String>,
    Form(post_review): Form<PostReview>,
) -> Response {
    use post::PostStatus::*;
    use post::ReviewAction::*;
    use post::ReviewError::*;
    use user::AccountRole::*;
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
    let post = match Post::select_by_key(&mut tx, &key).await {
        None => return not_found("post does not exist"),
        Some(post) => post,
    };
    let review_action = post_review.determine_action(&post.status, &account.role);
    match review_action {
        Err(SameStatus) => return bad_request("post already has this status"),
        Err(ReturnToPending) => return bad_request("cannot return post to pending"),
        Err(ModOnly) => return unauthorized("only mods can report posts"),
        Err(AdminOnly) => return unauthorized("only admins can ban or reject posts"),
        Err(RejectedOrBanned) => return bad_request("cannot review a banned or rejected post"),
        Ok(DecryptMedia) | Ok(DeleteEncryptedMedia) => {
            if post.media_file_name.is_some() {
                let encrypted_media_path = post.encrypted_media_path();
                if !encrypted_media_path.exists() {
                    return not_found("encrypted media file does not exist");
                }
                if review_action == Ok(DecryptMedia) {
                    if let Err(msg) = PostReview::handle_decrypt_media(&mut tx, &post).await {
                        return internal_server_error(&msg);
                    }
                }
                PostReview::delete_upload_key_dir(&encrypted_media_path);
            }
        }
        Ok(DeletePublishedMedia) => {
            if post.media_file_name.as_ref().is_some() && post.published_media_path().exists() {
                PostReview::delete_media_key_dir(&post.key);
            }
        }
        Ok(ReencryptMedia) => {
            if let Err(msg) = post.reencrypt_media_file().await {
                return internal_server_error(msg);
            }
        }
        Ok(NoAction) => (),
    }
    post.update_status(&mut tx, &post_review.status).await;
    post_review.insert(&mut tx, account.id, post.id).await;
    let post = Post::select_by_key(&mut tx, &key)
        .await
        .expect("select post");
    if post.status == Banned {
        if let Some(ip_hash) = post.ip_hash.as_ref() {
            ban::insert(&mut tx, ip_hash, post.account_id, Some(account.id)).await;
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
