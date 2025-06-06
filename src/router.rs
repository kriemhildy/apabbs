mod helpers;
#[cfg(test)]
mod tests;

use crate::AppState;
use apabbs::{
    BEGIN, COMMIT, ban,
    post::{Post, PostHiding, PostReview, PostStatus, PostSubmission, ReviewAction, ReviewError},
    user::{Account, AccountRole, Credentials, Logout, TimeZoneUpdate, User},
};
use axum::{
    extract::{
        DefaultBodyLimit, Multipart, Path, State, WebSocketUpgrade,
        ws::{Message, Utf8Bytes, WebSocket},
    },
    http::{
        Method, StatusCode,
        header::{CONTENT_DISPOSITION, CONTENT_TYPE, HeaderMap},
    },
    response::{Form, Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use helpers::*;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;

const ROOT: &'static str = "/";

// Used with background tasks
type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

//-------------------------------------------------------------------------------------------------
/// URL path router
//-------------------------------------------------------------------------------------------------

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
        .route("/post/{key}", get(solo_post))
        .route("/p/{key}", get(solo_post))
        .route("/{key}", get(solo_post)) // temporary for backwards compatibility
        .layer(DefaultBodyLimit::max(20_000_000));
    let router = if trace {
        let trace_layer = {
            use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
            use tracing::Level;
            tracing_subscriber::fmt()
                .with_max_level(Level::DEBUG)
                .try_init()
                .expect("init tracing");
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::DEBUG))
                .on_response(DefaultOnResponse::new().level(Level::DEBUG))
        };
        router.layer(trace_layer)
    } else {
        router
    };
    router.with_state(state)
}

//-------------------------------------------------------------------------------------------------
// route handlers
//-------------------------------------------------------------------------------------------------

async fn index(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Path(path): Path<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    let page_post_opt = match path.get("key") {
        Some(key) => match init_post(&mut tx, key, &user).await {
            Err(response) => return response,
            Ok(post) => Some(post),
        },
        None => None,
    };
    let page_post_id_opt = page_post_opt.as_ref().map(|p| p.id);
    let mut posts = Post::select(&mut tx, &user, page_post_id_opt, false).await;
    let prior_page_post_opt = if posts.len() <= apabbs::per_page() {
        None
    } else {
        posts.pop()
    };
    let html = Html(render(
        &state,
        "index.jinja",
        minijinja::context!(
            dev => apabbs::dev(),
            host => apabbs::host(),
            user_agent_opt => analyze_user_agent(&headers),
            nav => true,
            user,
            posts,
            page_post_opt,
            prior_page_post_opt,
            solo => false,
        ),
    ));
    (jar, html).into_response()
}

async fn solo_post(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    Path(key): Path<String>,
    headers: HeaderMap,
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
        minijinja::context!(
            dev => apabbs::dev(),
            host => apabbs::host(),
            user_agent_opt => analyze_user_agent(&headers),
            user,
            post,
            solo => true,
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
    let mut post_submission = PostSubmission::default();
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_owned();
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
                if post_submission.media_filename_opt.is_some() {
                    return bad_request("only upload one media file");
                }
                let filename = match field.file_name() {
                    None => return bad_request("media file has no filename"),
                    Some(filename) => filename.to_owned(),
                };
                if filename.is_empty() {
                    continue;
                }
                post_submission.media_filename_opt = Some(filename);
                post_submission.media_bytes_opt = Some(field.bytes().await.unwrap().to_vec());
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
    if let Some(response) = check_for_ban(
        &mut tx,
        &ip_hash,
        user.account_opt.as_ref().map(|a| a.id),
        None,
    )
    .await
    {
        tx.commit().await.expect(COMMIT);
        return response;
    }
    if post_submission.body.is_empty() && post_submission.media_filename_opt.is_none() {
        return bad_request("post cannot be empty unless there is a media file");
    }
    let key = PostSubmission::generate_key(&mut tx).await;
    let post = post_submission.insert(&mut tx, &user, &ip_hash, &key).await;
    if post_submission.media_filename_opt.is_some() {
        if let Err(msg) = post_submission.encrypt_uploaded_file(&post).await {
            return internal_server_error(&msg);
        }
    }
    tx.commit().await.expect(COMMIT);
    if state.sender.send(post).is_err() {
        println!("No active receivers to send to");
    }
    let response = if is_fetch_request(&headers) {
        StatusCode::CREATED.into_response()
    } else {
        Redirect::to(ROOT).into_response()
    };
    (jar, response).into_response()
}

async fn login_form(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    let html = Html(render(
        &state,
        "login.jinja",
        minijinja::context!(
            dev => apabbs::dev(),
            host => apabbs::host(),
            user_agent_opt => analyze_user_agent(&headers),
            user,
        ),
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
    headers: HeaderMap,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    let html = Html(render(
        &state,
        "register.jinja",
        minijinja::context!(
            dev => apabbs::dev(),
            host => apabbs::host(),
            user_agent_opt => analyze_user_agent(&headers),
            user,
        ),
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
    if user.account_opt.is_none() {
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
    let jar = match user.account_opt {
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
    use PostStatus::*;
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
        use AccountRole::*;
        use PostStatus::*;
        while let Ok(post) = receiver.recv().await {
            let should_send = post.author(&user)
                || match user.account_opt {
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
    let since_post_id_opt = Some(since_post.id);
    let new_posts = Post::select(&mut tx, &user, since_post_id_opt, true).await;
    if new_posts.is_empty() {
        return (jar, StatusCode::NO_CONTENT).into_response();
    }
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
    headers: HeaderMap,
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
            dev => apabbs::dev(),
            host => apabbs::host(),
            user_agent_opt => analyze_user_agent(&headers),
            user,
            account,
            posts,
        ),
    ));
    (jar, html).into_response()
}

async fn settings(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, None).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    if user.account_opt.is_none() {
        return unauthorized("not logged in");
    }
    let time_zones = TimeZoneUpdate::select_time_zones(&mut tx).await;
    let (jar, notice_opt) = remove_notice_cookie(jar);
    let html = Html(render(
        &state,
        "settings.jinja",
        minijinja::context!(
            dev => apabbs::dev(),
            host => apabbs::host(),
            user_agent_opt => analyze_user_agent(&headers),
            user,
            time_zones,
            notice_opt,
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
    let account = match user.account_opt {
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
    match user.account_opt {
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
    use AccountRole::*;
    use PostStatus::*;
    use ReviewAction::*;
    use ReviewError::*;
    let mut tx = state.db.begin().await.expect(BEGIN);
    let (user, jar) = match init_user(jar, &mut tx, method, Some(post_review.session_token)).await {
        Err(response) => return response,
        Ok(tuple) => tuple,
    };
    let account = match user.account_opt {
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
    let review_action = post_review.determine_action(&post, &account.role);
    let mut background_task: Option<BoxFuture> = None;
    match review_action {
        Err(SameStatus) => return bad_request("post already has this status"),
        Err(ReturnToPending) => return bad_request("cannot return post to pending"),
        Err(ModOnly) => return unauthorized("only mods can report posts"),
        Err(AdminOnly) => return unauthorized("only admins can ban or reject posts"),
        Err(RejectedOrBanned) => return bad_request("cannot review a banned or rejected post"),
        Err(RecentOnly) => return unauthorized("mods can only review approved posts for two days"),
        Err(CurrentlyProcessing) => return bad_request("post is currently being processed"),
        Err(ManualProcessing) => return bad_request("cannot manually set post to processing"),
        Ok(DecryptMedia | DeleteEncryptedMedia) => {
            if post.media_filename_opt.is_some() {
                let encrypted_media_path = post.encrypted_media_path();
                if !encrypted_media_path.exists() {
                    return not_found("encrypted media file does not exist");
                }
                if review_action == Ok(DecryptMedia) {
                    async fn decrypt_media_task(
                        state: AppState,
                        post: Post,
                        post_review: PostReview,
                        encrypted_media_path: std::path::PathBuf,
                    ) {
                        let mut tx = state.db.begin().await.expect(BEGIN);
                        if let Err(msg) = PostReview::handle_decrypt_media(&mut tx, &post).await {
                            println!("Error decrypting media: {}", msg);
                            return;
                        }
                        post.update_status(&mut tx, post_review.status).await;
                        let post = match Post::select_by_key(&mut tx, &post.key).await {
                            None => {
                                println!("Post does not exist after decrypting media");
                                return;
                            }
                            Some(post) => post,
                        };
                        tx.commit().await.expect(COMMIT);
                        PostReview::delete_upload_key_dir(&encrypted_media_path);
                        if state.sender.send(post).is_err() {
                            println!("No active receivers to send to");
                        }
                    }
                    background_task = Some(Box::pin(decrypt_media_task(
                        state.clone(),
                        post.clone(),
                        post_review.clone(),
                        encrypted_media_path.clone(),
                    )));
                }
            }
        }
        Ok(DeletePublishedMedia) => {
            if post.media_filename_opt.as_ref().is_some() && post.published_media_path().exists() {
                PostReview::delete_media_key_dir(&post.key);
            }
        }
        Ok(ReencryptMedia) => {
            async fn reencrypt_media_task(state: AppState, post: Post, post_review: PostReview) {
                let mut tx = state.db.begin().await.expect(BEGIN);
                if let Err(msg) = post.reencrypt_media_file().await {
                    println!("Error re-encrypting media: {}", msg);
                    return;
                }
                post.update_status(&mut tx, post_review.status).await;
                let post = match Post::select_by_key(&mut tx, &post.key).await {
                    None => {
                        println!("Post does not exist after re-encrypting media");
                        return;
                    }
                    Some(post) => post,
                };
                tx.commit().await.expect(COMMIT);
                if state.sender.send(post).is_err() {
                    println!("No active receivers to send to");
                }
            }
            background_task = Some(Box::pin(reencrypt_media_task(
                state.clone(),
                post.clone(),
                post_review.clone(),
            )));
        }
        Ok(NoAction) => (),
    }
    let status = if background_task.is_some() {
        Processing
    } else {
        post_review.status
    };
    post.update_status(&mut tx, status).await;
    post_review.insert(&mut tx, account.id, post.id).await;
    let post = match Post::select_by_key(&mut tx, &key).await {
        None => return not_found("post does not exist"),
        Some(post) => post,
    };
    if post.status == Banned {
        if let Some(ip_hash) = post.ip_hash_opt.as_ref() {
            ban::insert(&mut tx, ip_hash, post.account_id_opt, Some(account.id)).await;
        }
        post.delete(&mut tx).await;
    }
    if post.status == Approved
        && post.thumb_filename_opt.is_some()
        && !post.thumbnail_path().exists()
    {
        return internal_server_error("error setting post thumbnail");
    }
    tx.commit().await.expect(COMMIT);
    if state.sender.send(post).is_err() {
        println!("No active receivers to send to");
    }
    if let Some(task) = background_task {
        tokio::spawn(task);
    }
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
    let media_filename = post
        .media_filename_opt
        .as_ref()
        .expect("read media filename");
    let media_bytes = post.decrypt_media_file().await;
    let content_type = post.media_mime_type_opt.expect("read mime type");
    let headers = [
        (CONTENT_TYPE, &content_type),
        (
            CONTENT_DISPOSITION,
            &format!(r#"inline; filename="{}""#, media_filename),
        ),
    ];
    (jar, headers, media_bytes).into_response()
}
