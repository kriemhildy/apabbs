mod helpers;

use crate::{
    ban, init,
    post::{Post, PostHiding, PostReview, PostStatus, PostSubmission},
    user::{Account, Credentials, User},
    AppState, PostMessage, BEGIN, COMMIT,
};
use axum::{
    extract::{State, WebSocketUpgrade},
    http::header::HeaderMap,
    response::{Form, Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use helpers::*;

const ACCOUNT_COOKIE: &'static str = "account";
const ACCOUNT_NOT_FOUND: &'static str = "account not found";
const ANON_COOKIE: &'static str = "anon";
const ROOT: &'static str = "/";

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
        .route("/admin/update-post-status", post(update_post_status));
    let router = match trace {
        true => router.layer(init::trace_layer()),
        false => router,
    };
    router.with_state(state)
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
    Form(post_submission): Form<PostSubmission>,
) -> Response {
    let mut tx = state.db.begin().await.expect(BEGIN);
    let user = user!(jar, tx);
    let ip_hash = ip_hash(&headers);
    check_for_ban!(tx, &ip_hash);
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

///////////////////////////////////////////////////////////////////////////////////////////////////
// tests
///////////////////////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{
            header::{CONNECTION, CONTENT_TYPE, COOKIE, SET_COOKIE, UPGRADE},
            Method, Request, StatusCode,
        },
        Router,
    };
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`

    const LOCAL_IP: &'static str = "::1";

    async fn init_test() -> (Router, AppState) {
        if !dev() {
            panic!("not in dev mode");
        }
        let state = init::app_state().await;
        let router = router(state.clone(), false);
        (router, state)
    }

    #[tokio::test]
    async fn test_not_found() {
        let (router, _state) = init_test().await;
        let request = Request::builder()
            .uri("/not-found")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_index() {
        let (router, _state) = init_test().await;
        let request = Request::builder().uri(ROOT).body(Body::empty()).unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get(SET_COOKIE)
            .is_some_and(|c| c.to_str().unwrap().contains(ANON_COOKIE)));
    }

    #[tokio::test]
    async fn test_submit_post() {
        let (router, state) = init_test().await;
        let post_submission = PostSubmission {
            body: String::from("test body"),
            anon: Some(String::from("on")),
        };
        let post_str = serde_urlencoded::to_string(&post_submission).unwrap();
        let anon_token = uuid::Uuid::new_v4().hyphenated().to_string();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/post")
            .header(COOKIE, format!("{}={}", ANON_COOKIE, anon_token))
            .header(CONTENT_TYPE, mime::APPLICATION_WWW_FORM_URLENCODED.as_ref())
            .header(X_REAL_IP, LOCAL_IP)
            .body(Body::from(post_str))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        sqlx::query("DELETE FROM posts WHERE anon_token = $1")
            .bind(anon_token)
            .execute(&state.db)
            .await
            .expect("delete test post");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_login_form() {
        let (router, _state) = init_test().await;
        let request = Request::builder()
            .uri("/login")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_authenticate() {
        let (router, state) = init_test().await;
        let mut tx = state.db.begin().await.expect(BEGIN);
        let credentials = Credentials {
            username: String::from("test1"),
            password: String::from("test_password"),
        };
        credentials.register(&mut tx, LOCAL_IP).await;
        tx.commit().await.expect(COMMIT);
        let creds_str = serde_urlencoded::to_string(&credentials).unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/login")
            .header(CONTENT_TYPE, mime::APPLICATION_WWW_FORM_URLENCODED.as_ref())
            .body(Body::from(creds_str))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        sqlx::query("DELETE FROM accounts WHERE username = $1")
            .bind("test1")
            .execute(&state.db)
            .await
            .expect("delete test account");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(response
            .headers()
            .get(SET_COOKIE)
            .is_some_and(|c| c.to_str().unwrap().contains(ACCOUNT_COOKIE)));
    }

    #[tokio::test]
    async fn test_registration_form() {
        let (router, _state) = init_test().await;
        let request = Request::builder()
            .uri("/register")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_account() {
        let (router, state) = init_test().await;
        let credentials = Credentials {
            username: String::from("test2"),
            password: String::from("test_password"),
        };
        let creds_str = serde_urlencoded::to_string(&credentials).unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/register")
            .header(CONTENT_TYPE, mime::APPLICATION_WWW_FORM_URLENCODED.as_ref())
            .header(X_REAL_IP, LOCAL_IP)
            .body(Body::from(creds_str))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        sqlx::query("DELETE FROM accounts WHERE username = $1")
            .bind("test2")
            .execute(&state.db)
            .await
            .expect("delete test account");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(response
            .headers()
            .get(SET_COOKIE)
            .is_some_and(|c| c.to_str().unwrap().contains(ACCOUNT_COOKIE)));
    }

    #[tokio::test]
    async fn test_logout() {
        let (router, state) = init_test().await;
        let mut tx = state.db.begin().await.expect(BEGIN);
        let credentials = Credentials {
            username: String::from("test3"),
            password: String::from("test_password"),
        };
        let account = credentials.register(&mut tx, LOCAL_IP).await;
        tx.commit().await.expect(COMMIT);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/logout")
            .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        sqlx::query("DELETE FROM accounts WHERE username = $1")
            .bind("test3")
            .execute(&state.db)
            .await
            .expect("delete test account");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_new_hash() {
        let (router, _state) = init_test().await;
        let anon_token = uuid::Uuid::new_v4().hyphenated().to_string();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/hash")
            .header(COOKIE, format!("{}={}", ANON_COOKIE, anon_token))
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(response
            .headers()
            .get(SET_COOKIE)
            .is_some_and(|c| c.to_str().unwrap().contains(ANON_COOKIE)));
    }

    #[tokio::test]
    async fn test_hide_rejected_post() {
        let (router, state) = init_test().await;
        let mut tx = state.db.begin().await.expect(BEGIN);
        let user = User {
            account: None,
            anon_token: uuid::Uuid::new_v4().hyphenated().to_string(),
        };
        let post = PostSubmission {
            body: String::from("test body"),
            anon: Some(String::from("on")),
        }
        .insert(&mut tx, &user, LOCAL_IP)
        .await;
        PostReview {
            uuid: post.uuid.clone(),
            status: PostStatus::Rejected,
        }
        .update_status(&mut tx)
        .await;
        tx.commit().await.expect(COMMIT);
        let post_hiding = PostHiding {
            uuid: post.uuid.clone(),
        };
        let post_hiding_str = serde_urlencoded::to_string(&post_hiding).unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/hide-rejected-post")
            .header(COOKIE, format!("{}={}", ANON_COOKIE, user.anon_token))
            .header(CONTENT_TYPE, mime::APPLICATION_WWW_FORM_URLENCODED.as_ref())
            .body(Body::from(post_hiding_str))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        sqlx::query("DELETE FROM posts WHERE anon_token = $1")
            .bind(user.anon_token)
            .execute(&state.db)
            .await
            .expect("delete test post");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    #[ignore] // does not work currently
    async fn test_web_socket() {
        let (router, _state) = init_test().await;
        let request = Request::builder()
            .uri("/web-socket")
            .header(CONNECTION, "Upgrade")
            .header(UPGRADE, "WebSocket")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    }

    #[tokio::test]
    async fn test_update_post_status() {
        let (router, state) = init_test().await;
        let mut tx = state.db.begin().await.expect(BEGIN);
        let post_user = User {
            account: None,
            anon_token: uuid::Uuid::new_v4().hyphenated().to_string(),
        };
        let post = PostSubmission {
            body: String::from("test body"),
            anon: Some(String::from("on")),
        }
        .insert(&mut tx, &post_user, LOCAL_IP)
        .await;
        let admin_account = Credentials {
            username: String::from("test4"),
            password: String::from("test_password"),
        }
        .register(&mut tx, LOCAL_IP)
        .await;
        sqlx::query("UPDATE accounts SET admin = $2 WHERE username = $1")
            .bind(admin_account.username.clone())
            .bind(true)
            .execute(&mut *tx)
            .await
            .expect("set account as admin");
        tx.commit().await.expect(COMMIT);
        let post_review = PostReview {
            uuid: post.uuid.clone(),
            status: PostStatus::Approved,
        };
        let post_review_str = serde_urlencoded::to_string(&post_review).unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/admin/update-post-status")
            .header(
                COOKIE,
                format!("{}={}", ACCOUNT_COOKIE, admin_account.token),
            )
            .header(CONTENT_TYPE, mime::APPLICATION_WWW_FORM_URLENCODED.as_ref())
            .body(Body::from(post_review_str))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        let mut tx = state.db.begin().await.expect(BEGIN);
        sqlx::query("DELETE FROM posts WHERE anon_token = $1")
            .bind(post_user.anon_token)
            .execute(&mut *tx)
            .await
            .expect("delete test post");
        sqlx::query("DELETE FROM accounts WHERE username = $1")
            .bind(admin_account.username)
            .execute(&mut * tx)
            .await
            .expect("delete test admin account");
        tx.commit().await.expect(COMMIT);
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }
}
