//! Authentication and account-related integration tests.

mod helpers;

use apabbs::{
    router::helpers::{ACCOUNT_COOKIE, SESSION_COOKIE, X_REAL_IP},
    user::AccountRole,
};
use axum::http::{
    Request, StatusCode,
    header::{CONTENT_TYPE, COOKIE},
};
use helpers::*;
use tower::ServiceExt;

#[tokio::test]
async fn login_form() {
    let (router, _state) = init_test().await;
    let request = Request::builder()
        .uri("/login")
        .header(X_REAL_IP, LOCAL_IP)
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    let body_str = response_body_str(response).await;
    assert!(body_str.contains("Log in"));
}

#[tokio::test]
async fn authenticate() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");
    let user = test_user(None);
    let credentials = test_credentials(&user);
    let account = credentials
        .register(&mut tx, &local_ip_hash())
        .await
        .expect("query succeeds");
    tx.commit().await.expect("commits");
    let creds_str = serde_urlencoded::to_string(&credentials).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/login")
        .header(
            COOKIE,
            format!("{}={}", SESSION_COOKIE, &user.session_token),
        )
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(axum::body::Body::from(creds_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_adds_cookie(&response, ACCOUNT_COOKIE));
    let mut tx = state.db.begin().await.expect("begins");
    delete_test_account(&mut tx, &account).await;
    tx.commit().await.expect("commits");
}

#[tokio::test]
async fn registration_form() {
    let (router, _state) = init_test().await;
    let request = Request::builder()
        .uri("/register")
        .header(X_REAL_IP, LOCAL_IP)
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    let body_str = response_body_str(response).await;
    assert!(body_str.contains("Register"));
}

#[tokio::test]
async fn create_account() {
    let (router, state) = init_test().await;
    let user = test_user(None);
    let credentials = test_credentials(&user);
    let creds_str = serde_urlencoded::to_string(&credentials).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/register")
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(
            COOKIE,
            format!("{}={}", SESSION_COOKIE, &user.session_token),
        )
        .header(X_REAL_IP, LOCAL_IP)
        .body(axum::body::Body::from(creds_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_adds_cookie(&response, ACCOUNT_COOKIE));
    let mut tx = state.db.begin().await.expect("begins");
    let account = apabbs::user::Account::select_by_username(&mut tx, &credentials.username)
        .await
        .expect("query succeeds")
        .expect("account exists");
    delete_test_account(&mut tx, &account).await;
    tx.commit().await.expect("commits");
}

#[tokio::test]
async fn logout() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("commits");
    let logout = apabbs::router::auth::Logout {
        session_token: user.session_token,
    };
    let logout_str = serde_urlencoded::to_string(&logout).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/settings/logout")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(axum::body::Body::from(logout_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_removes_cookie(&response, ACCOUNT_COOKIE));
    let mut tx = state.db.begin().await.expect("begins");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
}

#[tokio::test]
async fn reset_account_token() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("commits");
    let logout = apabbs::router::auth::Logout {
        session_token: user.session_token,
    };
    let logout_str = serde_urlencoded::to_string(&logout).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/settings/reset-account-token")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(axum::body::Body::from(logout_str))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_removes_cookie(&response, ACCOUNT_COOKIE));
    let mut tx = state.db.begin().await.expect("begins");
    let updated_account = apabbs::user::Account::select_by_username(&mut tx, &account.username)
        .await
        .expect("query succeeds")
        .expect("account exists");
    assert_ne!(updated_account.token, account.token);
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
}
