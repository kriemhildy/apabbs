//! User profile and settings integration tests.

mod helpers;

use apabbs::router::helpers::{ACCOUNT_COOKIE, SESSION_COOKIE, X_REAL_IP};
use apabbs::user::AccountRole;
use axum::http::{Request, header::COOKIE};
use helpers::*;
use tower::ServiceExt;

#[tokio::test]
async fn user_profile() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("commits");
    let request = Request::builder()
        .uri(format!("/user/{}", &account.username))
        .header(X_REAL_IP, LOCAL_IP)
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    let body_str = response_body_str(response).await;
    assert!(body_str.contains(&account.username));
    let mut tx = state.db.begin().await.expect("begins");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
}

#[tokio::test]
async fn settings() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("commits");
    let request = Request::builder()
        .uri("/settings")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(X_REAL_IP, LOCAL_IP)
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert!(response.status().is_success());
    assert!(response_adds_cookie(&response, SESSION_COOKIE));
    let body_str = response_body_str(response).await;
    assert!(body_str.contains("Settings"));
    let mut tx = state.db.begin().await.expect("begins");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
}
