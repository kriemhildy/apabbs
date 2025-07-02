//! User profile and settings integration tests.

mod helpers;

use apabbs::{
    router::helpers::{ACCOUNT_COOKIE, SESSION_COOKIE, X_REAL_IP},
    user::{Account, AccountRole, Credentials},
};
use axum::{
    body::Body,
    http::{
        Method, Request, StatusCode,
        header::{CONTENT_TYPE, COOKIE},
    },
};
use helpers::*;
use tower::ServiceExt;

/// Tests user profile page rendering.
#[tokio::test]
async fn user_profile() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");

    // Create a test user account
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("commits");

    // Request the user profile page
    let request = Request::builder()
        .uri(format!("/user/{}", &account.username))
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();

    // Verify response
    assert!(response.status().is_success());
    let body_str = response_body_str(response).await;
    assert!(body_str.contains(&account.username));

    // Clean up
    let mut tx = state.db.begin().await.expect("begins");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
}

/// Tests the settings page rendering and functionality.
#[tokio::test]
async fn settings() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");

    // Create a test user account
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("commits");

    // Request the settings page
    let request = Request::builder()
        .uri("/settings")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();

    // Verify response
    assert!(response.status().is_success());
    assert!(response_adds_cookie(&response, SESSION_COOKIE));
    let body_str = response_body_str(response).await;
    assert!(body_str.contains("Settings"));

    // Clean up
    let mut tx = state.db.begin().await.expect("begins");
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
}

/// Tests updating the user's time zone setting.
#[tokio::test]
async fn update_time_zone() {
    use apabbs::user::TimeZoneUpdate;

    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");

    // Create a test user account
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("commits");

    // Submit time zone update
    let time_zone_update = TimeZoneUpdate {
        session_token: user.session_token,
        time_zone: String::from("America/New_York"),
    };
    let time_zone_update_str = serde_urlencoded::to_string(&time_zone_update).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/settings/update-time-zone")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(time_zone_update_str))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Verify time zone was updated
    let mut tx = state.db.begin().await.expect("begins");
    let updated_account = Account::select_by_username(&mut tx, &account.username)
        .await
        .expect("query succeeds")
        .expect("account exists");
    assert_eq!(updated_account.time_zone, time_zone_update.time_zone);

    // Clean up
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
}

/// Tests updating the user's password.
#[tokio::test]
async fn update_password() {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await.expect("begins");

    // Create a test user account
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await.expect("commits");

    // Submit password update
    let credentials = Credentials {
        session_token: user.session_token,
        username: account.username.clone(),
        password: String::from("new_passw0rd"),
        confirm_password: Some(String::from("new_passw0rd")),
        year: Some("on".to_string()),
    };
    let credentials_str = serde_urlencoded::to_string(&credentials).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/settings/update-password")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(credentials_str))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Verify password was updated
    let mut tx = state.db.begin().await.expect("begins");
    let updated_account = Account::select_by_username(&mut tx, &account.username)
        .await
        .expect("query succeeds")
        .expect("account exists");
    assert!(
        credentials
            .authenticate(&mut tx)
            .await
            .expect("query succeeds")
            .is_some_and(|a| a.id == updated_account.id)
    );

    // Clean up
    delete_test_account(&mut tx, account).await;
    tx.commit().await.expect("commits");
}
