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
use helpers::{
    APPLICATION_WWW_FORM_URLENCODED, LOCAL_IP, create_test_account, delete_test_account, init_test,
    response_adds_cookie, response_body_str,
};
use std::error::Error;
use tower::ServiceExt;

/// Tests user profile page rendering.
#[tokio::test]
async fn user_profile() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await?;

    // Create a test user account
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await?;

    // Request the user profile page
    let request = Request::builder()
        .uri(format!("/user/{}", &account.username))
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;

    // Verify response
    assert!(response.status().is_success());
    let body_str = response_body_str(response).await;
    assert!(body_str.contains(&account.username));

    // Clean up
    let mut tx = state.db.begin().await?;
    delete_test_account(&mut tx, account).await;
    tx.commit().await?;
    Ok(())
}

/// Tests the settings page rendering and functionality.
#[tokio::test]
async fn settings() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await?;

    // Create a test user account
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await?;

    // Request the settings page
    let request = Request::builder()
        .uri("/settings")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;

    // Verify response
    assert!(response.status().is_success());
    assert!(response_adds_cookie(&response, SESSION_COOKIE));
    let body_str = response_body_str(response).await;
    assert!(body_str.contains("Settings"));

    // Clean up
    let mut tx = state.db.begin().await?;
    delete_test_account(&mut tx, account).await;
    tx.commit().await?;
    Ok(())
}

/// Tests updating the user's time zone setting.
#[tokio::test]
async fn update_time_zone() -> Result<(), Box<dyn Error + Send + Sync>> {
    use apabbs::user::TimeZoneUpdate;

    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await?;

    // Create a test user account
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await?;

    // Submit time zone update
    let time_zone_update = TimeZoneUpdate {
        session_token: user.session_token,
        time_zone: String::from("America/New_York"),
    };
    let time_zone_update_str = serde_urlencoded::to_string(&time_zone_update)?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/settings/update-time-zone")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(time_zone_update_str))?;

    let response = router.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Verify time zone was updated
    let mut tx = state.db.begin().await?;
    let updated_account = Account::select_by_username(&mut tx, &account.username)
        .await?
        .unwrap();
    assert_eq!(updated_account.time_zone, time_zone_update.time_zone);

    // Clean up
    delete_test_account(&mut tx, account).await;
    tx.commit().await?;
    Ok(())
}

/// Tests updating the user's password.
#[tokio::test]
async fn update_password() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (router, state) = init_test().await;
    let mut tx = state.db.begin().await?;

    // Create a test user account
    let user = create_test_account(&mut tx, AccountRole::Novice).await;
    let account = user.account.as_ref().unwrap();
    tx.commit().await?;

    // Submit password update
    let credentials = Credentials {
        session_token: user.session_token,
        username: account.username.clone(),
        password: String::from("new_passw0rd"),
        confirm_password: Some(String::from("new_passw0rd")),
        year: Some("on".to_string()),
    };
    let credentials_str = serde_urlencoded::to_string(&credentials)?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/settings/update-password")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(credentials_str))?;

    let response = router.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Verify password was updated
    let mut tx = state.db.begin().await?;
    let updated_account = Account::select_by_username(&mut tx, &account.username)
        .await?
        .unwrap();
    assert!(
        credentials
            .authenticate(&mut tx)
            .await?
            .is_some_and(|a| a.id == updated_account.id)
    );

    // Clean up
    delete_test_account(&mut tx, account).await;
    tx.commit().await?;
    Ok(())
}
