//! Authentication and account-related integration tests.

mod helpers;

use apabbs::{
    router::{
        auth::Logout,
        helpers::{ACCOUNT_COOKIE, SESSION_COOKIE, X_REAL_IP},
    },
    user::{Account, AccountRole},
};
use axum::{
    body::Body,
    http::{
        Method, Request, StatusCode,
        header::{CONTENT_TYPE, COOKIE},
    },
};
use helpers::{
    LOCAL_IP, create_test_account, delete_test_account, init_test, local_ip_hash,
    response_adds_cookie, response_body_str, response_removes_cookie, test_credentials, test_user,
};
use std::error::Error;
use tower::ServiceExt;

use crate::helpers::APPLICATION_WWW_FORM_URLENCODED;

/// Tests the login form page rendering.
#[tokio::test]
async fn login_form() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (router, _state) = init_test().await;
    let request = Request::builder()
        .uri("/login")
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;

    assert!(response.status().is_success());
    let body_str = response_body_str(response).await;
    assert!(body_str.contains("Log in"));
    Ok(())
}

/// Tests user authentication with valid credentials.
#[tokio::test]
async fn authenticate() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (router, state) = init_test().await;

    // Create test account
    let mut tx = state.db.begin().await?;
    let user = test_user(None);
    let credentials = test_credentials(&user);
    let account = credentials.register(&mut tx, &local_ip_hash()).await?;
    tx.commit().await?;

    // Attempt login
    let creds_str = serde_urlencoded::to_string(&credentials)?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(
            COOKIE,
            format!("{}={}", SESSION_COOKIE, &user.session_token),
        )
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(creds_str))?;

    let response = router.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_adds_cookie(&response, ACCOUNT_COOKIE));

    // Clean up
    let mut tx = state.db.begin().await?;
    delete_test_account(&mut tx, &account).await;
    tx.commit().await?;
    Ok(())
}

/// Tests the account registration form page.
#[tokio::test]
async fn registration_form() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (router, _state) = init_test().await;
    let request = Request::builder()
        .uri("/register")
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::empty())?;

    let response = router.oneshot(request).await?;
    assert!(response.status().is_success());

    let body_str = response_body_str(response).await;
    assert!(body_str.contains("Register"));
    Ok(())
}

/// Tests creating a new user account.
#[tokio::test]
async fn create_account() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (router, state) = init_test().await;
    let user = test_user(None);
    let credentials = test_credentials(&user);

    // Submit registration
    let creds_str = serde_urlencoded::to_string(&credentials)?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/register")
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(
            COOKIE,
            format!("{}={}", SESSION_COOKIE, &user.session_token),
        )
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(creds_str))?;

    let response = router.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_adds_cookie(&response, ACCOUNT_COOKIE));

    // Verify account was created
    let mut tx = state.db.begin().await?;
    let account = Account::select_by_username(&mut tx, &credentials.username)
        .await?
        .unwrap();

    // Clean up
    delete_test_account(&mut tx, &account).await;
    tx.commit().await?;
    Ok(())
}

/// Tests logging out from a user account.
#[tokio::test]
async fn logout() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (router, state) = init_test().await;

    // Create test account
    let mut tx = state.db.begin().await?;
    let user = create_test_account(&mut tx, AccountRole::Novice).await?;
    let account = user.account.as_ref().unwrap();
    tx.commit().await?;

    // Submit logout request
    let logout = Logout {
        session_token: user.session_token,
    };
    let logout_str = serde_urlencoded::to_string(&logout)?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/settings/logout")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(logout_str))?;

    let response = router.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_removes_cookie(&response, ACCOUNT_COOKIE));

    // Clean up
    let mut tx = state.db.begin().await?;
    delete_test_account(&mut tx, account).await;
    tx.commit().await?;
    Ok(())
}

/// Tests resetting the account token.
#[tokio::test]
async fn reset_account_token() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (router, state) = init_test().await;

    // Create test account
    let mut tx = state.db.begin().await?;
    let user = create_test_account(&mut tx, AccountRole::Novice).await?;
    let account = user.account.as_ref().unwrap();
    tx.commit().await?;

    // Submit token reset request
    let logout = Logout {
        session_token: user.session_token,
    };
    let logout_str = serde_urlencoded::to_string(&logout)?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/settings/reset-account-token")
        .header(COOKIE, format!("{}={}", ACCOUNT_COOKIE, account.token))
        .header(COOKIE, format!("{}={}", SESSION_COOKIE, user.session_token))
        .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
        .header(X_REAL_IP, LOCAL_IP)
        .body(Body::from(logout_str))?;

    let response = router.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response_removes_cookie(&response, ACCOUNT_COOKIE));

    // Verify token was updated
    let mut tx = state.db.begin().await?;
    let updated_account = Account::select_by_username(&mut tx, &account.username)
        .await?
        .unwrap();
    assert_ne!(updated_account.token, account.token);

    // Clean up
    delete_test_account(&mut tx, account).await;
    tx.commit().await?;
    Ok(())
}
