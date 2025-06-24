//! Web application routing and request handling.
//!
//! This module defines the main router configuration for the web application.
//! It includes routes for public content, user authentication, account management,
//! content moderation, and real-time updates. Middleware layers such as tracing
//! and body size limits are also applied here.

//==================================================================================================
// Modules
//==================================================================================================

pub mod auth;
pub mod helpers;
pub mod moderation;
pub mod posts;
pub mod profile;
#[cfg(test)]
pub mod tests;

//==================================================================================================
// Imports
//==================================================================================================

use crate::AppState;
use crate::{ban, post::*, user::*};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{
        Method, StatusCode,
        header::{CONTENT_DISPOSITION, CONTENT_TYPE, HeaderMap},
    },
    response::{Form, Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use helpers::*;
use std::error::Error;
use std::{future::Future, pin::Pin};
use uuid::Uuid;

//==================================================================================================
// Constants
//==================================================================================================

/// Root path for the application.
pub const ROOT: &str = "/";

//==================================================================================================
// Error Handling
//==================================================================================================

/// Custom error type for application errors.
#[derive(Debug)]
pub enum ResponseError {
    InternalServerError(String),
    NotFound(String),
    Unauthorized(String),
    Forbidden(String),
    BadRequest(String),
    Banned(String),
}

use ResponseError::*;

/// Convert an `sqlx::Error` into a `ResponseError`.
impl From<sqlx::Error> for ResponseError {
    fn from(error: sqlx::Error) -> Self {
        ResponseError::InternalServerError(error.to_string())
    }
}

impl From<Box<dyn Error>> for ResponseError {
    fn from(error: Box<dyn Error>) -> Self {
        ResponseError::InternalServerError(error.to_string())
    }
}

/// Convert a `ResponseError` into an HTTP response.
impl IntoResponse for ResponseError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Banned(expires_at_str) => (
                StatusCode::FORBIDDEN,
                format!("Banned until {expires_at_str}"),
            ),
        };

        (status, body).into_response()
    }
}

//==================================================================================================
// Type Aliases
//==================================================================================================

/// Type alias for boxed background task futures.
pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

//==================================================================================================
// Router Configuration
//==================================================================================================

/// Configures the application router with routes and middleware.
pub fn router(state: AppState, trace: bool) -> axum::Router {
    use axum::routing::{get, post};

    let router = axum::Router::new()
        // Public content routes
        .route("/", get(posts::index))
        .route("/page/{key}", get(posts::index))
        .route("/post/{key}", get(posts::solo_post))
        .route("/p/{key}", get(posts::solo_post))
        .route("/{key}", get(posts::solo_post))
        // Content creation and interaction
        .route("/submit-post", post(posts::submit_post))
        .route("/hide-post", post(posts::hide_post))
        .route("/interim/{key}", get(posts::interim))
        // Authentication and account management
        .route("/login", get(auth::login_form).post(auth::authenticate))
        .route(
            "/register",
            get(auth::registration_form).post(auth::create_account),
        )
        .route("/user/{username}", get(profile::user_profile))
        .route("/settings", get(profile::settings))
        .route("/settings/logout", post(auth::logout))
        .route(
            "/settings/reset-account-token",
            post(auth::reset_account_token),
        )
        .route(
            "/settings/update-time-zone",
            post(profile::update_time_zone),
        )
        .route("/settings/update-password", post(profile::update_password))
        // Real-time updates
        .route("/web-socket", get(posts::web_socket))
        // Moderation features
        .route("/review/{key}", post(moderation::review_post))
        .route("/decrypt-media/{key}", get(moderation::decrypt_media))
        // File size limit for uploads
        .layer(DefaultBodyLimit::max(20_000_000));

    let router = if trace {
        use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
        use tracing::Level;

        let trace_layer = TraceLayer::new_for_http()
            .make_span_with(DefaultMakeSpan::new().level(Level::DEBUG))
            .on_response(DefaultOnResponse::new().level(Level::DEBUG));
        router.layer(trace_layer)
    } else {
        router
    };

    router.with_state(state)
}
