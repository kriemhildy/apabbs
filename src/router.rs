//! Web application routing and request handling.
//!
//! This module defines all HTTP routes and handlers for the application,
//! implementing core functionality such as post management, user authentication,
//! content moderation, and real-time updates via WebSockets.

mod auth;
mod helpers;
mod moderation;
mod posts;
mod profile;
#[cfg(test)]
mod tests;

use crate::AppState;
use apabbs::{BEGIN, COMMIT, ban, post::*, user::*};
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
use std::future::Future;
use std::pin::Pin;
use uuid::Uuid;

/// Root path for the application
const ROOT: &str = "/";

/// Type alias for background task futures
///
/// Used for tasks that need to run asynchronously after a request completes,
/// such as media processing operations.
type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

//==================================================================================================
/// URL path router
//==================================================================================================

/// Configures the application router with all available routes
///
/// Creates and returns a router configured with all endpoints and middleware.
///
/// # Parameters
/// - `state`: Application state accessible to all handlers
/// - `trace`: Whether to enable request/response tracing for debugging
///
/// # Returns
/// Configured router ready to serve requests
pub fn router(state: AppState, trace: bool) -> axum::Router {
    use axum::routing::{get, post};

    // Define all routes with their respective handlers
    let router = axum::Router::new()
        // Public content routes
        .route("/", get(posts::index))
        .route("/page/{key}", get(posts::index))
        .route("/post/{key}", get(posts::solo_post))
        .route("/p/{key}", get(posts::solo_post))
        .route("/{key}", get(posts::solo_post)) // temporary for backwards compatibility
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
        .layer(DefaultBodyLimit::max(20_000_000)); // 20MB limit

    // Apply tracing middleware if enabled
    let router = if trace {
        let trace_layer = {
            use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
            use tracing::Level;

            // Initialize tracing with debug level
            tracing_subscriber::fmt()
                .with_max_level(Level::DEBUG)
                .try_init()
                .expect("initialize tracing");

            // Configure trace layer
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::DEBUG))
                .on_response(DefaultOnResponse::new().level(Level::DEBUG))
        };
        router.layer(trace_layer)
    } else {
        router
    };

    // Attach application state
    router.with_state(state)
}
