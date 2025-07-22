//! Web application routing and request handling.
//!
//! This module defines the main router configuration for the web application.
//! It includes routes for public content, user authentication, account management,
//! content moderation, and real-time updates. Middleware layers such as tracing
//! and body size limits are also applied here.

pub mod auth;
pub mod errors;
pub mod helpers;
pub mod moderation;
pub mod posts;
pub mod profile;
pub mod websocket;

use crate::AppState;

/// Root path for the application.
pub const ROOT: &str = "/";

/// Configures the application router with routes and middleware.
pub fn init_router(state: AppState, trace: bool) -> axum::Router {
    use auth;
    use axum::{
        extract::DefaultBodyLimit,
        routing::{get, post},
    };
    use moderation;
    use posts;
    use profile;
    use websocket;

    let router = axum::Router::new()
        // Public content routes
        .route(ROOT, get(posts::index))
        .route("/page/{key}", get(posts::index))
        .route("/post/{key}", get(posts::solo_post))
        .route("/p/{key}", get(posts::solo_post))
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
        .route("/web-socket", get(websocket::web_socket))
        // Moderation features
        .route("/review-post/{key}", post(moderation::review_post))
        .route("/decrypt-media/{key}", get(moderation::decrypt_media))
        .route("/review-account", post(moderation::review_account))
        // File size limit for uploads
        .layer(DefaultBodyLimit::max(26_214_400)); // 25 MiB

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
