//! Application entry point and server initialization.
//!
//! This module sets up the web server, configures template rendering,
//! initializes background tasks, and manages application state.

mod cron;
mod router;

use apabbs::post::Post;
use minijinja::Environment;
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast::Sender;

/// Shared application state accessible to all request handlers.
///
/// Contains database connections, template rendering engine,
/// and event broadcasting channels.
#[derive(Clone)]
struct AppState {
    /// Database connection pool
    db: PgPool,
    /// Template rendering environment with filters and loaders
    jinja: Arc<RwLock<Environment<'static>>>,
    /// Broadcast channel for real-time updates
    sender: Arc<Sender<Post>>,
}

/// Initializes the application state.
///
/// Sets up database connections, configures template rendering,
/// and creates a broadcast channel for real-time updates.
///
/// # Returns
/// Configured application state ready for use by request handlers.
async fn app_state() -> AppState {
    // Initialize database connection pool
    let db = apabbs::db().await;

    // Configure template rendering environment
    let jinja = {
        use regex::Regex;
        let mut env = Environment::new();

        // Configure template loading and rendering options
        env.set_loader(minijinja::path_loader("templates"));
        env.set_keep_trailing_newline(true);
        env.set_lstrip_blocks(true);
        env.set_trim_blocks(true);

        // Template filter to remove link wrappers from YouTube thumbnails
        fn remove_youtube_thumbnail_links(body: &str) -> String {
            let re = Regex::new(concat!(
                r#"<a href="/p/\w{8,}"><img src="/youtube/([\w\-]{11})/(\w{4,}).jpg" "#,
                r#"alt="Post \w{8,}" width="(\d+)" height="(\d+)"></a>"#
            ))
            .expect("regex builds");

            re.replace_all(
                body,
                concat!(
                    r#"<img src="/youtube/$1/$2.jpg" alt="YouTube thumbnail $1" "#,
                    r#"width="$3" height="$4">"#,
                ),
            )
            .to_string()
        }
        env.add_filter(
            "remove_youtube_thumbnail_links",
            remove_youtube_thumbnail_links,
        );

        // Template filter to slice a string to a specific byte length
        fn byte_slice(body: &str, end: usize) -> String {
            // Ensure we don't exceed the string length
            let end = end.min(body.len());
            body[..end].to_owned()
        }
        env.add_filter("byte_slice", byte_slice);

        Arc::new(RwLock::new(env))
    };

    // Create broadcast channel for real-time updates
    let sender = Arc::new(tokio::sync::broadcast::channel(100).0);

    AppState { db, jinja, sender }
}

/// Application entry point.
///
/// Sets up the environment, initializes application state,
/// configures the HTTP server, and starts listening for requests.
#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    if let Err(error) = dotenv::dotenv() {
        eprintln!("Error loading .env file: {}", error);
        std::process::exit(1);
    }

    // Validate critical configuration
    if apabbs::secret_key().len() < 16 {
        panic!("SECRET_KEY env must be at least 16 chars");
    }

    // Initialize background tasks and scheduled jobs
    cron::init().await;

    // Initialize application state
    let state = app_state().await;

    // Configure router with request handlers
    let router = router::router(state, true);

    // Determine server port from environment or use default
    let port = match std::env::var("PORT") {
        Ok(port) => port.parse().expect("parse PORT env"),
        Err(_) => 7878,
    };

    // Bind server to network address
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect(&format!("listen on port {port}"));

    println!("Server listening on port {port}");

    // Start HTTP server
    axum::serve(listener, router)
        .await
        .expect("server terminated unexpectedly");
}
