//! Anonymous Pre-Approval Bulletin Board System (APABBS)
//! -----------------------------------------------------
//!
//! The general philosophy of this forum system is that moderation of posts after
//! they are published is a bad strategy. Trolls are usually content to get their
//! message heard even if it comes at the cost of their (temporary) ban.
//!
//! Thus the only way to really allow anonymous conversation is to review every
//! single post prior to its publication. [Only this will ensure that the fullness
//! of the varied experience of the moderator will not go to waste.]

pub mod ban;
pub mod cron;
pub mod post;
pub mod router;
pub mod user;

use crate::post::Post;
use minijinja::Environment;
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast::Sender;

/// Format string for RFC 5322-style datetime in PostgreSQL queries.
pub const POSTGRES_RFC5322_DATETIME: &str = "Dy, DD Mon YYYY HH24:MI:SS TZHTZM";

/// Format string for HTML5 datetime attribute in PostgreSQL queries.
pub const POSTGRES_HTML_DATETIME: &str = r#"YYYY-MM-DD\"T\"HH24:MI:SS.FF3TZH:TZM"#;

/// Format string for UTC hour granularity in PostgreSQL queries.
pub const POSTGRES_UTC_HOUR: &str = "YYYY-MM-DD-HH24";

/// Creates a connection pool to the PostgreSQL database.
///
/// Uses the `DATABASE_URL` environment variable to establish a connection.
///
/// # Panics
/// Panics if `DATABASE_URL` is not set or the connection fails.
pub async fn db() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL environment variable must be set for database connection");
    PgPool::connect(&url)
        .await
        .expect("Failed to connect to PostgreSQL database")
}

/// Returns the number of items to show per page.
///
/// Uses the `PER_PAGE` environment variable if set, otherwise defaults to 1000.
///
/// # Panics
/// Panics if `PER_PAGE` is set but not a valid integer.
pub fn per_page() -> usize {
    match std::env::var("PER_PAGE") {
        Ok(per_page) => per_page
            .parse()
            .expect("PER_PAGE environment variable must be a valid integer"),
        Err(_) => 1000,
    }
}

/// Checks if the application is running in development mode.
///
/// Development mode is enabled when the `DEV` environment variable is set to "1".
pub fn dev() -> bool {
    std::env::var("DEV").is_ok_and(|v| v == "1")
}

/// Returns the host domain name for the application.
///
/// Uses the `HOST` environment variable.
///
/// # Panics
/// Panics if `HOST` is not set.
pub fn host() -> String {
    std::env::var("HOST").expect("HOST environment variable must be set for host name")
}

/// Retrieves the application's secret key for secure operations.
///
/// The secret key is used for encryption, cookie signing, and other security features.
///
/// # Panics
/// Panics if `SECRET_KEY` is not set.
pub fn secret_key() -> String {
    std::env::var("SECRET_KEY").expect("SECRET_KEY environment variable must be set for security")
}

/// Shared application state accessible to all request handlers.
///
/// Contains database connections, template rendering engine,
/// and event broadcasting channels.
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    pub db: PgPool,
    /// Template rendering environment with filters and loaders
    pub jinja: Arc<RwLock<Environment<'static>>>,
    /// Broadcast channel for real-time updates
    pub sender: Arc<Sender<Post>>,
}

/// Initializes the application state.
///
/// Sets up database connections, configures template rendering,
/// and creates a broadcast channel for real-time updates.
///
/// # Returns
/// Configured application state ready for use by request handlers.
pub async fn app_state() -> AppState {
    // Initialize database connection pool
    let db = db().await;

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
            .expect("Failed to build regex for removing YouTube thumbnail links");

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
