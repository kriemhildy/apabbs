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

// ==============================================================================
// Module Declarations
// ==============================================================================

pub mod ban;
pub mod cron;
pub mod post;
pub mod router;
pub mod user;

// ==============================================================================
// Imports
// ==============================================================================

use crate::post::Post;
use minijinja::Environment;
use sqlx::PgPool;
use std::{
    pin::Pin,
    sync::{Arc, RwLock},
};
use tokio::sync::broadcast::Sender;

// ==============================================================================
// Constants
// ==============================================================================

/// Format string for RFC 5322-style datetime in PostgreSQL queries.
pub const POSTGRES_RFC5322_DATETIME: &str = "Dy, DD Mon YYYY HH24:MI:SS TZHTZM";

/// Format string for HTML5 datetime attribute in PostgreSQL queries.
pub const POSTGRES_HTML_DATETIME: &str = r#"YYYY-MM-DD\"T\"HH24:MI:SS.FF3TZH:TZM"#;

/// Format string for UTC hour granularity in PostgreSQL queries.
pub const POSTGRES_UTC_HOUR: &str = "YYYY-MM-DD-HH24";

//==================================================================================================
// Type Aliases
//==================================================================================================

/// Type alias for boxed background task futures.
pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

// ==============================================================================
// Environment/Config Functions
// ==============================================================================

/// Creates a connection pool to the PostgreSQL database.
pub async fn db() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("sets database env var");
    PgPool::connect(&url).await.expect("connects to postgres")
}

/// Returns the number of items to show per page.
pub fn per_page() -> usize {
    match std::env::var("PER_PAGE") {
        Ok(per_page) => per_page.parse().expect("per_page env var is integer"),
        Err(_) => 1000,
    }
}

/// Checks if the application is running in development mode.
pub fn dev() -> bool {
    std::env::var("DEV").is_ok_and(|v| v == "1")
}

/// Returns the host domain name for the application.
pub fn host() -> String {
    std::env::var("HOST").expect("sets host env var")
}

/// Retrieves the application's secret key for secure operations.
///
/// The secret key is used for encryption, cookie signing, and other security features.
pub fn secret_key() -> String {
    std::env::var("SECRET_KEY").expect("sets secret key env var")
}

// ==============================================================================
// Application State
// ==============================================================================

/// Shared application state accessible to all request handlers.
///
/// Contains database connections, template rendering engine, and event broadcasting channels.
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
/// Sets up database connections, configures template rendering, and creates a broadcast channel for real-time updates.
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

        /// Removes anchor link wrappers from YouTube thumbnail images in post bodies.
        fn remove_youtube_thumbnail_links(body: &str) -> String {
            let re = Regex::new(concat!(
                r#"<a href="/p/\w{8,}"><img src="/youtube/([\w\-]{11})/(\w{4,}).jpg" "#,
                r#"alt="Post \w{8,}" width="(\d+)" height="(\d+)"></a>"#
            ))
            .expect("builds regex");

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

        /// Template filter to slice a string to a specific byte length.
        fn byte_slice(body: &str, end: usize) -> String {
            // Ensure we don't exceed the string length
            let end = end.min(body.len());
            body[..end].to_string()
        }
        env.add_filter("byte_slice", byte_slice);

        Arc::new(RwLock::new(env))
    };

    // Create broadcast channel for real-time updates
    let sender = Arc::new(tokio::sync::broadcast::channel(100).0);

    AppState { db, jinja, sender }
}

mod utils {
    use super::*;
    use sqlx::{Postgres, Transaction};
    use std::error::Error;
    //==================================================================================================
    // Database transactions
    //==================================================================================================

    /// Begin a new database transaction.
    pub async fn begin_transaction(
        db: &PgPool,
    ) -> Result<Transaction<'_, Postgres>, Box<dyn Error + Send + Sync>> {
        db.begin()
            .await
            .map_err(|e| format!("failed to begin database transaction: {e}").into())
    }

    /// Commit a database transaction.
    pub async fn commit_transaction(
        tx: Transaction<'_, Postgres>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        tx.commit()
            .await
            .map_err(|e| format!("failed to commit transaction: {e}").into())
    }

    //==================================================================================================
    // WebSocket utilities
    //==================================================================================================

    /// Send a message to a WebSocket connection.
    pub fn send_to_websocket(sender: &Sender<Post>, post: Post) {
        if let Err(e) = sender.send(post) {
            tracing::warn!("No active WebSocket receivers to send to: {e}");
        }
    }
}

// ==============================================================================
// Test Initialization
// ==============================================================================

// Ensure we are in development mode before running tests.
#[cfg(test)]
#[ctor::ctor]
fn init() {
    if !dev() {
        eprintln!("Only run tests in development mode (DEV=1)");
        std::process::exit(1);
    }
}

// Initializes tracing for tests to capture logs and output them to the console.
#[cfg(test)]
fn init_tracing_for_test() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .init();
    });
}
