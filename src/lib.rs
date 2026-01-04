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
pub mod utils;

// ==============================================================================
// Imports
// ==============================================================================

use crate::{post::Post, user::Account};
use minijinja::Environment;
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast::Sender;

// ==============================================================================
// Environment/Config Functions
// ==============================================================================

/// Returns the number of items to show per page.
pub fn per_page() -> usize {
    match std::env::var("PER_PAGE") {
        Ok(per_page) => per_page
            .parse()
            .expect("Parse PER_PAGE environment variable as integer"),
        Err(_) => 500,
    }
}

/// Checks if the application is running in development mode.
pub fn dev() -> bool {
    std::env::var("DEV").is_ok_and(|v| v == "1")
}

/// Returns the production hostname for the application.
pub fn prod_host() -> String {
    std::env::var("PROD_HOST").expect("Read PROD_HOST environment variable")
}

/// Retrieves the application's secret key for secure operations.
///
/// The secret key is used for encryption, cookie signing, and other security features.
pub fn secret_key() -> String {
    std::env::var("SECRET_KEY").expect("Read SECRET_KEY environment variable")
}

// ==============================================================================
// Application State
// ==============================================================================

/// Represents a message in the application, which can be either a post or an account message.
#[derive(Clone)]
pub enum AppMessage {
    /// Represents a post message in the application.
    Post(Post),
    /// Represents an account message in the application.
    Account(Account),
}

/// Shared application state accessible to all request handlers.
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    pub db: PgPool,
    /// Template rendering environment with filters and loaders
    pub jinja: Arc<RwLock<Environment<'static>>>,
    /// Broadcast channel for real-time updates
    pub sender: Arc<Sender<AppMessage>>,
}

/// Initializes the application state.
pub async fn init_app_state() -> AppState {
    AppState {
        db: init_db().await,
        jinja: init_jinja(),
        sender: init_sender(),
    }
}

/// Creates a connection pool to the PostgreSQL database.
pub async fn init_db() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("Read DATABASE_URL environment variable");
    PgPool::connect(&url).await.expect("Connect to PostgreSQL")
}

/// Initializes the template rendering environment with filters and loaders.
pub fn init_jinja() -> Arc<RwLock<Environment<'static>>> {
    use utils::{byte_slice, unlink_youtube_thumbnails};

    let mut env = Environment::new();

    // Configure template loading and rendering options
    env.set_loader(minijinja::path_loader("templates"));
    env.set_keep_trailing_newline(true);
    env.set_lstrip_blocks(true);
    env.set_trim_blocks(true);
    env.add_filter("unlink_youtube_thumbnails", unlink_youtube_thumbnails);
    env.add_filter("byte_slice", byte_slice);

    Arc::new(RwLock::new(env))
}

/// Initializes the broadcast channel for real-time updates.
pub fn init_sender() -> Arc<Sender<AppMessage>> {
    Arc::new(tokio::sync::broadcast::channel(100).0)
}

// ==============================================================================
// Test Initialization
// ==============================================================================

/// Ensure we are in development mode before running tests.
#[cfg(test)]
#[ctor::ctor]
fn ensure_dev() {
    if !dev() {
        eprintln!("Only run tests in development mode (DEV=1)");
        std::process::exit(1);
    }
}

/// Initializes tracing for tests to capture logs and output them to the console.
pub fn init_tracing_for_test() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .init();
    });
}
