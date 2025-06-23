//! Core library functionality and shared utilities for the application.
//!
//! Provides constants, configuration helpers, and database access functions used throughout the app.

pub mod ban;
pub mod post;
pub mod user;

use sqlx::PgPool;

// Error messages for database operations
pub const BEGIN_FAILED_ERR: &str = "Failed to begin database transaction";
pub const COMMIT_FAILED_ERR: &str = "Failed to commit database transaction";

// PostgreSQL datetime format strings
pub const POSTGRES_RFC5322_DATETIME: &str = "Dy, DD Mon YYYY HH24:MI:SS TZHTZM";
pub const POSTGRES_HTML_DATETIME: &str = r#"YYYY-MM-DD\"T\"HH24:MI:SS.FF3TZH:TZM""#;
pub const POSTGRES_UTC_HOUR: &str = "YYYY-MM-DD-HH24";

/// Create a connection pool to the PostgreSQL database.
///
/// Uses the `DATABASE_URL` environment variable to establish a connection.
///
/// # Panics
/// Panics if `DATABASE_URL` is not set or the connection fails.
pub async fn db() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL environment variable must be set");
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
        Ok(per_page) => per_page.parse().expect("PER_PAGE must be a valid integer"),
        Err(_) => 1000,
    }
}

/// Checks if the application is running in development mode.
///
/// Development mode is enabled when the `DEV` environment variable is set to "1".
pub fn dev() -> bool {
    std::env::var("DEV").map_or(false, |v| v == "1")
}

/// Returns the host domain name for the application.
///
/// Uses the `HOST` environment variable.
///
/// # Panics
/// Panics if `HOST` is not set.
pub fn host() -> String {
    std::env::var("HOST").expect("HOST environment variable must be set")
}

/// Retrieves the application's secret key for secure operations.
///
/// The secret key is used for encryption, cookie signing, and other security features.
///
/// # Panics
/// Panics if `SECRET_KEY` is not set.
pub fn secret_key() -> String {
    std::env::var("SECRET_KEY").expect("SECRET_KEY environment variable must be set")
}
