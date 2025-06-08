//! Core library functionality and shared utilities for the application.
//!
//! This module provides common constants, configuration helpers, and database
//! access functions used throughout the application.

pub mod ban;
pub mod post;
pub mod user;

use sqlx::PgPool;

/// Transaction beginning statement for database operations
pub const BEGIN: &str = "begin transaction";

/// Transaction commit statement for database operations
pub const COMMIT: &str = "commit transaction";

/// Format string for RFC5322-compliant datetime display in PostgreSQL
pub const POSTGRES_RFC5322_DATETIME: &str = "Dy, DD Mon YYYY HH24:MI:SS TZHTZM";

/// Format string for HTML datetime attribute format in PostgreSQL
pub const POSTGRES_HTML_DATETIME: &str = r#"YYYY-MM-DD"T"HH24:MI:SS.FF3TZH:TZM""#;

/// Creates a connection pool to the PostgreSQL database.
///
/// Uses the DATABASE_URL environment variable to establish a connection.
///
/// # Returns
/// A connection pool that can be used for database operations.
///
/// # Panics
/// Panics if the DATABASE_URL environment variable is not set or the connection fails.
pub async fn db() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("read DATABASE_URL env");
    PgPool::connect(&url).await.expect("connect postgres")
}

/// Returns the number of items to show per page.
///
/// Uses the PER_PAGE environment variable if set, otherwise defaults to 1000.
///
/// # Returns
/// The number of items per page.
pub fn per_page() -> usize {
    match std::env::var("PER_PAGE") {
        Ok(per_page) => per_page.parse().expect("parse PER_PAGE env"),
        Err(_) => 1000,
    }
}

/// Checks if the application is running in development mode.
///
/// Development mode is enabled when the DEV environment variable is set to "1".
///
/// # Returns
/// `true` if in development mode, `false` otherwise.
pub fn dev() -> bool {
    std::env::var("DEV").is_ok_and(|v| v == "1")
}

/// Returns the host domain name for the application.
///
/// Uses the HOST environment variable to determine the application's domain.
///
/// # Returns
/// The application's host domain name.
///
/// # Panics
/// Panics if the HOST environment variable is not set.
pub fn host() -> String {
    std::env::var("HOST").expect("read HOST env")
}

/// Retrieves the application's secret key for secure operations.
///
/// The secret key is used for encryption, cookie signing, and other security features.
///
/// # Returns
/// The application's secret key.
///
/// # Panics
/// Panics if the SECRET_KEY environment variable is not set.
pub fn secret_key() -> String {
    std::env::var("SECRET_KEY").expect("read SECRET_KEY env")
}
