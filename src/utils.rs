//! General utility functions and constants for database, rendering, and time handling.
//!
//! This module provides helpers for database transactions, WebSocket messaging,
//! template rendering, and time/date formatting used throughout the application.

use crate::{AppState, post::Post};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use std::error::Error;
use tokio::sync::broadcast::Sender;

// ==============================================================================
// Constants
// ==============================================================================

/// Format string for RFC 5322-style datetime in PostgreSQL queries.
pub const POSTGRES_RFC5322_DATETIME: &str = "Dy, DD Mon YYYY HH24:MI:SS TZHTZM";

/// Format string for HTML5 datetime attribute in PostgreSQL queries.
pub const POSTGRES_HTML_DATETIME: &str = r#"YYYY-MM-DD"T"HH24:MI:SS.FF3TZH:TZM"#;

/// Format string for UTC hour granularity in PostgreSQL queries.
pub const POSTGRES_UTC_HOUR: &str = "YYYY-MM-DD-HH24";

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

//==================================================================================================
// Templating and Rendering
//==================================================================================================

/// Render a template with the given context using the application's Jinja environment.
pub fn render(
    state: &AppState,
    name: &str,
    ctx: minijinja::value::Value,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    if crate::dev() {
        let mut env = state
            .jinja
            .write()
            .map_err(|e| format!("failed to acquire write lock for template \"{name}\": {e}"))?;
        env.clear_templates();
    }
    let env = state
        .jinja
        .read()
        .map_err(|e| format!("failed to acquire read lock for template \"{name}\": {e}"))?;
    let tmpl = env.get_template(name).map_err(|e| {
        Box::<dyn Error + Send + Sync>::from(format!("failed to get template \"{name}\": {e}"))
    })?;
    tmpl.render(ctx)
        .map_err(|e| format!("failed to render template \"{name}\": {e}").into())
}

/// Removes anchor link wrappers from YouTube thumbnail images in post bodies.
pub fn unlink_youtube_thumbnails(body: &str) -> String {
    use regex::Regex;

    let re = Regex::new(concat!(
        r#"<a href="/p/\w{8,}"><img src="/youtube/([\w\-]{11})/(\w{4,}).jpg" "#,
        r#"alt="Post \w{8,}" width="(\d+)" height="(\d+)"></a>"#
    ))
    .expect("Build regular expression");

    re.replace_all(
        body,
        concat!(
            r#"<img src="/youtube/$1/$2.jpg" alt="YouTube thumbnail $1" "#,
            r#"width="$3" height="$4">"#,
        ),
    )
    .to_string()
}

/// Template filter to slice a string to a specific byte length.
pub fn byte_slice(body: &str, end: usize) -> String {
    // Ensure we don't exceed the string length
    let end = end.min(body.len());
    body[..end].to_string()
}

//==================================================================================================
// Time and Date Utilities
//==================================================================================================

/// Set the PostgreSQL session time zone for the current connection.
pub async fn set_session_time_zone(
    tx: &mut PgConnection,
    time_zone: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    sqlx::query(&format!("SET TIME ZONE '{time_zone}'"))
        .execute(&mut *tx)
        .await
        .map(|_| ())
        .map_err(|e| format!("failed to set session time zone: {e}").into())
}

/// Generate a UTC timestamp string for the current hour.
pub async fn utc_hour_timestamp(
    tx: &mut PgConnection,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    sqlx::query_scalar("SELECT to_char(current_timestamp AT TIME ZONE 'UTC', $1)")
        .bind(POSTGRES_UTC_HOUR)
        .fetch_one(tx)
        .await
        .map_err(|e| format!("failed to get UTC hour timestamp: {e}").into())
}

//==================================================================================================
// Tests
//==================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unlink_youtube_thumbnails() {
        let input = concat!(
            r#"<a href="/p/12345678"><img src="/youtube/abcdefghijk/abcd.jpg" "#,
            r#"alt="Post 12345678" width="320" height="180"></a>"#
        );
        let expected = concat!(
            r#"<img src="/youtube/abcdefghijk/abcd.jpg" alt="YouTube thumbnail abcdefghijk" "#,
            r#"width="320" height="180">"#
        );
        let output = unlink_youtube_thumbnails(input);
        assert_eq!(output, expected);
    }

    #[test]
    fn test_byte_slice() {
        let s = "héllo"; // 'é' is two bytes
        // Slicing at 1 byte should give 'h'
        assert_eq!(byte_slice(s, 1), "h");
        // Slicing at 2 bytes should still give 'h' (since 'é' is two bytes)
        // assert_eq!(byte_slice(s, 2), "h");
        // Slicing at 3 bytes should give 'hé'
        assert_eq!(byte_slice(s, 3), "hé");
        // Slicing at 10 bytes should give the whole string
        assert_eq!(byte_slice(s, 10), "héllo");
    }
}
