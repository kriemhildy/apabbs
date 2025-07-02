use crate::{AppState, post::Post};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use std::{error::Error, pin::Pin};
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
    let tmpl = env.get_template(name)?;
    tmpl.render(ctx)
        .map_err(|e| format!("failed to render template \"{name}\": {e}").into())
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
