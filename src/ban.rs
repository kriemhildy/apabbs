//! User ban management and abuse prevention.
//!
//! Provides functionality for managing temporary bans, detecting potential abuse,
//! and protecting the system from malicious behavior. Handles IP-based and account-based
//! restrictions to prevent spam and flooding.

use crate::utils::POSTGRES_RFC5322_DATETIME;
use sqlx::PgConnection;
use std::error::Error;

/// Maximum combined count of new accounts and pending posts allowed from a single IP
/// within a 24-hour period before considering it to be flooding.
pub const MAX_CONTENT_PER_IP_DAILY: i64 = 9;

/// Inserts a new ban record into the database.
pub async fn insert(
    tx: &mut PgConnection,
    ip_hash: &str,
    banned_account_id: Option<i32>,
    admin_account_id: Option<i32>,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    sqlx::query_scalar(concat!(
        "INSERT INTO bans (ip_hash, banned_account_id, admin_account_id) ",
        "VALUES ($1, $2, $3) RETURNING to_char(expires_at, $4)",
    ))
    .bind(ip_hash)
    .bind(banned_account_id)
    .bind(admin_account_id)
    .bind(POSTGRES_RFC5322_DATETIME)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("failed to insert ban: {e}").into())
}

/// Checks if an active ban exists for an IP hash or account ID.
pub async fn exists(
    tx: &mut PgConnection,
    ip_hash: &str,
    banned_account_id: Option<i32>,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    sqlx::query_scalar(concat!(
        "SELECT to_char(expires_at, $1) FROM bans ",
        "WHERE expires_at > now() AND (ip_hash = $2 OR banned_account_id = $3)",
    ))
    .bind(POSTGRES_RFC5322_DATETIME)
    .bind(ip_hash)
    .bind(banned_account_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("failed to check for existing ban: {e}").into())
}

/// Counts new accounts created from an IP address within the past day.
pub async fn new_accounts_count(
    tx: &mut PgConnection,
    ip_hash: &str,
) -> Result<i64, Box<dyn Error + Send + Sync>> {
    sqlx::query_scalar(concat!(
        "SELECT count(*) FROM accounts WHERE ip_hash = $1 ",
        "AND created_at > now() - interval '1 day'"
    ))
    .bind(ip_hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("failed to count new accounts: {e}").into())
}

/// Counts pending posts created from an IP address within the past day.
pub async fn new_posts_count(
    tx: &mut PgConnection,
    ip_hash: &str,
) -> Result<i64, Box<dyn Error + Send + Sync>> {
    sqlx::query_scalar(concat!(
        "SELECT count(*) FROM posts WHERE ip_hash = $1 ",
        "AND status = 'pending' AND created_at > now() - interval '1 day'"
    ))
    .bind(ip_hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("failed to count new posts: {e}").into())
}

/// Determines if an IP address is creating excessive content (flooding).
pub async fn flooding(
    tx: &mut PgConnection,
    ip_hash: &str,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let new_accounts = new_accounts_count(tx, ip_hash).await?;
    let new_posts = new_posts_count(tx, ip_hash).await?;
    Ok(new_accounts + new_posts >= MAX_CONTENT_PER_IP_DAILY)
}

/// Removes content from a banned IP address.
pub async fn prune(
    tx: &mut PgConnection,
    ip_hash: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    sqlx::query(concat!(
        "DELETE FROM accounts WHERE ip_hash = $1 AND NOT ",
        "EXISTS(SELECT 1 FROM posts WHERE account_id = accounts.id AND status <> 'pending')"
    ))
    .bind(ip_hash)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("failed to prune accounts: {e}"))?;

    sqlx::query("DELETE FROM posts WHERE ip_hash = $1 AND status = 'pending'")
        .bind(ip_hash)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("failed to prune posts: {e}"))?;

    Ok(())
}

/// Removes IP address data from older content for privacy.
pub async fn scrub(tx: &mut PgConnection) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Scrub IP data from accounts older than 1 day
    sqlx::query(concat!(
        "UPDATE accounts SET ip_hash = NULL WHERE ip_hash IS NOT NULL ",
        "AND created_at < now() - interval '1 day'"
    ))
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("failed to scrub accounts: {e}"))?;

    // Scrub IP data from posts older than 1 day that don't need IP tracking
    sqlx::query(concat!(
        "UPDATE posts SET ip_hash = NULL WHERE ip_hash IS NOT NULL ",
        "AND status NOT IN ('pending', 'banned') ",
        "AND created_at < now() - interval '1 day'"
    ))
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("failed to scrub posts: {e}"))?;

    Ok(())
}
