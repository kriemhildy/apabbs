//! User ban management and abuse prevention.
//!
//! Provides functionality for managing temporary bans, detecting potential abuse,
//! and protecting the system from malicious behavior. Handles IP-based and account-based
//! restrictions to prevent spam and flooding.

use crate::utils::POSTGRES_RFC5322_DATETIME;
use sqlx::PgConnection;
use std::error::Error;

/// Maximum allowed count of pending posts from a single IP
/// within a 24-hour period before considering it to be flooding.
pub const FLOOD_CUTOFF: i64 = 10;

/// Represents a ban record for an IP address or account.
#[derive(sqlx::FromRow, Default)]
pub struct Ban {
    /// The hash of the banned IP address.
    pub ip_hash: String,
    /// The ID of the banned user account, if applicable.
    pub banned_account_id: Option<i32>,
    /// The ID of the admin account that issued the ban, if applicable.
    pub admin_account_id: Option<i32>,
}

impl Ban {
    /// Inserts a new ban record into the database.
    pub async fn insert(
        &self,
        tx: &mut PgConnection,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        sqlx::query_scalar(concat!(
            "INSERT INTO bans (ip_hash, banned_account_id, admin_account_id) ",
            "VALUES ($1, $2, $3) RETURNING to_char(expires_at, $4)",
        ))
        .bind(&self.ip_hash)
        .bind(self.banned_account_id)
        .bind(self.admin_account_id)
        .bind(POSTGRES_RFC5322_DATETIME)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("insert ban: {e}").into())
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
        .map_err(|e| format!("check for existing ban: {e}").into())
    }
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
    .map_err(|e| format!("count new posts: {e}").into())
}

/// Determines if an IP address is creating excessive content (flooding).
pub async fn is_flooding(
    tx: &mut PgConnection,
    ip_hash: &str,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let new_posts = new_posts_count(tx, ip_hash).await?;
    Ok(new_posts >= FLOOD_CUTOFF)
}

/// Removes content from a banned IP address.
pub async fn prune(
    tx: &mut PgConnection,
    ip_hash: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    sqlx::query("DELETE FROM posts WHERE ip_hash = $1 AND status = 'pending'")
        .bind(ip_hash)
        .execute(&mut *tx)
        .await
        .map(|_| ())
        .map_err(|e| format!("prune posts: {e}").into())
}

/// Removes IP address data from older content for privacy.
pub async fn scrub(tx: &mut PgConnection) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Scrub IP data from posts older than 1 day that don't need IP tracking
    sqlx::query(concat!(
        "UPDATE posts SET ip_hash = NULL WHERE ip_hash IS NOT NULL ",
        "AND status NOT IN ('pending', 'banned') ",
        "AND created_at < now() - interval '1 day'"
    ))
    .execute(&mut *tx)
    .await
    .map(|_| ())
    .map_err(|e| format!("scrub posts: {e}").into())
}

/// Check if text contains any known spam terms.
pub async fn contains_spam_term(
    tx: &mut PgConnection,
    text: &str,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM spam_terms WHERE $1 ~ term)")
        .bind(text)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("check for spam terms: {e}").into())
}
