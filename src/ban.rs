//! User ban management and abuse prevention.
//!
//! This module provides functionality for managing temporary bans, detecting
//! potential abuse, and protecting the system from malicious behavior. It
//! handles IP-based and account-based restrictions to prevent spam and
//! flooding.
//!
//! # Key Functions
//!
//! - [`insert`]: Creates a new temporary ban record
//! - [`exists`]: Checks if an IP or account is currently banned
//! - [`flooding`]: Detects excessive content creation from a single IP
//! - [`prune`]: Removes content from banned IPs
//! - [`scrub`]: Privacy-focused removal of IP data from older records
//!
//! # Rate Limiting
//!
//! The module implements rate limiting by tracking the combined count of new
//! accounts and pending posts from each IP address. When this count exceeds
//! [`MAX_CONTENT_PER_IP_DAILY`], the system considers it flooding and may
//! apply temporary restrictions.

use crate::POSTGRES_RFC5322_DATETIME;
use sqlx::PgConnection;

/// Maximum combined count of new accounts and pending posts allowed from a single IP
/// within a 24-hour period before considering it to be flooding
pub const MAX_CONTENT_PER_IP_DAILY: i64 = 9;

/// Inserts a new ban record into the database
///
/// Creates a new entry in the bans table with the specified IP hash and optional
/// account IDs. The ban will have an automatic expiration time set by the database.
///
/// # Parameters
/// - `tx`: Database transaction
/// - `ip_hash`: Hash of the IP address to ban
/// - `banned_account_id`: Optional ID of the account being banned
/// - `admin_account_id`: Optional ID of the admin who created the ban
///
/// # Returns
/// A string representation of the ban expiration time formatted according to RFC5322
pub async fn insert(
    tx: &mut PgConnection,
    ip_hash: &str,
    banned_account_id: Option<i32>,
    admin_account_id: Option<i32>,
) -> String {
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
    .expect("insert ban")
}

/// Checks if an active ban exists for an IP hash or account ID
///
/// Queries the database for unexpired bans matching either the IP hash
/// or the account ID (if provided).
///
/// # Parameters
/// - `tx`: Database transaction
/// - `ip_hash`: Hash of the IP address to check
/// - `banned_account_id`: Optional ID of the banned account
///
/// # Returns
/// The expiration time of the ban if it exists and is unexpired, `None` otherwise
pub async fn exists(
    tx: &mut PgConnection,
    ip_hash: &str,
    banned_account_id: Option<i32>,
) -> Option<String> {
    sqlx::query_scalar(concat!(
        "SELECT to_char(expires_at, $1) FROM bans ",
        "WHERE expires_at > now() AND (ip_hash = $2 OR banned_account_id = $3)",
    ))
    .bind(POSTGRES_RFC5322_DATETIME)
    .bind(ip_hash)
    .bind(banned_account_id)
    .fetch_optional(&mut *tx)
    .await
    .expect("return expiration if ban exists")
}

/// Counts new accounts created from an IP address within the past day
///
/// Used for rate limiting and anti-abuse detection.
///
/// # Parameters
/// - `tx`: Database transaction
/// - `ip_hash`: Hash of the IP address to check
///
/// # Returns
/// The count of new accounts created from the IP address within the past day
pub async fn new_accounts_count(tx: &mut PgConnection, ip_hash: &str) -> i64 {
    sqlx::query_scalar(concat!(
        "SELECT count(*) FROM accounts WHERE ip_hash = $1 ",
        "AND created_at > now() - interval '1 day'"
    ))
    .bind(ip_hash)
    .fetch_one(&mut *tx)
    .await
    .expect("count new account registrations by IP")
}

/// Counts pending posts created from an IP address within the past day
///
/// Used for rate limiting and anti-abuse detection.
///
/// # Parameters
/// - `tx`: Database transaction
/// - `ip_hash`: Hash of the IP address to check
///
/// # Returns
/// The count of pending posts created from the IP address within the past day
pub async fn new_posts_count(tx: &mut PgConnection, ip_hash: &str) -> i64 {
    sqlx::query_scalar(concat!(
        "SELECT count(*) FROM posts WHERE ip_hash = $1 ",
        "AND status = 'pending' AND created_at > now() - interval '1 day'"
    ))
    .bind(ip_hash)
    .fetch_one(&mut *tx)
    .await
    .expect("count new pending posts by IP")
}

/// Determines if an IP address is creating excessive content (flooding)
///
/// Combines the count of new accounts and pending posts from an IP address
/// to determine if it exceeds the system's rate limits.
///
/// # Parameters
/// - `tx`: Database transaction
/// - `ip_hash`: Hash of the IP address to check
///
/// # Returns
/// `true` if the IP is flooding (combined count >= MAX_CONTENT_PER_IP_DAILY), `false` otherwise
pub async fn flooding(tx: &mut PgConnection, ip_hash: &str) -> bool {
    let new_accounts_count = new_accounts_count(tx, ip_hash).await;
    let new_posts_count = new_posts_count(tx, ip_hash).await;
    new_accounts_count + new_posts_count >= MAX_CONTENT_PER_IP_DAILY
}

/// Removes content from a banned IP address
///
/// Deletes accounts that have only created pending posts and removes all
/// pending posts associated with the IP address.
///
/// # Parameters
/// - `tx`: Database transaction
/// - `ip_hash`: Hash of the IP address to prune
pub async fn prune(tx: &mut PgConnection, ip_hash: &str) {
    sqlx::query(concat!(
        "DELETE FROM accounts WHERE ip_hash = $1 AND NOT ",
        "EXISTS(SELECT 1 FROM posts WHERE account_id = accounts.id AND status <> 'pending')"
    ))
    .bind(ip_hash)
    .execute(&mut *tx)
    .await
    .expect("delete banned accounts with only pending posts");

    sqlx::query("DELETE FROM posts WHERE ip_hash = $1 AND status = 'pending'")
        .bind(ip_hash)
        .execute(&mut *tx)
        .await
        .expect("delete banned posts which are pending");
}

/// Removes IP address data from older content for privacy
///
/// This function removes IP hash data from accounts and posts that are
/// older than 1 day and are not in a state requiring IP tracking (like pending
/// or banned posts). This improves user privacy by not storing IP data longer
/// than necessary for moderation purposes.
///
/// # Parameters
/// - `tx`: Database transaction
pub async fn scrub(tx: &mut PgConnection) {
    // Scrub IP data from accounts older than 1 day
    sqlx::query(concat!(
        "UPDATE accounts SET ip_hash = NULL WHERE ip_hash IS NOT NULL ",
        "AND created_at < now() - interval '1 day'"
    ))
    .execute(&mut *tx)
    .await
    .expect("scrub ip_hash data from users");

    // Scrub IP data from posts older than 1 day that don't need IP tracking
    sqlx::query(concat!(
        "UPDATE posts SET ip_hash = NULL WHERE ip_hash IS NOT NULL ",
        "AND status NOT IN ('pending', 'banned') ",
        "AND created_at < now() - interval '1 day'"
    ))
    .execute(&mut *tx)
    .await
    .expect("scrub ip_hash data from posts and accounts");
}
