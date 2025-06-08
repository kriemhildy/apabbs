use crate::POSTGRES_RFC5322_DATETIME;
use sqlx::PgConnection;

/// Inserts a new ban record into the database
///
/// Creates a new entry in the bans table with the specified IP hash and optional
/// account IDs. The ban will have an automatic expiration time set by the database.
///
///
pub async fn insert(
    tx: &mut PgConnection,
    ip_hash: &str,
    banned_account_id_opt: Option<i32>,
    admin_account_id_opt: Option<i32>,
) -> String {
    sqlx::query_scalar(concat!(
        "INSERT INTO bans (ip_hash, banned_account_id_opt, admin_account_id_opt) ",
        "VALUES ($1, $2, $3) RETURNING to_char(expires_at, $4)",
    ))
    .bind(ip_hash)
    .bind(banned_account_id_opt)
    .bind(admin_account_id_opt)
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
///
pub async fn exists(
    tx: &mut PgConnection,
    ip_hash: &str,
    banned_account_id_opt: Option<i32>,
) -> Option<String> {
    sqlx::query_scalar(concat!(
        "SELECT to_char(expires_at, $1) FROM bans ",
        "WHERE expires_at > now() AND (ip_hash = $2 OR banned_account_id_opt = $3)",
    ))
    .bind(POSTGRES_RFC5322_DATETIME)
    .bind(ip_hash)
    .bind(banned_account_id_opt)
    .fetch_optional(&mut *tx)
    .await
    .expect("return expiration if ban exists")
}

/// Counts new accounts created from an IP address within the past day
///
/// Used for rate limiting and anti-abuse detection.
///
///
pub async fn new_accounts_count(tx: &mut PgConnection, ip_hash: &str) -> i64 {
    sqlx::query_scalar(concat!(
        "SELECT count(*) FROM accounts WHERE ip_hash_opt = $1 ",
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
///
pub async fn new_posts_count(tx: &mut PgConnection, ip_hash: &str) -> i64 {
    sqlx::query_scalar(concat!(
        "SELECT count(*) FROM posts WHERE ip_hash_opt = $1 ",
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
///
pub async fn flooding(tx: &mut PgConnection, ip_hash: &str) -> bool {
    let new_accounts_count = new_accounts_count(tx, ip_hash).await;
    let new_posts_count = new_posts_count(tx, ip_hash).await;
    new_accounts_count + new_posts_count >= 9
}

/// Removes content from a banned IP address
///
/// Deletes accounts that have only created pending posts and removes all
/// pending posts associated with the IP address.
///
///
pub async fn prune(tx: &mut PgConnection, ip_hash: &str) {
    sqlx::query(concat!(
        "DELETE FROM accounts WHERE ip_hash_opt = $1 AND NOT ",
        "EXISTS(SELECT 1 FROM posts WHERE account_id_opt = accounts.id AND status <> 'pending')"
    ))
    .bind(ip_hash)
    .execute(&mut *tx)
    .await
    .expect("delete banned accounts with only pending posts");

    sqlx::query("DELETE FROM posts WHERE ip_hash_opt = $1 AND status = 'pending'")
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
///
pub async fn scrub(tx: &mut PgConnection) {
    // Scrub IP data from accounts older than 1 day
    sqlx::query(concat!(
        "UPDATE accounts SET ip_hash_opt = NULL WHERE ip_hash_opt IS NOT NULL ",
        "AND created_at < now() - interval '1 day'"
    ))
    .execute(&mut *tx)
    .await
    .expect("scrub ip_hash data from users");

    // Scrub IP data from posts older than 1 day that don't need IP tracking
    sqlx::query(concat!(
        "UPDATE posts SET ip_hash_opt = NULL WHERE ip_hash_opt IS NOT NULL ",
        "AND status NOT IN ('pending', 'banned') ",
        "AND created_at < now() - interval '1 day'"
    ))
    .execute(&mut *tx)
    .await
    .expect("scrub ip_hash data from posts and accounts");
}
