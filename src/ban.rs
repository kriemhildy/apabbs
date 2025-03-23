use crate::POSTGRES_RFC5322_DATETIME;
use sqlx::PgConnection;

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

pub async fn flooding(tx: &mut PgConnection, ip_hash: &str) -> bool {
    let new_accounts_count = new_accounts_count(tx, ip_hash).await;
    let new_posts_count = new_posts_count(tx, ip_hash).await;
    new_accounts_count + new_posts_count >= 9
}

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

pub async fn scrub(tx: &mut PgConnection) {
    sqlx::query(concat!(
        "UPDATE accounts SET ip_hash_opt = NULL WHERE ip_hash_opt IS NOT NULL ",
        "AND created_at < now() - interval '1 day'"
    ))
    .execute(&mut *tx)
    .await
    .expect("scrub ip_hash data from users");
    sqlx::query(concat!(
        "UPDATE posts SET ip_hash_opt = NULL WHERE ip_hash_opt IS NOT NULL ",
        "AND status NOT IN ('pending', 'banned') ",
        "AND created_at < now() - interval '1 day'"
    ))
    .execute(&mut *tx)
    .await
    .expect("scrub ip_hash data from posts and accounts");
}
