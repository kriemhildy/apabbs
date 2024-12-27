use sqlx::{types::time::OffsetDateTime, PgConnection};

pub async fn insert(tx: &mut PgConnection, ip_hash: &str) -> String {
    let expires_at: OffsetDateTime =
        sqlx::query_scalar("INSERT INTO bans (ip_hash) VALUES ($1) RETURNING expires_at")
            .bind(ip_hash)
            .fetch_one(&mut *tx)
            .await
            .expect("insert ip ban");
    expires_at.to_string()
}

pub async fn exists(tx: &mut PgConnection, ip_hash: &str) -> Option<String> {
    let expires_at: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT expires_at FROM bans WHERE ip_hash = $1 AND expires_at > now()")
            .bind(ip_hash)
            .fetch_optional(&mut *tx)
            .await
            .expect("return expiration if ip ban exists");
    match expires_at {
        Some(expires_at) => Some(expires_at.to_string()),
        None => None,
    }
}

pub async fn flooding(tx: &mut PgConnection, ip_hash: &str) -> bool {
    let new_users_count: i64 = sqlx::query_scalar(concat!(
        "SELECT count(*) FROM accounts WHERE ip_hash = $1 ",
        "AND created_at > now() - interval '1 day'"
    ))
    .bind(ip_hash)
    .fetch_one(&mut *tx)
    .await
    .expect("count new account registrations by IP");
    let new_posts_count: i64 = sqlx::query_scalar(concat!(
        "SELECT count(*) FROM posts WHERE ip_hash = $1 ",
        "AND status = 'pending' AND created_at > now() - interval '1 day'"
    ))
    .bind(ip_hash)
    .fetch_one(&mut *tx)
    .await
    .expect("count new pending posts by IP");
    new_users_count + new_posts_count >= 10
}

pub async fn prune(tx: &mut PgConnection, ip_hash: &str) {
    sqlx::query(concat!(
        "DELETE FROM accounts WHERE ip_hash = $1 ",
        "AND NOT ",
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

pub async fn scrub(tx: &mut PgConnection) {
    sqlx::query(concat!(
        "UPDATE accounts SET ip_hash = NULL WHERE ip_hash IS NOT NULL ",
        "AND created_at < now() - interval '1 day'"
    ))
    .execute(&mut *tx)
    .await
    .expect("scrub ip_hash data from users");
    sqlx::query(concat!(
        "UPDATE posts SET ip_hash = NULL WHERE ip_hash IS NOT NULL ",
        "AND status NOT IN ('pending', 'banned') ",
        "AND created_at < now() - interval '1 day'"
    ))
    .execute(&mut *tx)
    .await
    .expect("scrub ip_hash data from posts");
}
