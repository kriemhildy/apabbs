use sqlx::PgConnection;

pub async fn insert(tx: &mut PgConnection, ip: &str) {
    sqlx::query("INSERT INTO bans (ip) VALUES ($1)")
        .bind(ip)
        .execute(&mut *tx)
        .await
        .expect("insert ip ban");
}

pub async fn exists(tx: &mut PgConnection, ip: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM bans WHERE ip = $1)")
        .bind(ip)
        .fetch_one(&mut *tx)
        .await
        .expect("check if ip ban exists")
}

pub async fn prune(tx: &mut PgConnection, ip: &str) {
    sqlx::query(concat!(
        "DELETE FROM users WHERE ip = $1 ",
        "AND NOT EXISTS(SELECT 1 FROM posts WHERE user_id = users.id AND status <> 'pending')"
    ))
    .bind(ip)
    .execute(&mut *tx)
    .await
    .expect("delete banned users with only pending posts");
    sqlx::query("DELETE FROM posts WHERE ip = $1 AND status = 'pending'")
        .bind(ip)
        .execute(&mut *tx)
        .await
        .expect("delete banned posts which are pending");
}
