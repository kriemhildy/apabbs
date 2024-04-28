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

pub async fn flooding(tx: &mut PgConnection, ip: &str) -> bool {
    // this is too aggressive currently, needs to check for post status being pending.
    // 10 posts in a week is much more reasonable than 10 user accounts in a week.
    sqlx::query_scalar(concat!(
        "SELECT count(*) >= 10 FROM users ",
        "LEFT OUTER JOIN posts ON posts.ip = users.ip ",
        "WHERE ip = $1 AND created_at > now() - interval '1 week'" // unclear table names
    ))
    .bind(ip)
    .fetch_one(&mut *tx)
    .await
    .expect("detect if ip is flooding")
}

pub async fn prune(tx: &mut PgConnection, ip: &str) {
    sqlx::query("")
    .bind(ip)
    .execute(&mut *tx)
    .await
    .expect("prune records from banned ip");
}
