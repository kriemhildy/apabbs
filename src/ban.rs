#[derive(sqlx::FromRow, serde::Serialize)]
pub struct Ban {
    ip: String,
}

use sqlx::PgConnection;

impl Ban {
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
}
