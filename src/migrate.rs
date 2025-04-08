use apabbs::{BEGIN, COMMIT};
use sqlx::PgConnection;
use std::collections::HashMap;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let db = apabbs::db().await;
    let migrations = HashMap::from([("word wrap and limit", word_wrap_and_limit)]);
    for (desc, func) in migrations {
        println!("checking migration: {desc}");
        let mut tx = db.begin().await.expect(BEGIN);
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM _rust_migrations WHERE description = $1)",
        )
        .bind(desc)
        .fetch_one(&mut *tx)
        .await
        .expect("check if migration needed");
        if exists {
            continue;
        }
        println!("migrating: {desc}");
        func(&mut *tx).await;
        sqlx::query("INSERT INTO _rust_migrations (description) VALUES ($1)")
            .bind(desc)
            .execute(&mut *tx)
            .await
            .expect("insert migration record");
        tx.commit().await.expect(COMMIT);
    }
}

async fn word_wrap_and_limit(_tx: &mut PgConnection) {
    println!("word wrap and limit migration");
}
