use apabbs::{BEGIN, COMMIT};
use std::collections::HashMap;
use sqlx::PgPool;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let db = apabbs::db().await;
    let migrations = HashMap::from([
        ("word wrap and limit", word_wrap_and_limit)
    ]);
    for (name, func) in migrations {
        println!("migrating: {name}");
        func(&db).await;
    }
}

async fn word_wrap_and_limit(db: &PgPool) {
    let mut tx = db.begin().await.expect(BEGIN);
    sqlx::query(
        r#"
        update post
        set body = left(body, 10000)
        where length(body) > 10000
        "#,
    )
    .execute(&mut *tx)
    .await
    .expect("update post body");
    tx.commit().await.expect(COMMIT);
}
