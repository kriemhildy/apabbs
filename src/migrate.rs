use apabbs::{BEGIN, COMMIT};
use sqlx::PgConnection;
use std::collections::HashMap;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let db = apabbs::db().await;
    let migrations = HashMap::from([("update_intro_limit", update_intro_limit)]);
    for (name, func) in migrations {
        println!("checking migration: {name}");
        let mut tx = db.begin().await.expect(BEGIN);
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _rust_migrations WHERE name = $1)")
                .bind(name)
                .fetch_one(&mut *tx)
                .await
                .expect("check if migration needed");
        if exists {
            continue;
        }
        println!("migrating: {name}");
        func(&mut *tx).await;
        sqlx::query("INSERT INTO _rust_migrations (name) VALUES ($1)")
            .bind(name)
            .execute(&mut *tx)
            .await
            .expect("insert migration record");
        tx.commit().await.expect(COMMIT);
    }
}

async fn update_intro_limit(tx: &mut PgConnection) {
    use apabbs::post::{Post, PostSubmission};
    let posts: Vec<Post> = sqlx::query_as("SELECT * FROM posts WHERE intro_limit_opt IS NOT NULL")
        .fetch_all(&mut *tx)
        .await
        .expect("fetch posts for migration");
    for post in posts {
        let intro_limit_opt = PostSubmission::intro_limit(&post.body);
        sqlx::query("UPDATE posts SET intro_limit_opt = $1 WHERE id = $2")
            .bind(intro_limit_opt)
            .bind(post.id)
            .execute(&mut *tx)
            .await
            .expect("update post intro limit");
    }
}
