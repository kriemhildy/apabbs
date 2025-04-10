use apabbs::{BEGIN, COMMIT};
use sqlx::PgPool;
use std::future::Future;
use std::pin::Pin;

// Define a type alias for the migration function
type MigrationFn = fn(PgPool) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

#[tokio::main]
async fn main() {
    let migrations: [(&str, MigrationFn); 2] = [
        ("update_intro_limit", |pool| {
            Box::pin(update_intro_limit(pool))
        }),
        ("download_youtube_thumbnails", |pool| {
            Box::pin(download_youtube_thumbnails(pool))
        }),
    ];
    dotenv::dotenv().ok();
    let db = apabbs::db().await;
    for (name, func) in migrations {
        println!("checking migration: {name}");
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _rust_migrations WHERE name = $1)")
                .bind(name)
                .fetch_one(&db)
                .await
                .expect("check if migration needed");
        if exists {
            continue;
        }
        println!("migrating: {name}");
        func(db.clone()).await;
        sqlx::query("INSERT INTO _rust_migrations (name) VALUES ($1)")
            .bind(name)
            .execute(&db)
            .await
            .expect("insert migration record");
    }
}

async fn update_intro_limit(db: PgPool) {
    use apabbs::post::{Post, PostSubmission};
    let mut tx = db.begin().await.expect(BEGIN);
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
    tx.commit().await.expect(COMMIT);
}

async fn download_youtube_thumbnails(db: PgPool) {
    let mut tx = db.begin().await.expect(BEGIN);
    #[derive(sqlx::FromRow)]
    struct ThumbnailLink {
        post_id: i32,
        video_id: String,
        size: String,
    }
    use apabbs::post::{Post, PostSubmission};
    let thumbnail_links: Vec<ThumbnailLink> = sqlx::query_as(concat!(
        r"SELECT id AS post_id, substring(body from 'vi\/([a-zA-z0-9\-_]+)\/') AS video_id, ",
        r"substring(body from 'vi\/[a-zA-z0-9\-_]+/(\w+)\.jpg') AS size ",
        r#"FROM posts WHERE body LIKE '%<img src="https://img.youtube.com/vi%' "#,
        "AND status = 'approved'"
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("fetch posts");
    for link in thumbnail_links {
        if let Some(thumbnail_url) =
            PostSubmission::download_youtube_thumbnail(&link.video_id, &link.size)
        {
            // sqlx::query("UPDATE posts SET thumbnail_url = $1 WHERE id = $2")
            //     .bind(thumbnail_url)
            //     .bind(post.id)
            //     .execute(&mut *tx)
            //     .await
            //     .expect("update post thumbnail URL");
        }
    }
    tx.commit().await.expect(COMMIT);
}
