use apabbs::{BEGIN, COMMIT};
use sqlx::PgPool;
use std::future::Future;
use std::pin::Pin;

type MigrationFn = fn(PgPool) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

macro_rules! migrations {
    ($($func:ident),* $(,)?) => {
        [$(
            (stringify!($func), (|db| Box::pin($func(db))) as MigrationFn)
        ),*]
    };
}

#[tokio::main]
async fn main() {
    let migrations = migrations![update_intro_limit, download_youtube_thumbnails];
    dotenv::dotenv().ok();
    let db = apabbs::db().await;
    for (name, func) in migrations {
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
    #[derive(sqlx::FromRow, Debug)]
    struct ThumbnailLink {
        post_id: i32,
        video_id: String,
        size: String,
    }
    use apabbs::post::PostSubmission;
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
        println!("downloading youtube thumbnail for link: {:?}", link);
        if PostSubmission::download_youtube_thumbnail(&link.video_id, &link.size).is_some() {
            sqlx::query(concat!(
                "UPDATE posts SET body = ",
                r#"replace(body, '<img src="https://img.youtube.com/vi/$1/$2.jpg', "#,
                r#"'<img src="/youtube/$1/$2.jpg') WHERE id = $3"#
            ))
            .bind(&link.video_id)
            .bind(&link.size)
            .bind(link.post_id)
            .execute(&mut *tx)
            .await
            .expect("update youtube thumbnail url");
        }
    }
    tx.commit().await.expect(COMMIT);
}
