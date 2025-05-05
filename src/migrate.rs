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
    let migrations = migrations![
        uuid_to_key,
        download_youtube_thumbnails,
        generate_media_thumbnails,
        update_intro_limit,
        add_image_dimensions,
        add_video_dimensions,
    ];
    if let Err(error) = dotenv::dotenv() {
        eprintln!("Error loading .env file: {}", error);
        std::process::exit(1);
    }
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
    use apabbs::post::PostSubmission;
    use std::thread;
    use tokio::time::Duration;
    let mut tx = db.begin().await.expect(BEGIN);
    // we need all matches, possibly multiple per post
    let video_ids: Vec<String> = sqlx::query_scalar(concat!(
        "SELECT matches[1] AS video_id FROM ",
        "(SELECT regexp_matches(body, ",
        r#"'<a href="https://www\.youtube\.com/(?:watch\?v=|shorts/)([\w\-]{11})', 'g') "#,
        r#"FROM posts WHERE body LIKE '%<img src="/youtube/%' AND status = 'approved') "#,
        " AS subquery(matches)"
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("selects youtube links");
    // because old links were assumed to be mqdefault, and later maxresdefault, this will
    // re-determine the optimal size, and as such we need to update the database afterwards
    for video_id in video_ids {
        println!("downloading thumbnail for video {}", video_id);
        // detect whether or not the youtube is a short by checking the response code of the short url
        let response_code = std::process::Command::new("curl")
            .args([
                "--silent",
                "--output",
                "/dev/null",
                "--write-out",
                "'%{http_code}'",
            ])
            .arg(format!("https://www.youtube.com/shorts/{}", video_id))
            .output()
            .expect("checks response code for youtube short")
            .stdout;
        let short = response_code == b"'200'";
        if short {
            println!("youtube is a short");
            // update link url to be short if it is not
            sqlx::query(&format!(
                concat!(
                    r#"UPDATE posts SET body = replace(body, "#,
                    r#"'https://www.youtube.com/watch?v={video_id}', "#,
                    r#"'https://www.youtube.com/shorts/{video_id}') WHERE body LIKE "#,
                    r#"'%https://www.youtube.com/watch?v={video_id}%'"#
                ),
                video_id = video_id
            ))
            .execute(&mut *tx)
            .await
            .expect("updates youtube link to be short");
        }
        if let Some((local_thumbnail_path, width, height)) =
            PostSubmission::download_youtube_thumbnail(&video_id, short)
        {
            // remove pub prefix
            let thumbnail_url = local_thumbnail_path
                .to_str()
                .unwrap()
                .strip_prefix("pub")
                .expect("strips pub prefix");
            println!("saved to {thumbnail_url} ({width}x{height})");
            // update body of posts with new thumbnail url
            sqlx::query(&format!(
                concat!(
                    r#"UPDATE posts SET body = regexp_replace(body, "#,
                    r#"'<a href="/post/(\w+)">"#,
                    r#"<img src="/youtube/{video_id}/\w+\.jpg"[^>]*></a>', "#,
                    r#"'<a href="/post/\1">"#,
                    r#"<img src="{thumbnail_url}" alt="Post \1" "#,
                    r#"width="{width}" height="{height}"></a>', 'g')"#,
                    r#"WHERE body LIKE "#,
                    r#"'%<img src="/youtube/{video_id}/%'"#
                ),
                video_id = video_id,
                thumbnail_url = thumbnail_url,
                width = width,
                height = height
            ))
            .execute(&mut *tx)
            .await
            .expect("updates youtube thumbnail in posts");
        }
        // Sleep for 1 second to avoid rate limiting
        thread::sleep(Duration::from_secs(1));
    }
    tx.commit().await.expect(COMMIT);
}

async fn uuid_to_key(db: PgPool) {
    use uuid::Uuid;
    let mut tx = db.begin().await.expect(BEGIN);
    // check to see if uuid column exists
    let exists: bool = sqlx::query_scalar(concat!(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns ",
        "WHERE table_name = 'posts' AND column_name = 'uuid')"
    ))
    .fetch_one(&mut *tx)
    .await
    .expect("check if uuid column exists");
    if !exists {
        println!("uuid column does not exist, skipping migration");
        return;
    }
    #[derive(sqlx::FromRow, Debug)]
    struct UuidKeyPair {
        uuid: Uuid,
        key: String,
    }
    let pairs: Vec<UuidKeyPair> = sqlx::query_as(
        "SELECT uuid, key FROM posts WHERE uuid IS NOT NULL AND media_filename_opt IS NOT NULL ",
    )
    .fetch_all(&mut *tx)
    .await
    .expect("fetch posts for migration");
    for pair in pairs {
        println!("migrating {} to {}", pair.uuid, pair.key);
        let uuid_dir = format!("pub/media/{}", pair.uuid);
        if !std::path::Path::new(&uuid_dir).exists() {
            println!("media directory for uuid does not exist, skipping");
            continue;
        }
        std::fs::rename(uuid_dir, format!("pub/media/{}", pair.key))
            .expect("rename media directory");
    }
    sqlx::query("ALTER TABLE posts DROP COLUMN uuid")
        .execute(&mut *tx)
        .await
        .expect("drop uuid column");
    tx.commit().await.expect(COMMIT);
}

async fn generate_media_thumbnails(db: PgPool) {
    use apabbs::post::{Post, PostReview};
    let mut tx = db.begin().await.expect(BEGIN);
    let posts: Vec<Post> = sqlx::query_as(concat!(
        "SELECT * FROM posts WHERE media_filename_opt IS NOT NULL ",
        "AND media_category_opt = 'image' AND status = 'approved'",
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("selects posts with images");
    for post in posts {
        let published_media_path = post.published_media_path();
        println!(
            "generating thumbnail for media {}",
            published_media_path.to_str().unwrap()
        );
        PostReview::generate_image_thumbnail(&published_media_path).await;
        // update posts with new thumbnail filename
        let (thumbnail_filename, thumbnail_path) =
            PostReview::thumbnail_info(&published_media_path, ".webp");
        if !thumbnail_path.exists() {
            eprintln!("thumbnail not created successfully");
            std::process::exit(1);
        }
        if PostReview::thumbnail_is_larger(&thumbnail_path, &published_media_path) {
            println!("thumbnail is larger, deleting");
            std::fs::remove_file(&thumbnail_path).expect("remove thumbnail file");
            continue;
        }
        println!("setting thumb_filename_opt, thumb_width_opt, thumb_height_opt");
        let (width, height) = PostReview::image_dimensions(&thumbnail_path).await;
        post.update_thumbnail(&mut *tx, &thumbnail_filename, width, height)
            .await;
    }
    tx.commit().await.expect(COMMIT);
}

async fn add_image_dimensions(db: PgPool) {
    use apabbs::post::{Post, PostReview};
    let mut tx = db.begin().await.expect(BEGIN);
    let posts: Vec<Post> = sqlx::query_as(concat!(
        "SELECT * FROM posts WHERE media_filename_opt IS NOT NULL ",
        "AND media_category_opt = 'image' AND status = 'approved'",
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("selects posts with images");
    for post in posts {
        let published_media_path = post.published_media_path();
        println!(
            "adding dimensions for media {}",
            published_media_path.to_str().unwrap()
        );
        let (width, height) = PostReview::image_dimensions(&published_media_path).await;
        println!("setting media image dimensions: {}x{}", width, height);
        post.update_media_dimensions(&mut *tx, width, height).await;
        if let Some(ref thumb_filename) = post.thumb_filename_opt {
            let thumbnail_path = post.thumbnail_path();
            let (width, height) = PostReview::image_dimensions(&thumbnail_path).await;
            println!("setting thumbnail image dimensions: {}x{}", width, height);
            post.update_thumbnail(&mut *tx, thumb_filename, width, height)
                .await;
        }
    }
    tx.commit().await.expect(COMMIT);
}

async fn add_video_dimensions(db: PgPool) {
    use apabbs::post::{Post, PostReview};
    let mut tx = db.begin().await.expect(BEGIN);
    let posts: Vec<Post> = sqlx::query_as(concat!(
        "SELECT * FROM posts WHERE media_filename_opt IS NOT NULL ",
        "AND media_category_opt = 'video' AND status = 'approved'",
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("selects posts with videos");
    for post in posts {
        let published_media_path = post.published_media_path();
        println!(
            "adding dimensions for media {}",
            published_media_path.to_str().unwrap()
        );
        let (width, height) = PostReview::video_dimensions(&published_media_path).await;
        println!("setting video dimensions: {}x{}", width, height);
        post.update_media_dimensions(&mut *tx, width, height).await;
    }
    tx.commit().await.expect(COMMIT);
}
