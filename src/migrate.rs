//! Database migration utilities for the application.
//!
//! Provides sequential database migrations, tracking applied migrations in the `_rust_migrations` table.

use apabbs::{BEGIN_FAILED_ERR, COMMIT_FAILED_ERR};
use sqlx::PgPool;
use std::future::Future;
use std::pin::Pin;

/// Type alias for migration functions that take a database connection pool
/// and return an async operation.
type MigrationFn = fn(PgPool) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Macro to create an array of migration functions paired with their names.
///
/// Each function name is converted to a string and paired with the function itself.
/// This allows migrations to be tracked by name in the database.
macro_rules! migrations {
    ($($func:ident),* $(,)?) => {
        [$((stringify!($func), (|db| Box::pin($func(db))) as MigrationFn)),*]
    };
}

#[tokio::main]
async fn main() {
    // Register all migrations in the order they should be applied
    let migrations = migrations![
        uuid_to_key,
        download_youtube_thumbnails,
        generate_image_thumbnails,
        update_intro_limit,
        add_image_dimensions,
        process_videos,
    ];

    // Load environment variables from .env file
    if let Err(error) = dotenv::dotenv() {
        eprintln!("Failed to load .env file: {error}");
        std::process::exit(1);
    }

    // Connect to database
    let db = apabbs::db().await;

    // Process each migration
    for (name, func) in migrations {
        // Check if migration has already been applied
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _rust_migrations WHERE name = $1)")
                .bind(name)
                .fetch_one(&db)
                .await
                .expect("Failed to check if migration is needed");

        if exists {
            continue;
        }

        println!("Applying migration: {name}");
        func(db.clone()).await;

        // Record that migration was applied
        sqlx::query("INSERT INTO _rust_migrations (name) VALUES ($1)")
            .bind(name)
            .execute(&db)
            .await
            .expect("Failed to record applied migration");
    }
}

/// Updates post intro_limit values based on content analysis.
///
/// Recalculates the intro_limit field for all posts that have it set.
async fn update_intro_limit(db: PgPool) {
    use apabbs::post::{Post, PostSubmission};
    let mut tx = db.begin().await.expect(BEGIN_FAILED_ERR);
    let posts: Vec<Post> = sqlx::query_as("SELECT * FROM posts WHERE intro_limit IS NOT NULL")
        .fetch_all(&mut *tx)
        .await
        .expect("Failed to fetch posts for intro_limit migration");

    for post in posts {
        let intro_limit = PostSubmission::intro_limit(&post.body);
        sqlx::query("UPDATE posts SET intro_limit = $1 WHERE id = $2")
            .bind(intro_limit)
            .bind(post.id)
            .execute(&mut *tx)
            .await
            .expect("Failed to update post intro_limit");
    }
    tx.commit().await.expect(COMMIT_FAILED_ERR);
}

/// Downloads YouTube thumbnails for posts containing YouTube links.
///
/// Finds YouTube links in posts, determines if they're shorts or regular videos,
/// downloads appropriate thumbnails, and updates post content with the new thumbnail URLs.
async fn download_youtube_thumbnails(db: PgPool) {
    use apabbs::post::PostSubmission;
    use std::thread;
    use tokio::time::Duration;

    let mut tx = db.begin().await.expect(BEGIN_FAILED_ERR);

    // Extract all YouTube video IDs from posts with YouTube embeds
    let video_ids: Vec<String> = sqlx::query_scalar(concat!(
        "SELECT matches[1] AS video_id FROM ",
        "(SELECT regexp_matches(body, ",
        r#"'<a href=\"https://www\\.youtube\\.com/(?:watch\?v=|shorts/)([\w\-]{11})', 'g') "#,
        r#"FROM posts WHERE body LIKE '%<img src="/youtube/%' "#,
        "AND status IN ('approved', 'delisted')) ",
        " AS subquery(matches)"
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("Failed to select YouTube links");

    for video_id in video_ids {
        println!("Downloading thumbnail for video {video_id}");

        // Check if the YouTube video is a short
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
            .expect("Failed to check response code for YouTube short")
            .stdout;
        let short = response_code == b"'200'";

        if short {
            println!("Video is a YouTube short");
            // Update link URLs to use shorts format if needed
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
            .expect("Failed to update YouTube link to shorts format");
        }

        // Download thumbnail and get dimensions
        if let Some((local_thumbnail_path, width, height)) =
            PostSubmission::download_youtube_thumbnail(&video_id, short).await
        {
            // Remove pub prefix from path for URL
            let thumbnail_url = local_thumbnail_path
                .to_str()
                .unwrap()
                .strip_prefix("pub")
                .expect("Failed to strip pub prefix from thumbnail path");

            println!("Saved thumbnail to {thumbnail_url} ({width}x{height})");

            // Update post content with new thumbnail URL and dimensions
            sqlx::query(&format!(
                concat!(
                    r#"UPDATE posts SET body = regexp_replace(body, "#,
                    r#"'<a href="/p/(\w+)">"#,
                    r#"<img src="/youtube/{video_id}/\w+\.jpg"[^>]*></a>', "#,
                    r#"'<a href="/p/\1">"#,
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
            .expect("Failed to update YouTube thumbnail in posts");
        }

        // Avoid rate limiting
        thread::sleep(Duration::from_secs(1));
    }

    tx.commit().await.expect(COMMIT_FAILED_ERR);
}

/// Migrates from UUID-based media paths to key-based paths.
///
/// Renames media directories from UUID format to the new key format
/// and removes the now unused UUID column.
async fn uuid_to_key(db: PgPool) {
    use uuid::Uuid;
    let mut tx = db.begin().await.expect(BEGIN_FAILED_ERR);

    // Check if the UUID column exists before proceeding
    let exists: bool = sqlx::query_scalar(concat!(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns ",
        "WHERE table_name = 'posts' AND column_name = 'uuid')"
    ))
    .fetch_one(&mut *tx)
    .await
    .expect("Failed to check if uuid column exists");

    if !exists {
        println!("uuid column does not exist, skipping migration");
        return;
    }

    /// Structure to hold UUID-key pairs
    #[derive(sqlx::FromRow, Debug)]
    struct UuidKeyPair {
        uuid: Uuid,
        key: String,
    }

    // Get all UUID-key pairs for posts with media
    let pairs: Vec<UuidKeyPair> = sqlx::query_as(
        "SELECT uuid, key FROM posts WHERE uuid IS NOT NULL AND media_category IS NOT NULL ",
    )
    .fetch_all(&mut *tx)
    .await
    .expect("Failed to fetch posts for uuid_to_key migration");

    // Rename media directories
    for pair in pairs {
        println!("Migrating {} to {}", pair.uuid, pair.key);
        let uuid_dir = format!("pub/media/{}", pair.uuid);

        if !std::path::Path::new(&uuid_dir).exists() {
            println!("Media directory for uuid does not exist, skipping");
            continue;
        }

        tokio::fs::rename(&uuid_dir, format!("pub/media/{}", pair.key))
            .await
            .expect("Failed to rename media directory");
    }

    // Remove the UUID column now that it's no longer needed
    sqlx::query("ALTER TABLE posts DROP COLUMN uuid")
        .execute(&mut *tx)
        .await
        .expect("Failed to drop uuid column");

    tx.commit().await.expect(COMMIT_FAILED_ERR);
}

/// Generates thumbnails for image posts.
///
/// Creates smaller versions of images for faster loading and
/// updates the database with the thumbnail paths and dimensions.
async fn generate_image_thumbnails(db: PgPool) {
    use apabbs::post::{Post, PostReview};
    let mut tx = db.begin().await.expect(BEGIN_FAILED_ERR);

    // Get all image posts
    let posts: Vec<Post> = sqlx::query_as(concat!(
        "SELECT * FROM posts WHERE media_category = 'image' ",
        "AND status IN ('approved', 'delisted')",
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("Failed to select posts with images");

    for post in posts {
        let published_media_path = post.published_media_path();
        println!(
            "Generating thumbnail for media {}",
            published_media_path.to_str().unwrap()
        );

        // Generate thumbnail
        let thumbnail_path = PostReview::generate_image_thumbnail(&published_media_path).await;
        if !thumbnail_path.exists() {
            eprintln!("Thumbnail not created successfully");
            std::process::exit(1);
        }

        // Skip if thumbnail is larger than original (defeats the purpose)
        if PostReview::thumbnail_is_larger(&thumbnail_path, &published_media_path) {
            println!("Thumbnail is larger than original, deleting");
            tokio::fs::remove_file(&thumbnail_path)
                .await
                .expect("Failed to remove thumbnail file");
            continue;
        }

        // Update database with thumbnail information
        println!("Setting thumb_filename, thumb_width, thumb_height");
        let (width, height) = PostReview::image_dimensions(&thumbnail_path).await;
        post.update_thumbnail(&mut *tx, &thumbnail_path, width, height)
            .await;
    }

    tx.commit().await.expect(COMMIT_FAILED_ERR);
}

/// Adds width and height information to image posts.
///
/// Updates the database with dimension information for both original images
/// and their thumbnails.
async fn add_image_dimensions(db: PgPool) {
    use apabbs::post::{Post, PostReview};
    let mut tx = db.begin().await.expect(BEGIN_FAILED_ERR);

    // Get all image posts
    let posts: Vec<Post> = sqlx::query_as(concat!(
        "SELECT * FROM posts WHERE media_category = 'image' ",
        "AND status IN ('approved', 'delisted')",
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("Failed to select posts with images");

    for post in posts {
        let published_media_path = post.published_media_path();
        println!(
            "Adding dimensions for media {}",
            published_media_path.to_str().unwrap()
        );

        // Update original image dimensions
        let (width, height) = PostReview::image_dimensions(&published_media_path).await;
        println!("Setting media image dimensions: {}x{}", width, height);
        post.update_media_dimensions(&mut *tx, width, height).await;

        // Update thumbnail dimensions if present
        if post.thumb_filename.is_some() {
            let thumbnail_path = post.thumbnail_path();
            let (width, height) = PostReview::image_dimensions(&thumbnail_path).await;
            println!("Setting thumbnail image dimensions: {}x{}", width, height);
            post.update_thumbnail(&mut *tx, &thumbnail_path, width, height)
                .await;
        }
    }

    tx.commit().await.expect(COMMIT_FAILED_ERR);
}

/// Processes video posts: cleans up media files, generates posters/thumbnails, and updates dimensions.
async fn process_videos(db: PgPool) {
    use apabbs::post::{Post, PostReview, media::MEDIA_DIR};
    let mut tx = db.begin().await.expect(BEGIN_FAILED_ERR);

    // Get all video posts
    let posts: Vec<Post> = sqlx::query_as(concat!(
        "SELECT * FROM posts WHERE media_category = 'video' ",
        "AND status IN ('approved', 'delisted')",
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("Failed to select posts with videos");

    for post in posts {
        println!("Processing video for post {}...", post.key);
        // Iterate over media files and delete all besides the source video
        let media_key_dir = std::path::Path::new(MEDIA_DIR).join(&post.key);
        if media_key_dir.exists() {
            let mut read_dir = tokio::fs::read_dir(&media_key_dir)
                .await
                .expect("Failed to read media directory");

            while let Some(entry) = read_dir
                .next_entry()
                .await
                .expect("Failed to read next directory entry")
            {
                let path = entry.path();
                // Skip the source video file
                if path.file_name().unwrap().to_string_lossy()
                    != post.media_filename.as_ref().unwrap().as_str()
                {
                    println!("Deleting old media file: {}", path.display());
                    tokio::fs::remove_file(&path)
                        .await
                        .expect("Failed to remove old media file");
                }
            }
        }
        PostReview::process_video(&mut *tx, &post)
            .await
            .expect("Failed to process video");
        println!("Completed processing post {}", post.key);
    }

    tx.commit().await.expect(COMMIT_FAILED_ERR);
    println!("All video processing complete");
}
