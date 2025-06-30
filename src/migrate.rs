//! Database migration utilities for the application.
//!
//! Provides sequential database migrations, tracking applied migrations in the `_rust_migrations` table.

use apabbs::user::AccountRole;
use sqlx::PgPool;
use std::future::Future;
use std::pin::Pin;

/// Type alias for migration functions that take a database connection pool
/// and return an async operation.
pub type MigrationFn = fn(PgPool) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Macro to create an array of migration functions paired with their names.
///
/// Each function name is converted to a string and paired with the function itself.
/// This allows migrations to be tracked by name in the database.
#[macro_export]
macro_rules! migrations {
    ($($func:ident),* $(,)?) => {
        [$((stringify!($func), (|db| Box::pin($func(db))) as MigrationFn)),*]
    };
}

/// Application entry point for running migrations.
///
/// Registers and applies all migrations in order, tracking them in the database.
#[tokio::main]
pub async fn main() {
    tracing_subscriber::fmt().init();

    // Register all migrations in the order they should be applied
    let migrations = migrations![
        uuid_to_key,
        download_youtube_thumbnails,
        generate_image_thumbnails,
        update_intro_limit,
        add_image_dimensions,
        process_videos,
        rerun_failed_tasks,
    ];

    // Load environment variables from .env file
    if let Err(error) = dotenv::dotenv() {
        tracing::error!("Failed to load .env file: {error}");
        std::process::exit(1);
    }

    // Connect to database
    let db = apabbs::db().await;

    // Force execution of a specific migration if provided as an argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 {
        // Run a specific migration by name, even if already applied
        let migration_name = &args[1];
        let found = migrations.iter().find(|(name, _)| name == migration_name);
        if let Some((name, func)) = found {
            tracing::info!(migration = name, "Forcing execution of migration");
            func(db.clone()).await;
        } else {
            tracing::error!("Migration not found: {migration_name}");
            std::process::exit(1);
        }
        return;
    }

    // Process each migration (default behavior)
    for (name, func) in migrations {
        // Check if migration has already been applied
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _rust_migrations WHERE name = $1)")
                .bind(name)
                .fetch_one(&db)
                .await
                .expect("query succeeds");

        if exists {
            continue;
        }

        tracing::info!(migration = name, "Applying migration");
        func(db.clone()).await;

        // Record that migration was applied
        sqlx::query("INSERT INTO _rust_migrations (name) VALUES ($1)")
            .bind(name)
            .execute(&db)
            .await
            .expect("query succeeds");
    }
}

/// Updates post intro_limit values based on content analysis.
///
/// Recalculates the intro_limit field for all posts that have it set.
pub async fn update_intro_limit(db: PgPool) {
    use apabbs::post::{Post, PostSubmission};
    let mut tx = db.begin().await.expect("begins");
    let posts: Vec<Post> = sqlx::query_as("SELECT * FROM posts WHERE intro_limit IS NOT NULL")
        .fetch_all(&mut *tx)
        .await
        .expect("fetches posts");

    for post in posts {
        let intro_limit = PostSubmission::intro_limit(&post.body);
        sqlx::query("UPDATE posts SET intro_limit = $1 WHERE id = $2")
            .bind(intro_limit)
            .bind(post.id)
            .execute(&mut *tx)
            .await
            .expect("query succeeds");
    }
    tx.commit().await.expect("commits");
}

/// Downloads YouTube thumbnails for posts containing YouTube links.
///
/// Finds YouTube links in posts, determines if they're shorts or regular videos,
/// downloads appropriate thumbnails, and updates post content with the new thumbnail URLs.
pub async fn download_youtube_thumbnails(db: PgPool) {
    use apabbs::post::PostSubmission;
    use tokio::time::Duration;

    let mut tx = db.begin().await.expect("begins");

    // Extract all YouTube video IDs from posts with YouTube embeds
    let video_ids: Vec<String> = sqlx::query_scalar(concat!(
        "SELECT matches[1] AS video_id FROM ",
        "(SELECT regexp_matches(body, ",
        r#"'<a href="https://www\\.youtube\\.com/(?:watch\?v=|shorts/)([\w\-]{11})', 'g') "#,
        r#"FROM posts WHERE body LIKE '%<img src="/youtube/%' "#,
        "AND status IN ('approved', 'delisted')) ",
        " AS subquery(matches)"
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("selects youtube links");

    for video_id in video_ids {
        tracing::info!(video_id, "Downloading thumbnail for video");

        // Check if the YouTube video is a short
        let response_code = std::process::Command::new("curl")
            .args([
                "--silent",
                "--output",
                "/dev/null",
                "--write-out",
                "'%{http_code}'",
            ])
            .arg(format!("https://www.youtube.com/shorts/{video_id}"))
            .output()
            .expect("checks response code")
            .stdout;
        let short = response_code == b"'200'";

        if short {
            tracing::info!("Video is a YouTube short");
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
            .expect("query succeeds");
        }

        // Download thumbnail and get dimensions
        if let Some((local_thumbnail_path, width, height)) =
            PostSubmission::download_youtube_thumbnail(&video_id, short)
                .await
                .expect("download succeeds")
        {
            // Remove pub prefix from path for URL
            let thumbnail_url = local_thumbnail_path
                .to_str()
                .unwrap()
                .strip_prefix("pub")
                .expect("strips pub prefix");

            tracing::info!("Saved thumbnail to {thumbnail_url} ({width}x{height})");

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
            .expect("query succeeds");
        }

        // Avoid rate limiting
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    tx.commit().await.expect("commits");
}

/// Migrates from UUID-based media paths to key-based paths.
///
/// Renames media directories from UUID format to the new key format and removes the now unused UUID column.
pub async fn uuid_to_key(db: PgPool) {
    use uuid::Uuid;
    let mut tx = db.begin().await.expect("begins");

    // Check if the UUID column exists before proceeding
    let exists: bool = sqlx::query_scalar(concat!(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns ",
        "WHERE table_name = 'posts' AND column_name = 'uuid')"
    ))
    .fetch_one(&mut *tx)
    .await
    .expect("checks uuid column");

    if !exists {
        tracing::info!("uuid column does not exist, skipping migration");
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
    .expect("fetches posts");

    // Rename media directories
    for pair in pairs {
        tracing::info!(from = %pair.uuid, to = %pair.key, "Migrating");
        let uuid_dir = format!("pub/media/{}", pair.uuid);

        if !std::path::Path::new(&uuid_dir).exists() {
            tracing::info!("Media directory for uuid does not exist, skipping");
            continue;
        }

        tokio::fs::rename(&uuid_dir, format!("pub/media/{}", pair.key))
            .await
            .expect("renames dir");
    }

    // Remove the UUID column now that it's no longer needed
    sqlx::query("ALTER TABLE posts DROP COLUMN uuid")
        .execute(&mut *tx)
        .await
        .expect("query succeeds");

    tx.commit().await.expect("commits");
}

/// Generates thumbnails for image posts.
///
/// Creates smaller versions of images for faster loading and updates the database with the thumbnail paths and dimensions.
pub async fn generate_image_thumbnails(db: PgPool) {
    use apabbs::post::{Post, PostReview};
    let mut tx = db.begin().await.expect("begins");

    // Get all image posts
    let posts: Vec<Post> = sqlx::query_as(concat!(
        "SELECT * FROM posts WHERE media_category = 'image' ",
        "AND status IN ('approved', 'delisted')",
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("selects images");

    for post in posts {
        let published_media_path = post.published_media_path();
        tracing::info!(
            "Generating thumbnail for media {}",
            published_media_path.to_str().unwrap()
        );

        // Generate thumbnail
        let thumbnail_path = PostReview::generate_image_thumbnail(&published_media_path)
            .await
            .expect("generation succeeds");
        if !thumbnail_path.exists() {
            tracing::error!("Thumbnail not created successfully");
            std::process::exit(1);
        }

        // Skip if thumbnail is larger than original (defeats the purpose)
        if PostReview::thumbnail_is_larger(&thumbnail_path, &published_media_path)
            .expect("comparison succeeds")
        {
            tracing::info!("Thumbnail is larger than original, deleting");
            tokio::fs::remove_file(&thumbnail_path)
                .await
                .expect("removes file");
            continue;
        }

        // Update database with thumbnail information
        tracing::info!("Setting thumb_filename, thumb_width, thumb_height");
        let (width, height) = PostReview::image_dimensions(&thumbnail_path)
            .await
            .expect("gets dimensions");
        post.update_thumbnail(&mut tx, &thumbnail_path, width, height)
            .await
            .expect("query succeeds");
    }

    tx.commit().await.expect("commits");
}

/// Adds width and height information to image posts.
///
/// Updates the database with dimension information for both original images
/// and their thumbnails.
pub async fn add_image_dimensions(db: PgPool) {
    use apabbs::post::{Post, PostReview};
    let mut tx = db.begin().await.expect("begins");

    // Get all image posts
    let posts: Vec<Post> = sqlx::query_as(concat!(
        "SELECT * FROM posts WHERE media_category = 'image' ",
        "AND status IN ('approved', 'delisted')",
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("selects images");

    for post in posts {
        let published_media_path = post.published_media_path();
        tracing::info!(
            "Adding dimensions for media {}",
            published_media_path.to_str().unwrap()
        );

        // Update original image dimensions
        let (width, height) = PostReview::image_dimensions(&published_media_path)
            .await
            .expect("gets dimensions");
        tracing::info!("Setting media image dimensions: {width}x{height}");
        post.update_media_dimensions(&mut tx, width, height)
            .await
            .expect("query succeeds");

        // Update thumbnail dimensions if present
        if post.thumb_filename.is_some() {
            let thumbnail_path = post.thumbnail_path();
            let (width, height) = PostReview::image_dimensions(&thumbnail_path)
                .await
                .expect("gets dimensions");
            tracing::info!("Setting thumbnail image dimensions: {width}x{height}");
            post.update_thumbnail(&mut tx, &thumbnail_path, width, height)
                .await
                .expect("query succeeds");
        }
    }

    tx.commit().await.expect("commits");
}

/// Processes video posts: cleans up media files, generates posters/thumbnails, and updates dimensions.
pub async fn process_videos(db: PgPool) {
    use apabbs::post::{Post, PostReview, media::MEDIA_DIR};
    let mut tx = db.begin().await.expect("begins");

    // Get all video posts
    let posts: Vec<Post> = sqlx::query_as(concat!(
        "SELECT * FROM posts WHERE media_category = 'video' ",
        "AND status IN ('approved', 'delisted')",
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("selects videos");

    for post in posts {
        tracing::info!(post_key = post.key, "Processing video for post");
        // Iterate over media files and delete all besides the source video
        let media_key_dir = std::path::Path::new(MEDIA_DIR).join(&post.key);
        if media_key_dir.exists() {
            let mut read_dir = tokio::fs::read_dir(&media_key_dir)
                .await
                .expect("reads dir");

            while let Some(entry) = read_dir.next_entry().await.expect("reads entry") {
                let path = entry.path();
                // Skip the source video file
                if path.file_name().unwrap().to_string_lossy()
                    != post.media_filename.as_ref().unwrap().as_str()
                {
                    tracing::info!(file = %path.display(), "Deleting old media file");
                    tokio::fs::remove_file(&path).await.expect("removes file");
                }
            }
        }
        PostReview::process_video(&mut tx, &post)
            .await
            .expect("processes video");
        tracing::info!(post_key = post.key, "Completed processing post");
    }

    tx.commit().await.expect("commits");
    tracing::info!("All video processing complete");
}

/// Attempts to continue processing of any post that was interrupted.
pub async fn rerun_failed_tasks(db: PgPool) {
    use apabbs::post::{Post, PostReview, PostStatus, PostStatus::*, ReviewAction::*};

    let mut tx = db.begin().await.expect("begins");

    // Get all posts that are in Processing state
    let posts: Vec<Post> =
        sqlx::query_as(concat!("SELECT * FROM posts WHERE status = 'processing'",))
            .fetch_all(&mut *tx)
            .await
            .expect("selects processing posts");

    for post in posts {
        // Select the latest two review statuses for the post
        let statuses: Vec<PostStatus> = sqlx::query_scalar(
            "SELECT status FROM reviews WHERE post_id = $1 ORDER BY id DESC LIMIT 2",
        )
        .bind(post.id)
        .fetch_all(&mut *tx)
        .await
        .expect("selects latest review statuses");

        // If the second status does not exist, set the post to Pending.
        // Otherwise, update the post to the second status.
        let next_status = statuses[0];
        let restore_status = if statuses.len() < 2 {
            Pending
        } else {
            statuses[1]
        };
        tracing::info!(
            post_key = post.key,
            "Restoring post status to {:?}",
            restore_status
        );
        let post = post.update_status(&mut tx, restore_status)
            .await
            .expect("updates post status");

        let action = PostReview::determine_action(&post, next_status, AccountRole::Admin)
            .expect("determines action");
        tracing::info!(post_key = post.key, "Determined action: {:?}", action);

        // Only PublishMedia and ReencryptMedia actions are allowed to continue processing
        match action {
            PublishMedia => {
                tracing::info!(post_key = post.key, "Continue publishing media");
                PostReview::publish_media(&mut tx, &post)
                    .await
                    .expect("publishes media");
            }
            ReencryptMedia => {
                tracing::info!(post_key = post.key, "Continue re-encrypting media");
                post.reencrypt_media_file().await.expect("reencrypts media");
            }
            _ => {
                tracing::error!(post_key = post.key, "Invalid action for post: {:?}", action);
                continue; // Skip to next post if action is not allowed
            }
        }

        tracing::info!(post_key = post.key, "Post action completed: {:?}", action);

        // Update status to next status
        post.update_status(&mut tx, next_status)
            .await
            .expect("updates post status");

        tracing::info!(
            post_key = post.key,
            "Post updated to status: {:?}",
            next_status
        );
    }

    tx.commit().await.expect("commits");
}
