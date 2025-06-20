//! Database migration utilities for the application.
//!
//! This module provides functionality to run database migrations sequentially,
//! tracking which ones have already been applied in a `_rust_migrations` table.

use apabbs::{BEGIN, COMMIT};
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
        [$(
            (stringify!($func), (|db| Box::pin($func(db))) as MigrationFn)
        ),*]
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
        eprintln!("Error loading .env file: {}", error);
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
                .expect("check if migration needed");

        if exists {
            continue;
        }

        println!("migrating: {name}");
        func(db.clone()).await;

        // Record that migration was applied
        sqlx::query("INSERT INTO _rust_migrations (name) VALUES ($1)")
            .bind(name)
            .execute(&db)
            .await
            .expect("insert migration record");
    }
}

/// Updates post intro_limit values based on content analysis.
///
/// Recalculates the intro_limit_opt field for all posts that have it set.
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

/// Downloads YouTube thumbnails for posts containing YouTube links.
///
/// Finds YouTube links in posts, determines if they're shorts or regular videos,
/// downloads appropriate thumbnails, and updates post content with the new thumbnail URLs.
async fn download_youtube_thumbnails(db: PgPool) {
    use apabbs::post::PostSubmission;
    use std::thread;
    use tokio::time::Duration;

    let mut tx = db.begin().await.expect(BEGIN);

    // Extract all YouTube video IDs from posts with YouTube embeds
    let video_ids: Vec<String> = sqlx::query_scalar(concat!(
        "SELECT matches[1] AS video_id FROM ",
        "(SELECT regexp_matches(body, ",
        r#"'<a href="https://www\.youtube\.com/(?:watch\?v=|shorts/)([\w\-]{11})', 'g') "#,
        r#"FROM posts WHERE body LIKE '%<img src="/youtube/%' "#,
        "AND status IN ('approved', 'delisted')) ",
        " AS subquery(matches)"
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("selects youtube links");

    // Process each video ID
    for video_id in video_ids {
        println!("downloading thumbnail for video {}", video_id);

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
            .expect("checks response code for youtube short")
            .stdout;
        let short = response_code == b"'200'";

        if short {
            println!("youtube is a short");
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
            .expect("updates youtube link to be short");
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
                .expect("strips pub prefix");

            println!("saved to {thumbnail_url} ({width}x{height})");

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
            .expect("updates youtube thumbnail in posts");
        }

        // Avoid rate limiting
        thread::sleep(Duration::from_secs(1));
    }

    tx.commit().await.expect(COMMIT);
}

/// Migrates from UUID-based media paths to key-based paths.
///
/// Renames media directories from UUID format to the new key format
/// and removes the now unused UUID column.
async fn uuid_to_key(db: PgPool) {
    use uuid::Uuid;
    let mut tx = db.begin().await.expect(BEGIN);

    // Check if the UUID column exists before proceeding
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

    // Define structure to hold UUID-key pairs
    #[derive(sqlx::FromRow, Debug)]
    struct UuidKeyPair {
        uuid: Uuid,
        key: String,
    }

    // Get all UUID-key pairs for posts with media
    let pairs: Vec<UuidKeyPair> = sqlx::query_as(
        "SELECT uuid, key FROM posts WHERE uuid IS NOT NULL AND media_category_opt IS NOT NULL ",
    )
    .fetch_all(&mut *tx)
    .await
    .expect("fetch posts for migration");

    // Rename media directories
    for pair in pairs {
        println!("migrating {} to {}", pair.uuid, pair.key);
        let uuid_dir = format!("pub/media/{}", pair.uuid);

        if !std::path::Path::new(&uuid_dir).exists() {
            println!("media directory for uuid does not exist, skipping");
            continue;
        }

        tokio::fs::rename(uuid_dir, format!("pub/media/{}", pair.key))
            .await
            .expect("rename media directory");
    }

    // Remove the UUID column now that it's no longer needed
    sqlx::query("ALTER TABLE posts DROP COLUMN uuid")
        .execute(&mut *tx)
        .await
        .expect("drop uuid column");

    tx.commit().await.expect(COMMIT);
}

/// Generates thumbnails for image posts.
///
/// Creates smaller versions of images for faster loading and
/// updates the database with the thumbnail paths and dimensions.
async fn generate_image_thumbnails(db: PgPool) {
    use apabbs::post::{Post, PostReview};
    let mut tx = db.begin().await.expect(BEGIN);

    // Get all image posts
    let posts: Vec<Post> = sqlx::query_as(concat!(
        "SELECT * FROM posts WHERE media_category_opt = 'image' ",
        "AND status IN ('approved', 'delisted')",
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

        // Generate thumbnail
        let thumbnail_path = PostReview::generate_image_thumbnail(&published_media_path).await;
        if !thumbnail_path.exists() {
            eprintln!("thumbnail not created successfully");
            std::process::exit(1);
        }

        // Skip if thumbnail is larger than original (defeats the purpose)
        if PostReview::thumbnail_is_larger(&thumbnail_path, &published_media_path) {
            println!("thumbnail is larger, deleting");
            tokio::fs::remove_file(&thumbnail_path)
                .await
                .expect("remove thumbnail file");
            continue;
        }

        // Update database with thumbnail information
        println!("setting thumb_filename_opt, thumb_width_opt, thumb_height_opt");
        let (width, height) = PostReview::image_dimensions(&thumbnail_path).await;
        post.update_thumbnail(&mut *tx, &thumbnail_path, width, height)
            .await;
    }

    tx.commit().await.expect(COMMIT);
}

/// Adds width and height information to image posts.
///
/// Updates the database with dimension information for both original images
/// and their thumbnails.
async fn add_image_dimensions(db: PgPool) {
    use apabbs::post::{Post, PostReview};
    let mut tx = db.begin().await.expect(BEGIN);

    // Get all image posts
    let posts: Vec<Post> = sqlx::query_as(concat!(
        "SELECT * FROM posts WHERE media_category_opt = 'image' ",
        "AND status IN ('approved', 'delisted')",
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

        // Update original image dimensions
        let (width, height) = PostReview::image_dimensions(&published_media_path).await;
        println!("setting media image dimensions: {}x{}", width, height);
        post.update_media_dimensions(&mut *tx, width, height).await;

        // Update thumbnail dimensions if present
        if post.thumb_filename_opt.is_some() {
            let thumbnail_path = post.thumbnail_path();
            let (width, height) = PostReview::image_dimensions(&thumbnail_path).await;
            println!("setting thumbnail image dimensions: {}x{}", width, height);
            post.update_thumbnail(&mut *tx, &thumbnail_path, width, height)
                .await;
        }
    }

    tx.commit().await.expect(COMMIT);
}

/// Process videos
///
/// Create posters, thumbnails, compatibility videos, and add dimensions.
async fn process_videos(db: PgPool) {
    use apabbs::post::{Post, PostReview};
    let mut tx = db.begin().await.expect(BEGIN);

    // Get all video posts
    let posts: Vec<Post> = sqlx::query_as(concat!(
        "SELECT * FROM posts WHERE media_category_opt = 'video' ",
        "AND status IN ('approved', 'delisted')",
    ))
    .fetch_all(&mut *tx)
    .await
    .expect("selects posts with videos");

    for post in posts {
        PostReview::process_video(&mut *tx, &post)
            .await
            .expect("process video");
    }

    tx.commit().await.expect(COMMIT);
}

// /// Adds width and height information to video posts.
// ///
// /// Updates the database with dimension information for videos.
// async fn add_video_dimensions(db: PgPool) {
//     use apabbs::post::{Post, PostReview};
//     let mut tx = db.begin().await.expect(BEGIN);

//     // Get all video posts
//     let posts: Vec<Post> = sqlx::query_as(concat!(
//         "SELECT * FROM posts WHERE media_category_opt = 'video' ",
//         "AND status IN ('approved', 'delisted')",
//     ))
//     .fetch_all(&mut *tx)
//     .await
//     .expect("selects posts with videos");

//     for post in posts {
//         let published_media_path = post.published_media_path();
//         println!(
//             "adding dimensions for media {}",
//             published_media_path.to_str().unwrap()
//         );

//         // Extract and save video dimensions
//         let (width, height) = PostReview::video_dimensions(&published_media_path).await;
//         println!("setting video dimensions: {}x{}", width, height);
//         post.update_media_dimensions(&mut *tx, width, height).await;
//     }

//     tx.commit().await.expect(COMMIT);
// }

// /// Generates thumbnails for video posts.
// ///
// /// Creates static image thumbnails for videos and updates
// /// the database with the thumbnail paths and dimensions.
// async fn generate_video_thumbnails(db: PgPool) {
//     use apabbs::post::{Post, PostReview};
//     let mut tx = db.begin().await.expect(BEGIN);

//     // Get all video posts
//     let posts: Vec<Post> = sqlx::query_as(concat!(
//         "SELECT * FROM posts WHERE media_category_opt = 'video' ",
//         "AND status IN ('approved', 'delisted')",
//     ))
//     .fetch_all(&mut *tx)
//     .await
//     .expect("selects posts with videos");

//     for post in posts {
//         let published_media_path = post.published_media_path();
//         println!(
//             "generating thumbnail for media {}",
//             published_media_path.to_str().unwrap()
//         );

//         // Generate video thumbnail
//         let thumbnail_path = PostReview::generate_compatibility_video(&published_media_path).await;
//         if !thumbnail_path.exists() {
//             eprintln!("thumbnail not created successfully");
//             std::process::exit(1);
//         }

//         // Update database with thumbnail information
//         println!("setting thumb_filename_opt, thumb_width_opt, thumb_height_opt");
//         let (width, height) = PostReview::video_dimensions(&thumbnail_path).await;
//         post.update_thumbnail(&mut *tx, &thumbnail_path, width, height)
//             .await;
//     }

//     tx.commit().await.expect(COMMIT);
// }

// /// Generates poster images for videos and their thumbnails.
// ///
// /// Creates static poster images for both videos and their thumbnails,
// /// updating the database with the poster paths.
// async fn generate_video_posters(db: PgPool) {
//     use apabbs::post::{Post, PostReview};
//     let mut tx = db.begin().await.expect(BEGIN);

//     // Get all video posts
//     let posts: Vec<Post> = sqlx::query_as(concat!(
//         "SELECT * FROM posts WHERE media_category_opt = 'video' ",
//         "AND status IN ('approved', 'delisted')",
//     ))
//     .fetch_all(&mut *tx)
//     .await
//     .expect("selects posts with video");

//     for post in posts {
//         let published_media_path = post.published_media_path();
//         println!(
//             "generating poster for media {}",
//             published_media_path.to_str().unwrap()
//         );

//         // Generate posters for both video and thumbnail
//         let thumbnail_path = post.thumbnail_path();
//         let (video_poster_path, thumb_poster_path) = tokio::join!(
//             PostReview::generate_video_poster(&published_media_path),
//             PostReview::generate_video_poster(&thumbnail_path)
//         );

//         if !video_poster_path.exists() || !thumb_poster_path.exists() {
//             eprintln!("poster not created successfully");
//             std::process::exit(1);
//         }

//         // Update database with poster paths
//         println!("setting video_poster_opt");
//         post.update_poster(&mut *tx, &video_poster_path).await;
//     }

//     tx.commit().await.expect(COMMIT);
// }
