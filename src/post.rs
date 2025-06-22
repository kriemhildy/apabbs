//! Post content management and media processing functionality.
//!
//! This module provides the core data structures and functions for:
//! - Post creation, submission, and moderation
//! - Media file processing (encryption, decryption, thumbnailing)
//! - YouTube embed handling and thumbnail caching
//! - Content formatting and preview generation
//!
//! The main types include:
//! - `Post`: A complete post object with all its metadata
//! - `PostSubmission`: User-submitted content before processing
//! - `PostReview`: Moderation actions for post approval/rejection
//! - `PostHiding`: User requests to hide their own posts

// TODO: split this into smaller files

pub mod review;
pub mod submission;

use crate::{
    POSTGRES_HTML_DATETIME, POSTGRES_RFC5322_DATETIME,
    user::{AccountRole, User},
};
pub use review::{PostReview, ReviewAction, ReviewError};
use sqlx::{PgConnection, Postgres, QueryBuilder};
use std::path::PathBuf;
pub use submission::PostSubmission;
use uuid::Uuid;

/// File system directories
pub const UPLOADS_DIR: &str = "uploads"; // Encrypted storage
pub const MEDIA_DIR: &str = "pub/media"; // Published media

/// Content limits
const MAX_THUMB_WIDTH: i32 = 1280; // Maximum width for thumbnails
const MAX_THUMB_HEIGHT: i32 = 2160; // Maximum height for thumbnails

/// MIME types
const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";

/// Post status indicates the moderation/approval state of a post
#[derive(
    sqlx::Type, serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug, Copy, Default,
)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "post_status", rename_all = "snake_case")]
pub enum PostStatus {
    #[default]
    Pending, // Awaiting moderation review
    Processing, // Currently processing media
    Approved,   // Publicly visible
    Delisted,   // Visible only via direct link
    Reported,   // Under review after being reported
    Rejected,   // Declined by moderators
    Banned,     // Removed for policy violations
}

/// Media category identifies the type of media attached to a post
#[derive(sqlx::Type, serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "media_category", rename_all = "snake_case")]
pub enum MediaCategory {
    Image, // Images (jpg, png, webp, etc.)
    Video, // Video formats (mp4, webm, etc.)
    Audio, // Audio formats (mp3, wav, etc.)
}

/// Represents a post in the system including its content, status, and associated media
///
/// Posts can be associated with either a registered user account (account_id)
/// or an anonymous session (session_token), but not both.
#[derive(sqlx::FromRow, serde::Serialize, Clone, Debug, Default)]
pub struct Post {
    /// Unique database identifier for the post
    pub id: i32,
    /// HTML-formatted content of the post
    pub body: String,
    /// Optional reference to the account that created this post
    pub account_id: Option<i32>,
    /// Current moderation/approval status of the post
    pub status: PostStatus,
    /// For anonymous posts, the session token of the creator
    pub session_token: Option<Uuid>,
    /// Anonymized hash of the creator's IP address for anti-abuse
    pub ip_hash: Option<String>,
    /// Original filename of uploaded media, if present
    pub media_filename: Option<String>,
    /// Type of media (Image, Video, Audio) if present
    pub media_category: Option<MediaCategory>,
    /// MIME type of the media file if present
    pub media_mime_type: Option<String>,
    /// Filename of generated thumbnail if available
    pub thumb_filename: Option<String>,
    /// Unique URL-friendly identifier for the post
    pub key: String,
    /// Whether this post contains YouTube embeds
    pub youtube: bool,
    /// Character offset where the post should be truncated in previews
    pub intro_limit: Option<i32>,
    /// Width of the original media in pixels
    pub media_width: Option<i32>,
    /// Height of the original media in pixels
    pub media_height: Option<i32>,
    /// Width of the thumbnail in pixels
    pub thumb_width: Option<i32>,
    /// Height of the thumbnail in pixels
    pub thumb_height: Option<i32>,
    /// Filename of the poster image for video media
    pub video_poster: Option<String>,
    /// Filename of compatibility video (H.264) for non-Chromium browsers
    pub compat_video: Option<String>,
    /// Creation timestamp formatted according to RFC5322 for display
    #[sqlx(default)]
    pub created_at_rfc5322: Option<String>,
    /// Creation timestamp formatted for HTML datetime attribute
    #[sqlx(default)]
    pub created_at_html: Option<String>,
    /// Whether this post was created within the last 2 days
    #[sqlx(default)]
    pub recent: Option<bool>,
}

impl Post {
    /// Selects posts visible to the user according to their access level
    ///
    /// Filters posts by status based on the user's role:
    /// - Admins: all posts except rejected
    /// - Mods: all except rejected and reported
    /// - Others: only approved posts
    ///
    /// Additionally shows posts created by the user regardless of status.
    ///
    /// # Parameters
    /// - `tx`: Database connection
    /// - `user`: Current user with session and account info
    /// - `post_id`: Optional ID for pagination
    /// - `invert`: Whether to invert the sort order
    pub async fn select(
        tx: &mut PgConnection,
        user: &User,
        post_id: Option<i32>,
        invert: bool,
    ) -> Vec<Self> {
        let mut query_builder: QueryBuilder<Postgres> =
            QueryBuilder::new("SELECT * FROM posts WHERE (");

        // Filter by status based on user role
        match user.account {
            Some(ref account) => match account.role {
                AccountRole::Admin => query_builder.push("status <> 'rejected' "),
                AccountRole::Mod => query_builder.push("status NOT IN ('rejected', 'reported') "),
                _ => query_builder.push("status = 'approved' "),
            },
            None => query_builder.push("status = 'approved' "),
        };

        // Always show user's own posts
        query_builder.push("OR session_token = ");
        query_builder.push_bind(&user.session_token);

        if let Some(ref account) = user.account {
            query_builder.push(" OR account_id = ");
            query_builder.push_bind(account.id);
        }

        query_builder.push(") AND hidden = false");

        // Set up pagination parameters
        let (operator, order, limit) = if invert {
            (">", "ASC", crate::per_page()) // sanity limit
        } else {
            ("<=", "DESC", crate::per_page() + 1) // +1 to check if there are more pages
        };

        // Add pagination constraint if post_id is provided
        if let Some(post_id) = post_id {
            query_builder.push(&format!(" AND id {} ", operator));
            query_builder.push_bind(post_id);
        }

        // Add ordering and limit
        query_builder.push(&format!(" ORDER BY id {} LIMIT ", order));
        query_builder.push_bind(limit as i32);

        // Execute query
        query_builder
            .build_query_as()
            .fetch_all(&mut *tx)
            .await
            .expect("select posts")
    }

    /// Selects approved posts created by the specified account
    ///
    /// Returns only posts with status 'approved' and limits the result
    /// to the system-defined page size.
    pub async fn select_by_author(tx: &mut PgConnection, account_id: i32) -> Vec<Self> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE account_id = $1 ",
            "AND status = 'approved' ORDER BY id DESC LIMIT $2",
        ))
        .bind(account_id)
        .bind(crate::per_page() as i32)
        .fetch_all(&mut *tx)
        .await
        .expect("select posts by account")
    }

    /// Checks if the user is the author of this post
    ///
    /// Returns true if either:
    /// - The post's session token matches the user's session token
    /// - The post's account ID matches the user's account ID
    ///
    /// Checks if the user is the author of this post
    ///
    /// # Examples
    ///
    /// ```
    /// use apabbs::post::Post;
    /// use apabbs::user::User;
    /// use uuid::Uuid;
    ///
    /// let session_token = Uuid::new_v4();
    /// let user = User { session_token, account: None };
    /// let post = Post { session_token: Some(session_token), ..Default::default() };
    /// assert!(post.author(&user));
    /// ```
    pub fn author(&self, user: &User) -> bool {
        self.session_token
            .as_ref()
            .is_some_and(|uuid| uuid == &user.session_token)
            || user
                .account
                .as_ref()
                .is_some_and(|a| self.account_id.is_some_and(|id| id == a.id))
    }

    /// Selects a post by its unique key with formatted timestamps
    ///
    /// Also includes a flag indicating if the post is recent (less than 2 days old)
    pub async fn select_by_key(tx: &mut PgConnection, key: &str) -> Option<Self> {
        sqlx::query_as(concat!(
            "SELECT *, to_char(created_at, $1) AS created_at_rfc5322, ",
            "to_char(created_at, $2) AS created_at_html, ",
            "now() - interval '2 days' < created_at AS recent FROM posts WHERE key = $3"
        ))
        .bind(POSTGRES_RFC5322_DATETIME)
        .bind(POSTGRES_HTML_DATETIME)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await
        .expect("select post by key")
    }

    /// Permanently deletes a post from the database
    pub async fn delete(&self, tx: &mut PgConnection) {
        sqlx::query("DELETE FROM posts WHERE id = $1")
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("delete post");
    }

    /// Decrypts the post's media file using GPG
    ///
    /// Returns the decrypted file content as bytes.
    /// This operation is CPU-intensive and runs in a separate thread.
    pub async fn decrypt_media_file(&self) -> Vec<u8> {
        if self.media_filename.is_none() {
            panic!("No media bytes available");
        }

        let encrypted_file_path = self.encrypted_media_path().to_str().unwrap().to_owned();

        // Run GPG decrypt in a separate thread
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new("gpg")
                .args(["--batch", "--decrypt", "--passphrase-file", "gpg.key"])
                .arg(&encrypted_file_path)
                .output()
                .expect("decrypt media file")
        })
        .await
        .expect("decrypt task completed");

        println!("Media file decrypted successfully");
        output.stdout
    }

    /// Returns the path where an encrypted media file is stored
    ///
    /// Panics if the post has no associated media file.
    pub fn encrypted_media_path(&self) -> PathBuf {
        if self.media_filename.is_none() {
            panic!("Attempted to get encrypted_media_path for post without media");
        }

        let encrypted_filename = format!("{}.gpg", self.media_filename.as_ref().unwrap());
        std::path::Path::new(UPLOADS_DIR)
            .join(&self.key)
            .join(encrypted_filename)
    }

    /// Returns the path where published media is stored after processing
    ///
    /// Panics if the post has no associated media file.
    pub fn published_media_path(&self) -> PathBuf {
        if self.media_filename.is_none() {
            panic!("Attempted to get published_media_path for post without media");
        }

        std::path::Path::new(MEDIA_DIR)
            .join(&self.key)
            .join(self.media_filename.as_ref().unwrap())
    }

    /// Returns the path where a thumbnail is stored after processing
    ///
    /// Panics if the post has no associated thumbnail.
    pub fn thumbnail_path(&self) -> PathBuf {
        if self.thumb_filename.is_none() {
            panic!("Attempted to get thumbnail_path for post without thumbnail");
        }

        std::path::Path::new(MEDIA_DIR)
            .join(&self.key)
            .join(self.thumb_filename.as_ref().unwrap())
    }

    /// Encrypts the provided bytes using GPG with the application's key
    ///
    /// This function creates necessary directories, runs GPG to encrypt data,
    /// and handles cleanup in case of errors.
    ///
    /// Returns:
    /// - Ok(()) if encryption succeeded
    /// - Err with a message if encryption failed
    async fn gpg_encrypt(&self, bytes: Vec<u8>) -> Result<(), &str> {
        let encrypted_media_path = self.encrypted_media_path();
        let encrypted_media_path_str = encrypted_media_path.to_str().unwrap().to_owned();

        // Ensure parent directory exists
        let parent_dir = encrypted_media_path.parent().unwrap();
        if !parent_dir.exists() {
            tokio::fs::create_dir_all(parent_dir)
                .await
                .map_err(|_| "Failed to create directory for encrypted media")?;
        }

        // Run GPG encrypt in a separate thread to avoid blocking the async runtime
        let success = tokio::task::spawn_blocking(move || {
            let mut child = std::process::Command::new("gpg")
                .args([
                    "--batch",
                    "--symmetric",
                    "--passphrase-file",
                    "gpg.key",
                    "--output",
                ])
                .arg(&encrypted_media_path_str)
                .stdin(std::process::Stdio::piped())
                .spawn()
                .expect("spawn gpg to encrypt media file");

            // Write data to stdin
            if let Some(mut stdin) = child.stdin.take() {
                std::io::Write::write_all(&mut stdin, &bytes).expect("write data to stdin");
            }

            let child_status = child.wait().expect("wait for gpg to finish");
            child_status.success()
        })
        .await
        .expect("encrypt task completed");

        if success {
            println!(
                "File encrypted successfully: {}",
                encrypted_media_path.display()
            );
            Ok(())
        } else {
            Err("GPG failed to encrypt file")
        }
    }

    /// Updates the status of a post in the database
    pub async fn update_status(&self, tx: &mut PgConnection, new_status: PostStatus) {
        sqlx::query("UPDATE posts SET status = $1 WHERE id = $2")
            .bind(new_status)
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("update post status");
    }

    /// Updates thumbnail metadata for a post
    pub async fn update_thumbnail(
        &self,
        tx: &mut PgConnection,
        thumbnail_path: &PathBuf,
        width: i32,
        height: i32,
    ) {
        let thumbnail_filename = thumbnail_path
            .file_name()
            .expect("get thumbnail filename")
            .to_str()
            .expect("thumbnail filename to str");

        sqlx::query(concat!(
            "UPDATE posts SET thumb_filename = $1, thumb_width = $2, ",
            "thumb_height = $3 WHERE id = $4"
        ))
        .bind(thumbnail_filename)
        .bind(width)
        .bind(height)
        .bind(self.id)
        .execute(&mut *tx)
        .await
        .expect("update post thumbnail");
    }

    /// Update the compatibility video filename for a post
    ///
    ///  This is used to store a fallback video format for browsers that do not support
    ///  the primary video format (e.g., H.264 for non-Chromium browsers).
    ///
    /// # Parameters
    /// - `tx`: Database connection
    /// - `compat_path`: Path to the compatibility video file
    ///
    /// # Panics
    /// Panics if the compatibility video filename cannot be extracted or converted to a string.
    pub async fn update_compat_video(&self, tx: &mut PgConnection, compat_path: &PathBuf) {
        let compat_filename = compat_path
            .file_name()
            .expect("get compatibility video filename")
            .to_str()
            .expect("compatibility video filename to str");
        sqlx::query("UPDATE posts SET compat_video = $1 WHERE id = $2")
            .bind(compat_filename)
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("update post compatibility video");
    }

    /// Re-encrypts a media file that has already been published
    ///
    /// This is used when media needs to be moved back from published to reported state.
    pub async fn reencrypt_media_file(&self) -> Result<(), &str> {
        let encrypted_file_path = self.encrypted_media_path();
        let uploads_key_dir = encrypted_file_path.parent().unwrap();

        // Create the directory for encrypted content
        tokio::fs::create_dir(uploads_key_dir)
            .await
            .expect("create uploads key dir");

        // Read the published media file
        let media_file_path = self.published_media_path();
        let media_bytes = tokio::fs::read(&media_file_path)
            .await
            .expect("read media file");

        // Try to encrypt the file
        let result = self.gpg_encrypt(media_bytes).await;

        match result {
            // If encryption succeeded, clean up the published media
            Ok(()) => PostReview::delete_media_key_dir(&self.key).await,
            // If encryption failed, clean up the temp directory
            Err(msg) => {
                tokio::fs::remove_dir(uploads_key_dir)
                    .await
                    .expect("remove uploads key dir");
                eprintln!("Re-encryption failed: {}", msg);
            }
        }

        result
    }

    /// Updates the media dimensions for a post in the database
    pub async fn update_media_dimensions(&self, tx: &mut PgConnection, width: i32, height: i32) {
        sqlx::query("UPDATE posts SET media_width = $1, media_height = $2 WHERE id = $3")
            .bind(width)
            .bind(height)
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("update media dimensions");
    }

    /// Updates poster filename for videos
    pub async fn update_poster(&self, tx: &mut PgConnection, video_poster_path: &PathBuf) {
        let media_poster_filename = video_poster_path
            .file_name()
            .expect("get media poster filename")
            .to_str()
            .expect("media poster filename to str");

        sqlx::query("UPDATE posts SET video_poster = $1 WHERE id = $2")
            .bind(media_poster_filename)
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("update post posters");
    }
}

/// Represents a request to hide a post from public view
///
/// This structure contains the session token of the user requesting to hide a post
/// and the unique key of the post to be hidden. Used primarily for moderation actions
/// or user-initiated content hiding.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PostHiding {
    /// Session token of the user requesting to hide the post
    pub session_token: Uuid,

    /// Unique key identifier of the post to be hidden
    pub key: String,
}

impl PostHiding {
    /// Sets a post's hidden flag to true in the database
    ///
    /// This effectively removes the post from public view without deleting it.
    /// The post will no longer appear in feeds or search results, but remains
    /// in the database for record-keeping and potential future restoration.
    ///
    /// # Parameters
    /// - `tx`: Database connection for executing the update
    ///
    /// # Note
    /// This method does not verify authorization - the caller must ensure that
    /// the user identified by `session_token` has permission to hide this post.
    pub async fn hide_post(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE posts SET hidden = true WHERE key = $1")
            .bind(&self.key)
            .execute(&mut *tx)
            .await
            .expect("set hidden flag to true");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests post status transitions and review actions for different user roles
    #[tokio::test]
    async fn review_action_permissions() {
        // Create a post with defaults, only setting what we need for this test
        // PostStatus::Pending is already the default
        let post = Post {
            id: 1,
            key: String::from("testkey"),
            ..Default::default()
        };

        // Case 1: Admin approving a pending post
        let review = PostReview {
            session_token: Uuid::new_v4(),
            status: PostStatus::Approved,
        };
        assert_eq!(
            review.determine_action(&post, &AccountRole::Admin),
            Ok(ReviewAction::DecryptMedia)
        );

        // Case 2: Mod trying to modify a reported post (should fail)
        let reported_post = Post {
            status: PostStatus::Reported,
            ..Default::default()
        };
        let review = PostReview {
            session_token: Uuid::new_v4(),
            status: PostStatus::Approved,
        };
        assert_eq!(
            review.determine_action(&reported_post, &AccountRole::Mod),
            Err(ReviewError::AdminOnly)
        );

        // Case 3: Trying to modify a banned post (should fail)
        let banned_post = Post {
            status: PostStatus::Banned,
            ..Default::default()
        };
        let review = PostReview {
            session_token: Uuid::new_v4(),
            status: PostStatus::Approved,
        };
        assert_eq!(
            review.determine_action(&banned_post, &AccountRole::Admin),
            Err(ReviewError::RejectedOrBanned)
        );

        // Case 4: Mod trying to report an approved post (valid action)
        let approved_post = Post {
            status: PostStatus::Approved,
            recent: Some(true),
            ..Default::default()
        };
        let review = PostReview {
            session_token: Uuid::new_v4(),
            status: PostStatus::Reported,
        };
        assert_eq!(
            review.determine_action(&approved_post, &AccountRole::Mod),
            Ok(ReviewAction::ReencryptMedia)
        );

        // Case 5: Mod trying to modify a non-recent approved post (should fail)
        let old_post = Post {
            status: PostStatus::Approved,
            recent: Some(false),
            ..Default::default()
        };
        let review = PostReview {
            session_token: Uuid::new_v4(),
            status: PostStatus::Delisted,
        };
        assert_eq!(
            review.determine_action(&old_post, &AccountRole::Mod),
            Err(ReviewError::RecentOnly)
        );
    }

    /// Tests the author verification functionality
    #[tokio::test]
    async fn post_author_verification() {
        // Create test user with session token
        let session_token = Uuid::new_v4();
        let user = User {
            session_token,
            account: None,
        };

        // Create post with matching session token
        let post_by_session = Post {
            session_token: Some(session_token),
            ..Default::default()
        };

        // Create user with account but different session token
        let user_with_account = User {
            session_token: Uuid::new_v4(),
            account: Some(crate::user::Account {
                id: 123,
                username: String::from("testuser"),
                role: AccountRole::Novice,
                token: Uuid::new_v4(),
                ..Default::default()
            }),
        };

        // Create post with matching account ID
        let post_by_account = Post {
            id: 2,
            session_token: None,
            account_id: Some(123),
            ..Default::default()
        };

        // Test author verification
        assert!(post_by_session.author(&user));
        assert!(!post_by_account.author(&user));
        assert!(post_by_account.author(&user_with_account));
        assert!(!post_by_session.author(&user_with_account));
    }

    /// Tests path construction for media files
    #[tokio::test]
    async fn media_paths() {
        let post = Post {
            key: String::from("abcd1234"),
            media_filename: Some(String::from("test.jpg")),
            thumb_filename: Some(String::from("tn_test.webp")),
            ..Default::default()
        };

        // Test path construction
        assert_eq!(
            post.encrypted_media_path().to_str().unwrap(),
            format!("{}/abcd1234/test.jpg.gpg", UPLOADS_DIR)
        );

        assert_eq!(
            post.published_media_path().to_str().unwrap(),
            format!("{}/abcd1234/test.jpg", MEDIA_DIR)
        );

        assert_eq!(
            post.thumbnail_path().to_str().unwrap(),
            format!("{}/abcd1234/tn_test.webp", MEDIA_DIR)
        );
    }
}
