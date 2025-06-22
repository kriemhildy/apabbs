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

use crate::{
    POSTGRES_HTML_DATETIME, POSTGRES_RFC5322_DATETIME,
    user::{AccountRole, User},
};
use regex::Regex;
use sqlx::{PgConnection, Postgres, QueryBuilder};
use std::path::PathBuf;
use url::Url;
use uuid::Uuid;

/// File system directories
pub const UPLOADS_DIR: &str = "uploads"; // Encrypted storage
pub const MEDIA_DIR: &str = "pub/media"; // Published media
pub const YOUTUBE_DIR: &str = "pub/youtube"; // YouTube thumbnail cache

/// Content limits
const MAX_YOUTUBE_EMBEDS: usize = 16; // Maximum number of YouTube embeds per post
const MAX_INTRO_BYTES: usize = 1600; // Maximum number of bytes for post intro
const MAX_INTRO_BREAKS: usize = 24; // Maximum number of line breaks in intro
const KEY_LENGTH: usize = 8; // Length of randomly generated post keys
const MAX_THUMB_WIDTH: i32 = 1280; // Maximum width for thumbnails
const MAX_THUMB_HEIGHT: i32 = 2160; // Maximum height for thumbnails

/// MIME types
const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";

/// Error messages
const ERR_THUMBNAIL_FAILED: &str = "Thumbnail not created successfully";

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

/// Represents a post submission from a user
///
/// This struct contains all data needed to create a new post including the content,
/// associated media files, and user identification information. It handles converting
/// raw input into properly formatted post content with media processing.
#[derive(Default)]
pub struct PostSubmission {
    /// Session token of the user submitting the post
    pub session_token: Uuid,
    /// Raw text content of the post before HTML processing
    pub body: String,
    /// Original filename of any uploaded media (if present)
    pub media_filename: Option<String>,
    /// Raw bytes of the uploaded media file (if present)
    pub media_bytes: Option<Vec<u8>>,
}

impl PostSubmission {
    /// Generates a unique key for a post
    ///
    /// The key is a random string of alphanumeric characters with a length
    /// defined by the system. Checks the database to ensure the key is unique.
    pub async fn generate_key(tx: &mut PgConnection) -> String {
        use rand::{Rng, distr::Alphanumeric};
        loop {
            let key = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(KEY_LENGTH)
                .map(char::from)
                .collect();
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM posts WHERE key = $1)")
                    .bind(&key)
                    .fetch_one(&mut *tx)
                    .await
                    .expect("check if key exists");
            if !exists {
                return key;
            }
        }
    }

    /// Inserts a new post into the database
    ///
    /// This function handles determining the media type, generating the post key,
    /// and extracting the intro limit from the body content.
    ///
    /// # Parameters
    /// - `tx`: Database connection
    /// - `user`: Current user submitting the post
    /// - `ip_hash`: Anonymized IP hash of the user
    /// - `key`: Unique key for the post
    ///
    /// # Returns
    /// The newly created `Post` object
    pub async fn insert(
        &self,
        tx: &mut PgConnection,
        user: &User,
        ip_hash: &str,
        key: &str,
    ) -> Post {
        let (media_category, media_mime_type) =
            Self::determine_media_type(self.media_filename.as_deref());
        let (session_token, account_id) = match user.account {
            Some(ref account) => (None, Some(account.id)),
            None => (Some(self.session_token), None),
        };
        let html_body = self.body_to_html(key).await;
        let youtube = html_body.contains(r#"<a href="https://www.youtube.com"#);
        let intro_limit = Self::intro_limit(&html_body);
        sqlx::query_as(concat!(
            "INSERT INTO posts (key, session_token, account_id, body, ip_hash, ",
            "media_filename, media_category, media_mime_type, youtube, ",
            "intro_limit) ",
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *",
        ))
        .bind(key)
        .bind(session_token)
        .bind(account_id)
        .bind(&html_body)
        .bind(ip_hash)
        .bind(self.media_filename.as_deref())
        .bind(media_category)
        .bind(media_mime_type.as_deref())
        .bind(youtube)
        .bind(intro_limit)
        .fetch_one(&mut *tx)
        .await
        .expect("insert new post")
    }

    /// Downloads a YouTube thumbnail for the given video ID
    ///
    /// Tries to download the thumbnail in various sizes and returns the path
    /// to the downloaded thumbnail image along with its dimensions.
    ///
    /// # Parameters
    /// - `video_id`: The ID of the YouTube video
    /// - `youtube_short`: Whether the video is a YouTube Shorts video
    ///
    /// # Returns
    /// An optional tuple containing the thumbnail path and its width and height
    pub async fn download_youtube_thumbnail(
        video_id: &str,
        youtube_short: bool,
    ) -> Option<(PathBuf, i32, i32)> {
        println!("Downloading YouTube thumbnail for video ID: {}", video_id);
        fn dimensions(size: &str) -> (i32, i32) {
            match size {
                "maxresdefault" => (1280, 720),
                "sddefault" => (640, 480),
                "hqdefault" => (480, 360),
                "mqdefault" => (320, 180),
                "default" => (120, 90),
                "oar2" => (1080, 1920),
                _ => panic!("invalid thumbnail size"),
            }
        }
        let video_id_dir = std::path::Path::new(YOUTUBE_DIR).join(video_id);
        if video_id_dir.exists() {
            if let Some(first_entry) = video_id_dir.read_dir().expect("reads video id dir").next() {
                let existing_thumbnail_path = first_entry.expect("get first entry").path();
                let size = existing_thumbnail_path
                    .file_name()
                    .expect("get file name")
                    .to_str()
                    .expect("file name to str")
                    .split('.')
                    .next()
                    .expect("get file name without extension");
                let (width, height) = dimensions(size);
                return Some((existing_thumbnail_path, width, height));
            }
        } else {
            tokio::fs::create_dir(&video_id_dir)
                .await
                .expect("create youtube video id dir");
        }
        let thumbnail_sizes = if youtube_short {
            vec!["oar2"]
        } else {
            vec![
                "maxresdefault",
                "sddefault",
                "hqdefault",
                "mqdefault",
                "default",
            ]
        };
        for size in thumbnail_sizes {
            let local_thumbnail_path = video_id_dir.join(format!("{}.jpg", size));
            let remote_thumbnail_url =
                format!("https://img.youtube.com/vi/{}/{}.jpg", video_id, size);
            let curl_status = tokio::process::Command::new("curl")
                .args(["--silent", "--fail", "--output"])
                .arg(&local_thumbnail_path)
                .arg(&remote_thumbnail_url)
                .status()
                .await
                .expect("download youtube thumbnail");
            if curl_status.success() {
                let (width, height) = dimensions(size);
                return Some((local_thumbnail_path, width, height));
            }
        }
        None
    }

    /// Converts the post body from plain text to HTML format
    ///
    /// This function performs basic HTML escaping and replaces URLs with anchor links.
    /// YouTube links are processed to embed thumbnails and video IDs.
    ///
    /// # Parameters
    /// - `key`: The unique key of the post, used for generating YouTube links
    ///
    /// # Returns
    /// The HTML-formatted body of the post
    async fn body_to_html(&self, key: &str) -> String {
        let mut html = self
            .body
            .trim_end()
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&apos;")
            .replace("  ", " &nbsp;")
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .replace("\n", "<br>\n");
        let url_pattern =
            Regex::new(r#"\b(https?://[^\s<]{4,256})\b"#).expect("builds regex pattern");
        let anchor_tag = r#"<a href="$1">$1</a>"#;
        html = url_pattern.replace_all(&html, anchor_tag).to_string();
        Self::embed_youtube(html, key).await
    }

    /// Embeds YouTube video thumbnails in the post HTML
    ///
    /// Scans the post HTML for YouTube links and replaces them with embedded
    /// thumbnail images and video IDs. Generates HTML for the YouTube embed.
    ///
    /// # Parameters
    /// - `html`: The HTML content of the post body
    /// - `key`: The unique key of the post, used in the embed HTML
    ///
    /// # Returns
    /// The HTML content with YouTube embeds
    async fn embed_youtube(mut html: String, key: &str) -> String {
        let youtube_link_pattern = concat!(
            r#"(?m)^ *<a href=""#,
            r#"(https?://(?:youtu\.be/|(?:www\.|m\.)?youtube\.com/"#,
            r#"(watch\S*(?:\?|&amp;)v=|shorts/))"#,
            r#"([^&\s\?]+)\S*)">\S+</a> *(?:<br>)?$"#,
        );
        let youtube_link_regex = Regex::new(youtube_link_pattern).expect("build regex pattern");
        for _ in 0..MAX_YOUTUBE_EMBEDS {
            let captures = match youtube_link_regex.captures(&html) {
                None => break,
                Some(captures) => captures,
            };
            // youtu.be has no match for 2, but is always not a short
            let youtube_short = captures.get(2).is_some_and(|m| m.as_str() == "shorts/");
            let youtube_video_id = &captures[3];
            println!("captures: {:?}", captures);
            let youtube_timestamp = if youtube_short {
                None
            } else {
                let url_str = &captures[1].replace("&amp;", "&");
                let parsed_url = Url::parse(&url_str).expect("parse youtube url");
                parsed_url
                    .query_pairs()
                    .find(|(k, _)| k == "t")
                    .map(|(_, v)| v.to_string())
            };
            println!("youtube_video_id: {}", youtube_video_id);
            println!("youtube_timestamp: {:?}", youtube_timestamp);
            let thumbnail_tuple =
                Self::download_youtube_thumbnail(&youtube_video_id, youtube_short).await;
            let (local_thumbnail_url, width, height) = match thumbnail_tuple {
                None => break,
                Some((path, width, height)) => (
                    path.to_str()
                        .expect("path to str")
                        .strip_prefix("pub")
                        .expect("strip pub prefix")
                        .to_owned(),
                    width,
                    height,
                ),
            };
            let youtube_url_path = if youtube_short { "shorts/" } else { "watch?v=" };
            let youtube_thumbnail_link = format!(
                concat!(
                    "<div class=\"youtube\">\n",
                    "    <div class=\"youtube-logo\">\n",
                    "        <a href=\"https://www.youtube.com/{url_path}{video_id}{timestamp}\">",
                    "<img src=\"/youtube.svg\" alt=\"YouTube {video_id}\" ",
                    "width=\"20\" height=\"20\">",
                    "</a>\n",
                    "    </div>\n",
                    "    <div class=\"youtube-thumbnail\">\n",
                    "        <a href=\"/p/{key}\">",
                    "<img src=\"{thumbnail_url}\" alt=\"Post {key}\" ",
                    "width=\"{width}\" height=\"{height}\">",
                    "</a>\n",
                    "    </div>\n",
                    "</div>",
                ),
                url_path = youtube_url_path,
                video_id = youtube_video_id,
                thumbnail_url = local_thumbnail_url,
                key = key,
                timestamp = youtube_timestamp
                    .map(|t| format!("&amp;t={}", t))
                    .unwrap_or_default(),
                width = width,
                height = height,
            );
            html = youtube_link_regex
                .replace(&html, youtube_thumbnail_link)
                .to_string();
        }
        html
    }

    /// Determines the media type (category and MIME type) based on the file extension
    ///
    /// # Examples
    ///
    /// ```
    /// use apabbs::post::{PostSubmission, MediaCategory};
    /// let (cat, mime) = PostSubmission::determine_media_type(Some("foo.jpg"));
    /// assert_eq!(cat, Some(MediaCategory::Image));
    /// assert_eq!(mime, Some("image/jpeg".to_string()));
    ///
    /// let (cat, mime) = PostSubmission::determine_media_type(Some("foo.mp3"));
    /// assert_eq!(cat, Some(MediaCategory::Audio));
    /// assert_eq!(mime, Some("audio/mpeg".to_string()));
    ///
    /// let (cat, mime) = PostSubmission::determine_media_type(Some("foo.unknown"));
    /// assert_eq!(cat, None);
    /// assert_eq!(mime, Some("application/octet-stream".to_string()));
    /// ```
    pub fn determine_media_type(
        media_filename: Option<&str>,
    ) -> (Option<MediaCategory>, Option<String>) {
        let media_filename = match media_filename {
            None => return (None, None),
            Some(media_filename) => media_filename,
        };
        use MediaCategory::*;
        let extension = media_filename.split('.').last();
        let (media_category, media_mime_type_str) = match extension {
            Some(extension) => match extension.to_lowercase().as_str() {
                "jpg" | "jpeg" | "jpe" | "jfif" | "pjpeg" | "pjp" => (Some(Image), "image/jpeg"),
                "gif" => (Some(Image), "image/gif"),
                "png" => (Some(Image), "image/png"),
                "webp" => (Some(Image), "image/webp"),
                "svg" => (Some(Image), "image/svg+xml"),
                "avif" => (Some(Image), "image/avif"),
                "ico" | "cur" => (Some(Image), "image/x-icon"),
                "apng" => (Some(Image), "image/apng"),
                "bmp" => (Some(Image), "image/bmp"),
                "tiff" | "tif" => (Some(Image), "image/tiff"),
                "avi" => (Some(Video), "video/x-msvideo"),
                "mpeg" | "mpg" | "mpe" => (Some(Video), "video/mpeg"),
                "mp4" | "m4v" => (Some(Video), "video/mp4"),
                "webm" => (Some(Video), "video/webm"),
                "ogv" => (Some(Video), "video/ogg"),
                "flv" => (Some(Video), "video/x-flv"),
                "mov" => (Some(Video), "video/quicktime"),
                "wmv" => (Some(Video), "video/x-ms-wmv"),
                "mp3" => (Some(Audio), "audio/mpeg"),
                "ogg" => (Some(Audio), "audio/ogg"),
                "wav" => (Some(Audio), "audio/wav"),
                "flac" => (Some(Audio), "audio/flac"),
                "opus" => (Some(Audio), "audio/opus"),
                "m4a" => (Some(Audio), "audio/mp4"),
                "aac" => (Some(Audio), "audio/aac"),
                "wma" => (Some(Audio), "audio/x-ms-wma"),
                "weba" => (Some(Audio), "audio/webm"),
                "3gp" => (Some(Audio), "audio/3gpp"),
                "3g2" => (Some(Audio), "audio/3gpp2"),
                _ => (None, APPLICATION_OCTET_STREAM),
            },
            None => (None, APPLICATION_OCTET_STREAM),
        };
        (media_category, Some(media_mime_type_str.to_owned()))
    }

    /// Encrypts the uploaded file data for a post
    ///
    /// This function handles the encryption of media bytes using the post's
    /// encryption key. It also manages the creation of necessary directories
    /// and cleans up in case of errors.
    ///
    /// # Returns
    /// - Ok(()) if encryption succeeded
    /// - Err with a message if encryption failed
    pub async fn encrypt_uploaded_file(self, post: &Post) -> Result<(), &str> {
        if self.media_bytes.is_none() {
            return Err("no media bytes");
        }
        let encrypted_file_path = post.encrypted_media_path();
        let uploads_key_dir = encrypted_file_path.parent().unwrap();
        tokio::fs::create_dir(uploads_key_dir)
            .await
            .expect("create uploads key dir");
        let result = post.gpg_encrypt(self.media_bytes.unwrap()).await;
        if result.is_err() {
            tokio::fs::remove_dir(uploads_key_dir)
                .await
                .expect("remove uploads key dir");
        }
        result
    }

    /// Determines the intro limit for a post based on its HTML content
    ///
    /// The intro limit is the byte offset where the post should be truncated
    /// in previews. It is determined by the following factors:
    /// - Maximum byte length (MAX_INTRO_BYTES)
    /// - Maximum number of line breaks (MAX_INTRO_BREAKS)
    /// - Presence of YouTube video embeds
    ///
    /// # Parameters
    /// - `html`: The HTML content of the post body
    ///
    /// # Returns
    /// An optional byte offset for truncating the post intro
    ///
    /// # Examples
    ///
    /// ```
    /// use apabbs::post::PostSubmission;
    /// let html = "short content";
    /// assert_eq!(PostSubmission::intro_limit(html), None);
    /// ```
    pub fn intro_limit(html: &str) -> Option<i32> {
        println!("html.len(): {}", html.len());
        if html.len() == 0 {
            return None;
        }
        // get a slice of the maximum intro bytes limited to the last valid utf8 character
        let last_valid_utf8_index = html
            .char_indices()
            .take_while(|&(idx, _)| idx < MAX_INTRO_BYTES)
            .last()
            .map_or(0, |(idx, _)| idx);
        println!("last valid utf8 index: {}", last_valid_utf8_index);
        let slice = if html.len() - 1 > last_valid_utf8_index {
            &html[..last_valid_utf8_index]
        } else {
            html
        };
        println!("slice: {}", slice);
        // stop before a second youtube video
        let youtube_pattern =
            Regex::new(r#"(?s)<div class="youtube">(?:.*?</div>){3}"#).expect("regex builds");
        // debug
        let mut youtube_iter = youtube_pattern.find_iter(slice);
        println!("first youtube_pattern match: {:?}", youtube_iter.next());
        let youtube_limit = match youtube_iter.next() {
            None => None,
            Some(mat) => {
                println!("second youtube_pattern match: {:?}", mat);
                let before_second_youtube = &slice[..mat.start()];
                // strip any breaks or whitespace that might be present at the end
                let strip_breaks_pattern = Regex::new("(?:<br>\n)+$").expect("regex builds");
                let stripped = strip_breaks_pattern.replace(before_second_youtube, "");
                Some(stripped.trim_end().len() as i32)
            }
        };
        // check for the maximum breaks
        let single_break_pattern = Regex::new("<br>\n").expect("regex builds");
        let break_limit = match single_break_pattern.find_iter(slice).nth(MAX_INTRO_BREAKS) {
            None => None,
            Some(mat) => Some(mat.start() as i32),
        };
        // take the smallest of youtube and break limits
        println!(
            "youtube_limit: {:?}, break_limit: {:?}",
            youtube_limit, break_limit
        );
        let min_limit = match (youtube_limit, break_limit) {
            (None, None) => None,
            (Some(y), None) => Some(y),
            (None, Some(b)) => Some(b),
            (Some(y), Some(b)) => Some(y.min(b)),
        };
        println!("min_limit: {:?}", min_limit);
        if min_limit.is_some() {
            println!("intro: {}", &html[..min_limit.unwrap() as usize]);
            return min_limit;
        }
        // do not truncate if beneath the maximum intro length
        if html.len() <= MAX_INTRO_BYTES {
            return None;
        }
        // truncate to the last break(s)
        let multiple_breaks_pattern = Regex::new("(?:<br>\n)+").expect("regex builds");
        if let Some(mat) = multiple_breaks_pattern.find_iter(slice).last() {
            println!("found last break(s): {}", mat.start());
            return Some(mat.start() as i32);
        }
        // if no breaks, truncate to the last space byte.
        let last_space = slice.rfind(' ');
        if last_space.is_some() {
            return last_space.map(|p| p as i32);
        }
        // if no space found, use the last utf8 character index
        // need to strip incomplete html entities
        // check for & which is not terminated by a ;
        let incomplete_entity_pattern = Regex::new(r"&[^;]*$").expect("regex builds");
        if let Some(mat) = incomplete_entity_pattern.find(slice) {
            println!("found incomplete entity: {}", mat.start());
            return Some(mat.start() as i32);
        }
        // no incomplete entity, return last valid utf8 character index.
        Some(last_valid_utf8_index as i32)
    }
}

/// Defines possible actions resulting from post review decisions
///
/// Each action represents a specific operation to perform on a post's media
/// or status during the moderation workflow.
#[derive(PartialEq, Debug)]
pub enum ReviewAction {
    /// Decrypt and process encrypted media for public viewing
    DecryptMedia,
    /// Delete encrypted media files that haven't been published
    DeleteEncryptedMedia,
    /// Delete media files from the public directory
    DeletePublishedMedia,
    /// Move published media back to encrypted pending state
    ReencryptMedia,
    /// Update post status without modifying media files
    NoAction,
}

/// Represents errors that can occur during post review
///
/// These errors correspond to business rules that restrict
/// which status transitions are allowed and by which roles.
#[derive(PartialEq, Debug)]
pub enum ReviewError {
    /// Attempted to change post to its current status
    SameStatus,
    /// Cannot revert a post back to pending status
    ReturnToPending,
    /// Operation restricted to moderator role
    ModOnly,
    /// Operation restricted to administrator role
    AdminOnly,
    /// Cannot modify posts with final status (rejected/banned)
    RejectedOrBanned,
    /// Moderators can only modify recent posts
    RecentOnly,
    /// Cannot modify a post that's currently being processed
    CurrentlyProcessing,
    /// Cannot manually set a post to processing status
    ManualProcessing,
}

/// Represents a post review action submitted by a moderator or admin
///
/// Contains the reviewer's session token and the proposed new status for the post.
/// Used to process moderation decisions through the review workflow.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PostReview {
    /// Session token of the user performing the review
    pub session_token: Uuid,

    /// New status to apply to the post
    pub status: PostStatus,
}

impl PostReview {
    /// Writes decrypted media file bytes to the public directory
    ///
    /// Creates the necessary directory structure and writes the media bytes
    /// to the destination file for public access.
    ///
    /// # Parameters
    /// - `published_media_path`: Path where the media should be stored
    /// - `media_bytes`: Raw bytes of the decrypted media file
    pub async fn write_media_file(published_media_path: &PathBuf, media_bytes: Vec<u8>) {
        let media_key_dir = published_media_path.parent().unwrap();
        tokio::fs::create_dir(media_key_dir)
            .await
            .expect("create media key dir");
        tokio::fs::write(&published_media_path, media_bytes)
            .await
            .expect("write media file");
    }

    /// Generates a thumbnail image for a given media file
    ///
    /// Uses the vipsthumbnail utility to create a properly sized thumbnail.
    /// Handles special cases for animated image formats by extracting the last frame.
    ///
    /// # Parameters
    /// - `published_media_path`: Path to the original image file
    ///
    /// # Returns
    /// Path to the generated thumbnail file
    pub async fn generate_image_thumbnail(published_media_path: &PathBuf) -> PathBuf {
        let media_path_str = published_media_path.to_str().unwrap();
        let extension = media_path_str
            .split('.')
            .last()
            .expect("get file extension");

        // For animated images (GIF, WebP), extract the last frame as the thumbnail
        let vips_input_file_path = media_path_str.to_owned()
            + match extension.to_lowercase().as_str() {
                "gif" | "webp" => "[n=-1]", // animated image support
                _ => "",
            };

        // Run vipsthumbnail in a separate thread to avoid blocking async runtime
        tokio::task::spawn_blocking(move || {
            let command_output = std::process::Command::new("vipsthumbnail")
                .args([
                    // Max dimensions with aspect ratio preserved
                    &format!("--size={MAX_THUMB_WIDTH}x{MAX_THUMB_HEIGHT}>"),
                    "--output=tn_%s.webp", // Output format with prefix
                ])
                .arg(&vips_input_file_path)
                .output()
                .expect("generate thumbnail");

            println!("vipsthumbnail output: {:?}", command_output);
        })
        .await
        .expect("vipsthumbnail task completed");

        Self::alternate_path(published_media_path, "tn_", ".webp")
    }

    /// Constructs an alternate file path for a derived media file
    ///
    /// Generates a new file path in the same directory as the original, using the provided
    /// prefix and file extension. This is used for creating paths for thumbnails, compatibility
    /// videos, or other media variants derived from the original file.
    ///
    /// # Parameters
    /// - `media_path`: Path to the original media file
    /// - `prefix`: Prefix to prepend to the base filename (e.g., "tn_" for thumbnails)
    /// - `extension`: New file extension for the derived file (e.g., ".webp", ".mp4")
    ///
    /// # Returns
    /// Path where the derived file should be stored, in the same directory as the original
    pub fn alternate_path(media_path: &PathBuf, prefix: &str, extension: &str) -> PathBuf {
        let media_filename = media_path
            .file_name()
            .expect("get media filename")
            .to_str()
            .expect("media filename to str");

        let key_dir = media_path.parent().unwrap();
        let extension_pattern = Regex::new(r"\.[^\.]+$").expect("build extension regex pattern");

        // Create thumbnail filename with "tn_" prefix and specified extension
        let alternate_filename =
            prefix.to_owned() + &extension_pattern.replace(media_filename, extension);

        key_dir.join(&alternate_filename)
    }

    /// Determines if a thumbnail file is larger than the original media file
    ///
    /// Used to decide if the thumbnail provides any benefit over the original.
    /// If the thumbnail is larger, it's better to use the original file instead.
    ///
    /// # Parameters
    /// - `thumbnail_path`: Path to the thumbnail file
    /// - `published_media_path`: Path to the original media file
    ///
    /// # Returns
    /// `true` if the thumbnail is larger than the original, `false` otherwise
    pub fn thumbnail_is_larger(thumbnail_path: &PathBuf, published_media_path: &PathBuf) -> bool {
        let thumbnail_len = thumbnail_path.metadata().unwrap().len();
        let media_file_len = published_media_path.metadata().unwrap().len();
        thumbnail_len > media_file_len
    }

    /// Deletes an encrypted media file and its containing directory
    ///
    /// Used when rejecting or banning a post to clean up the encrypted media.
    ///
    /// # Parameters
    /// - `encrypted_media_path`: Path to the encrypted media file
    pub async fn delete_upload_key_dir(encrypted_media_path: &PathBuf) {
        let uploads_key_dir = encrypted_media_path.parent().unwrap();

        tokio::fs::remove_file(&encrypted_media_path)
            .await
            .expect("remove encrypted media file");

        tokio::fs::remove_dir(&uploads_key_dir)
            .await
            .expect("remove uploads key dir");
    }

    /// Deletes all media files associated with a post
    ///
    /// Removes the entire directory containing a post's media files.
    ///
    /// # Parameters
    /// - `key`: The unique key of the post whose media should be deleted
    pub async fn delete_media_key_dir(key: &str) {
        let media_key_dir = std::path::Path::new(MEDIA_DIR).join(key);

        tokio::fs::remove_dir_all(&media_key_dir)
            .await
            .expect("remove media key dir and its contents");
    }

    /// Records a review action in the database
    ///
    /// Creates an entry in the reviews table to track moderation activity.
    ///
    /// # Parameters
    /// - `tx`: Database transaction
    /// - `account_id`: ID of the account performing the review
    /// - `post_id`: ID of the post being reviewed
    pub async fn insert(&self, tx: &mut PgConnection, account_id: i32, post_id: i32) {
        sqlx::query("INSERT INTO reviews (account_id, post_id, status) VALUES ($1, $2, $3)")
            .bind(account_id)
            .bind(post_id)
            .bind(&self.status)
            .execute(&mut *tx)
            .await
            .expect("insert post review");
    }

    /// Determines what action should be taken for a review based on post state and user role
    ///
    /// This method implements the business rules that govern post moderation:
    /// - Which transitions between post statuses are allowed
    /// - Which roles can perform which actions
    /// - What should happen to media files during each transition
    ///
    /// # Parameters
    /// - `post`: The post being reviewed
    /// - `reviewer_role`: Role of the user performing the review
    ///
    /// # Returns
    /// - `Ok(ReviewAction)` if the action is allowed
    /// - `Err(ReviewError)` if the action is not allowed
    pub fn determine_action(
        &self,
        post: &Post,
        reviewer_role: &AccountRole,
    ) -> Result<ReviewAction, ReviewError> {
        use AccountRole::*;
        use PostStatus::*;
        use ReviewAction::*;
        use ReviewError::*;

        match post.status {
            // Rules for posts in Pending status
            Pending => match self.status {
                Pending => Err(SameStatus),                    // No change needed
                Processing => Err(ManualProcessing),           // Processing is set automatically
                Approved | Delisted => Ok(DecryptMedia), // Approve: decrypt media for public view
                Reported => Ok(NoAction),                // Just change status, no media action
                Rejected | Banned => Ok(DeleteEncryptedMedia), // Delete encrypted media
            },

            // Posts being processed can't be changed until processing completes
            Processing => Err(CurrentlyProcessing),

            // Rules for already approved or delisted posts
            Approved | Delisted => {
                // Mods can only change recent posts
                if post.status == Approved && *reviewer_role == Mod && !post.recent.unwrap() {
                    return Err(RecentOnly);
                }

                match self.status {
                    Pending => Err(ReturnToPending),     // Can't go backwards to pending
                    Processing => Err(ManualProcessing), // Processing is set automatically
                    Approved | Delisted => Ok(NoAction), // Just status change, no media action
                    Reported => {
                        // Only mods can report posts
                        if *reviewer_role != Mod {
                            return Err(ModOnly);
                        }
                        // When reporting, re-encrypt the media for admin review
                        Ok(ReencryptMedia)
                    }
                    Rejected | Banned => Ok(DeletePublishedMedia), // Delete the published media
                }
            }

            // Rules for reported posts
            Reported => {
                // Only admins can review reported posts
                if *reviewer_role != Admin {
                    return Err(AdminOnly);
                }

                match self.status {
                    Pending => Err(ReturnToPending),     // Can't go backwards to pending
                    Processing => Err(ManualProcessing), // Processing is set automatically
                    Approved | Delisted => Ok(DecryptMedia), // Approve: decrypt for public view
                    Rejected | Banned => Ok(DeleteEncryptedMedia), // Delete the encrypted media
                    Reported => Err(SameStatus),         // No change needed
                }
            }

            // Rejected or banned posts are final and can't be changed
            Rejected | Banned => Err(RejectedOrBanned),
        }
    }

    /// Handles the media decryption and processing workflow for a post
    ///
    /// This method decrypts the post's media file, processes it according to its type,
    /// generates appropriate thumbnails, and updates the database with metadata.
    ///
    /// # Parameters
    /// - `tx`: Database connection
    /// - `post`: The post whose media should be decrypted
    ///
    /// # Returns
    /// - `Ok(())` if processing was successful
    /// - `Err(String)` with an error message if processing failed
    pub async fn handle_decrypt_media(tx: &mut PgConnection, post: &Post) -> Result<(), String> {
        // Decrypt the media file
        let media_bytes = post.decrypt_media_file().await;

        // Write the decrypted file to the published media directory
        let published_media_path = post.published_media_path();
        Self::write_media_file(&published_media_path, media_bytes).await;

        // Process according to media type
        match post.media_category {
            Some(MediaCategory::Image) => Self::process_image(tx, post).await?,
            Some(MediaCategory::Video) => Self::process_video(tx, post).await?,
            // Audio files and posts without media don't need processing
            Some(MediaCategory::Audio) | None => (),
        }

        Ok(())
    }

    /// Process image media
    pub async fn process_image(tx: &mut PgConnection, post: &Post) -> Result<(), String> {
        let published_media_path = post.published_media_path();

        // Generate a thumbnail for the image
        let thumbnail_path = Self::generate_image_thumbnail(&published_media_path).await;

        if !thumbnail_path.exists() {
            return Err(ERR_THUMBNAIL_FAILED.to_owned());
        }

        // If thumbnail is larger than original, don't use it
        if Self::thumbnail_is_larger(&thumbnail_path, &published_media_path) {
            tokio::fs::remove_file(&thumbnail_path)
                .await
                .expect("remove thumbnail file");
        } else {
            // Update the database with thumbnail information
            let (width, height) = Self::image_dimensions(&thumbnail_path).await;
            post.update_thumbnail(tx, &thumbnail_path, width, height)
                .await;
        }

        // Update the media dimensions in the database
        let (width, height) = Self::image_dimensions(&published_media_path).await;
        post.update_media_dimensions(tx, width, height).await;

        Ok(())
    }

    /// Process video media
    pub async fn process_video(tx: &mut PgConnection, post: &Post) -> Result<(), String> {
        let published_media_path = post.published_media_path();

        // Generate a compatibility video for browser playback
        // Later, only do this if it's not already in the compatibility format.
        if !Self::video_is_compatible(&published_media_path).await {
            let compatibility_path =
                Self::generate_compatibility_video(&published_media_path).await;

            if !compatibility_path.exists() {
                return Err(String::from("Compatibility video generation failed"));
            }

            // Update the database with the compatibility video path
            post.update_compat_video(tx, &compatibility_path).await;
        }

        // Generate a poster image from the video
        let video_poster_path = Self::generate_video_poster(&published_media_path).await;
        post.update_poster(tx, &video_poster_path).await;

        // Update the post with media dimensions and poster
        let (media_width, media_height) = Self::image_dimensions(&video_poster_path).await;
        post.update_media_dimensions(tx, media_width, media_height)
            .await;

        // Check if dimensions are large enough to necessitate a thumbnail
        if media_width > MAX_THUMB_WIDTH || media_height > MAX_THUMB_HEIGHT {
            let thumbnail_path = Self::generate_image_thumbnail(&video_poster_path).await;

            if !thumbnail_path.exists() {
                return Err(ERR_THUMBNAIL_FAILED.to_owned());
            }

            let (thumb_width, thumb_height) = Self::image_dimensions(&thumbnail_path).await;

            // Update the post with thumbnail info
            post.update_thumbnail(tx, &thumbnail_path, thumb_width, thumb_height)
                .await;
        }

        Ok(())
    }

    /// Determines the dimensions of an image using the vipsheader utility
    ///
    /// # Parameters
    /// - `image_path`: Path to the image file
    ///
    /// # Returns
    /// A tuple of (width, height) as integers
    pub async fn image_dimensions(image_path: &PathBuf) -> (i32, i32) {
        println!("Getting image dimensions for: {:?}", image_path);
        let image_path_str = image_path.to_str().unwrap();

        // Helper function to extract specific field from vipsheader
        let vipsheader = async |field: &str| -> i32 {
            let output = tokio::process::Command::new("vipsheader")
                .args(["-f", field, image_path_str])
                .output()
                .await
                .expect("get image dimension");

            String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse()
                .expect("parses as i32")
        };

        // Get both dimensions in parallel
        let (width, height) = tokio::join!(vipsheader("width"), vipsheader("height"));
        println!(
            "Image dimensions for {:?}: {}x{}",
            image_path, width, height
        );
        (width, height)
    }

    /// Use ffprobe to determine if a video needs a compatibility variant.
    /// This is accomplished by checking if the video codec is H.264 and the audio codec is AAC.
    /// It must also be 8-bit YUV 4:2:0 pixel format and have an MP4 container.
    ///
    /// # Parameters
    /// - `video_path`: Path to the video file
    ///
    /// # Returns
    /// `true` if the video is compatible, `false` if it needs conversion
    pub async fn video_is_compatible(video_path: &PathBuf) -> bool {
        println!("Checking video compatibility for: {:?}", video_path);
        let video_path_str = video_path.to_str().unwrap().to_owned();

        // Run ffprobe to get video codec information
        let output = tokio::process::Command::new("ffprobe")
            .args([
                "-v",
                "error", // Suppress non-error messages
                "-select_streams",
                "v:0", // Select the first video stream
                "-show_entries",
                "stream=codec_name,pix_fmt,profile,level",
                "-of",
                "default=noprint_wrappers=1", // Use key=value output
                &video_path_str,              // Input video file
            ])
            .output()
            .await
            .expect("ffprobe command failed");

        let output_str = String::from_utf8_lossy(&output.stdout);

        println!("ffprobe output: {}", output_str);

        // Parse the output by key
        let mut codec = "";
        let mut pix_fmt = "";
        let mut profile = "";
        let mut level = "";
        for line in output_str.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("codec_name=") {
                codec = rest;
            } else if let Some(rest) = line.strip_prefix("pix_fmt=") {
                pix_fmt = rest;
            } else if let Some(rest) = line.strip_prefix("profile=") {
                profile = rest;
            } else if let Some(rest) = line.strip_prefix("level=") {
                level = rest;
            }
        }

        // Check if the video is compatible
        if codec == "h264"
            && pix_fmt == "yuv420p"
            && ["Baseline", "Constrained Baseline", "Main", "High"].contains(&profile)
            && level.parse::<i32>().unwrap_or(0) <= 42
        {
            println!("Video is compatible for web playback: {}", video_path_str);
            return true; // Compatible video
        }

        println!(
            "Video is not compatible for web playback: {}",
            video_path_str
        );
        false // Needs conversion
    }

    /// Generates a browser-compatible video variant for playback
    ///
    /// Converts the input video to an H.264/AVC MP4 file with AAC audio, suitable for maximum browser compatibility.
    /// The output and is intended as a fallback for browsers that do not support  the original video format. The
    /// generated file is saved alongside the original with a "cm_" prefix and ".mp4" extension.
    ///
    /// # Parameters
    /// - `video_path`: Path to the original video file
    ///
    /// # Returns
    /// Path to the generated compatibility video file (MP4)
    pub async fn generate_compatibility_video(video_path: &PathBuf) -> PathBuf {
        println!("Generating compatibility video for: {:?}", video_path);
        let video_path_str = video_path.to_str().unwrap().to_owned();
        let compatibility_path = Self::alternate_path(video_path, "cm_", ".mp4");
        let compatibility_path_str = compatibility_path.to_str().unwrap().to_owned();

        // Move the ffmpeg processing to a separate thread pool
        tokio::task::spawn_blocking(move || {
            let ffmpeg_output = std::process::Command::new("ffmpeg")
                .args([
                    "-nostdin", // No stdin interaction
                    "-i",
                    &video_path_str, // Input file
                    "-f",
                    "mp4", // Force MP4 container
                    "-c:v",
                    "libx264", // H.264 video codec
                    "-crf",
                    "23", // Constant rate factor (quality)
                    "-preset",
                    "medium", // Encoding speed/compression trade-off
                    "-movflags",
                    "+faststart", // Optimize for web playback
                    "-profile:v",
                    "high", // H.264 profile
                    "-pix_fmt",
                    "yuv420p", // Pixel format for compatibility
                    "-c:a",
                    "aac", // AAC audio codec
                    "-b:a",
                    "128k",                  // Audio bitrate
                    &compatibility_path_str, // Output file
                ])
                .output()
                .expect("generate video thumbnail");

            println!("ffmpeg output: {:?}", ffmpeg_output);
        })
        .await
        .expect("ffmpeg task completed");

        println!("Compatibility video generated at: {:?}", compatibility_path);
        compatibility_path
    }

    /// Generates a poster image (still frame) from a video file
    ///
    /// Extracts a single frame at the 1-second mark of the video and saves it
    /// as a WebP image to serve as a poster/preview for the video.
    ///
    /// # Parameters
    /// - `video_path`: Path to the video file
    ///
    /// # Returns
    /// Path to the generated poster image file
    pub async fn generate_video_poster(video_path: &PathBuf) -> PathBuf {
        println!("Generating video poster for: {:?}", video_path);
        let poster_path = video_path.with_extension("webp");

        let video_path_str = video_path.to_str().unwrap().to_owned();
        let poster_path_str = poster_path.to_str().unwrap().to_owned();

        // Move ffmpeg poster generation to a separate thread
        tokio::task::spawn_blocking(move || {
            let ffmpeg_output = std::process::Command::new("ffmpeg")
                .args([
                    "-nostdin", // No stdin interaction
                    "-i",
                    &video_path_str, // Input file
                    "-ss",
                    "00:00:01.000", // Seek to 1 second into the video
                    "-vframes",
                    "1", // Extract a single video frame
                    "-c:v",
                    "libwebp", // WebP format
                    "-lossless",
                    "0", // Use lossy compression
                    "-compression_level",
                    "6", // Compression level
                    "-quality",
                    "80", // Image quality
                    "-preset",
                    "picture",        // Optimize for still image
                    &poster_path_str, // Output file
                ])
                .output()
                .expect("generate video poster");

            println!("ffmpeg output: {:?}", ffmpeg_output);
        })
        .await
        .expect("poster generation task completed");

        println!("Video poster generated at: {:?}", poster_path);
        poster_path
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

    /// Tests MIME type and media category detection for different file extensions
    #[tokio::test]
    async fn media_type_detection() {
        // Test image file types
        let (category, mime) = PostSubmission::determine_media_type(Some("test.jpg"));
        assert_eq!(category, Some(MediaCategory::Image));
        assert_eq!(mime, Some("image/jpeg".to_string()));

        // Test video file types
        let (category, mime) = PostSubmission::determine_media_type(Some("video.mp4"));
        assert_eq!(category, Some(MediaCategory::Video));
        assert_eq!(mime, Some("video/mp4".to_string()));

        // Test audio file types
        let (category, mime) = PostSubmission::determine_media_type(Some("audio.mp3"));
        assert_eq!(category, Some(MediaCategory::Audio));
        assert_eq!(mime, Some("audio/mpeg".to_string()));

        // Test unknown file type
        let (category, mime) = PostSubmission::determine_media_type(Some("document.pdf"));
        assert_eq!(category, None);
        assert_eq!(mime, Some(APPLICATION_OCTET_STREAM.to_string()));

        // Test no file
        let (category, mime) = PostSubmission::determine_media_type(None);
        assert_eq!(category, None);
        assert_eq!(mime, None);
    }

    /// Tests the conversion of post body text to HTML with YouTube embed generation
    ///
    /// This test verifies:
    /// - Basic HTML escaping (converting <, >, &, etc. to HTML entities)
    /// - URL recognition and conversion to anchor tags
    /// - YouTube link detection and conversion to embedded thumbnails
    /// - Handling of various YouTube URL formats (standard, mobile, shorts, etc.)
    /// - Proper timestamp handling in YouTube links
    #[tokio::test]
    async fn body_to_html() {
        // Setup test with various types of content:
        // - HTML special characters
        // - Line breaks
        // - Regular URLs
        // - YouTube links in different formats
        let submission = PostSubmission {
            body: concat!(
                "<&test body\"' コンピューター\n\n",
                "https://example.com\n",
                " https://m.youtube.com/watch?v=jNQXAC9IVRw\n",
                "https://youtu.be/kixirmHePCc?si=q9OkPEWRQ0RjoWg&t=3\n",
                "http://youtube.com/shorts/cHMCGCWit6U?si=q9OkPEWRQ0RjoWg \n",
                "https://example.com?m.youtube.com/watch?v=jNQXAC9IVRw\n",
                "foo https://www.youtube.com/watch?v=ySrBS4ulbmQ&t=2m1s\n\n",
                "https://www.youtube.com/watch?v=ySrBS4ulbmQ bar\n",
                "https://www.youtube.com/watch?t=10s&app=desktop&v=28jr-6-XDPM",
            )
            .to_owned(),
            ..Default::default()
        };

        // Keep track of existing test directories to avoid deleting user data
        let test_ids = [
            "jNQXAC9IVRw",
            "kixirmHePCc",
            "cHMCGCWit6U",
            "28jr-6-XDPM",
            "ySrBS4ulbmQ",
        ];
        let mut existing_ids = Vec::new();
        for id in test_ids {
            if std::path::Path::new(YOUTUBE_DIR).join(id).exists() {
                existing_ids.push(id);
            }
        }

        // Run the test
        let key = "testkey1";
        assert_eq!(
            submission.body_to_html(key).await,
            concat!(
                "&lt;&amp;test body&quot;&apos; コンピューター<br>\n",
                "<br>\n",
                "<a href=\"https://example.com\">https://example.com</a><br>\n",
                "<div class=\"youtube\">\n",
                "    <div class=\"youtube-logo\">\n",
                "        <a href=\"https://www.youtube.com/watch?v=jNQXAC9IVRw\">",
                "<img src=\"/youtube.svg\" alt=\"YouTube jNQXAC9IVRw\" width=\"20\" height=\"20\">",
                "</a>\n",
                "    </div>\n",
                "    <div class=\"youtube-thumbnail\">\n",
                "        <a href=\"/p/testkey1\">",
                "<img src=\"/youtube/jNQXAC9IVRw/hqdefault.jpg\" alt=\"Post testkey1\" ",
                "width=\"480\" height=\"360\">",
                "</a>\n",
                "    </div>\n",
                "</div>\n",
                "<div class=\"youtube\">\n",
                "    <div class=\"youtube-logo\">\n",
                "        <a href=\"https://www.youtube.com/watch?v=kixirmHePCc&amp;t=3\">",
                "<img src=\"/youtube.svg\" alt=\"YouTube kixirmHePCc\" width=\"20\" height=\"20\">",
                "</a>\n",
                "    </div>\n",
                "    <div class=\"youtube-thumbnail\">\n",
                "        <a href=\"/p/testkey1\">",
                "<img src=\"/youtube/kixirmHePCc/maxresdefault.jpg\" alt=\"Post testkey1\" ",
                "width=\"1280\" height=\"720\">",
                "</a>\n",
                "    </div>\n",
                "</div>\n",
                "<div class=\"youtube\">\n",
                "    <div class=\"youtube-logo\">\n",
                "        <a href=\"https://www.youtube.com/shorts/cHMCGCWit6U\">",
                "<img src=\"/youtube.svg\" alt=\"YouTube cHMCGCWit6U\" width=\"20\" height=\"20\">",
                "</a>\n",
                "    </div>\n",
                "    <div class=\"youtube-thumbnail\">\n",
                "        <a href=\"/p/testkey1\">",
                "<img src=\"/youtube/cHMCGCWit6U/oar2.jpg\" alt=\"Post testkey1\" ",
                "width=\"1080\" height=\"1920\">",
                "</a>\n",
                "    </div>\n",
                "</div>\n",
                "<a href=\"https://example.com?m.youtube.com/watch?v=jNQXAC9IVRw\">",
                "https://example.com?m.youtube.com/watch?v=jNQXAC9IVRw",
                "</a><br>\n",
                "foo ",
                "<a href=\"https://www.youtube.com/watch?v=ySrBS4ulbmQ&amp;t=2m1s\">",
                "https://www.youtube.com/watch?v=ySrBS4ulbmQ&amp;t=2m1s",
                "</a><br>\n",
                "<br>\n",
                "<a href=\"https://www.youtube.com/watch?v=ySrBS4ulbmQ\">",
                "https://www.youtube.com/watch?v=ySrBS4ulbmQ",
                "</a> bar<br>\n",
                "<div class=\"youtube\">\n",
                "    <div class=\"youtube-logo\">\n",
                "        <a href=\"https://www.youtube.com/watch?v=28jr-6-XDPM&amp;t=10s\">",
                "<img src=\"/youtube.svg\" alt=\"YouTube 28jr-6-XDPM\" width=\"20\" height=\"20\">",
                "</a>\n",
                "    </div>\n",
                "    <div class=\"youtube-thumbnail\">\n",
                "        <a href=\"/p/testkey1\">",
                "<img src=\"/youtube/28jr-6-XDPM/hqdefault.jpg\" alt=\"Post testkey1\" ",
                "width=\"480\" height=\"360\">",
                "</a>\n",
                "    </div>\n",
                "</div>",
            )
        );

        // Clean up test data but preserve any existing directories
        for id in test_ids {
            if !existing_ids.contains(&id) {
                tokio::fs::remove_dir_all(std::path::Path::new(YOUTUBE_DIR).join(id))
                    .await
                    .ok(); // Use ok() to ignore errors if directory doesn't exist
            }
        }
    }

    /// Tests the intro_limit functionality for post previews
    ///
    /// This test verifies the algorithm correctly determines where to truncate posts for previews based on:
    /// - YouTube embed locations
    /// - Line break counts
    /// - Maximum size limits
    /// - Character encoding boundaries
    /// - HTML entity handling
    #[tokio::test]
    async fn intro_limit() {
        // Test case: Two YouTube embeds with line breaks beyond the limit
        // Should truncate at the first YouTube embed
        let two_youtubes = concat!(
            "<div class=\"youtube\">\n",
            "    <div class=\"youtube-logo\">\n",
            "        foo\n",
            "    </div>\n",
            "    <div class=\"youtube-thumbnail\">\n",
            "        bar\n",
            "    </div>\n",
            "</div>\n",
            "<div class=\"youtube\">\n",
            "    <div class=\"youtube-logo\">\n",
            "        baz\n",
            "    </div>\n",
            "    <div class=\"youtube-thumbnail\">\n",
            "        quux\n",
            "    </div>\n",
            "</div>",
        );

        // Case 1: Line breaks first, then YouTube content
        let html = str::repeat("<br>\n", MAX_INTRO_BREAKS + 1) + two_youtubes;
        assert_eq!(PostSubmission::intro_limit(&html), Some(120));

        // Case 2: YouTube content first, then line breaks beyond the limit
        let html = two_youtubes.to_owned() + &str::repeat("<br>\n", MAX_INTRO_BREAKS + 1);
        assert_eq!(PostSubmission::intro_limit(&html), Some(141));

        // Case 3: Content shorter than the limit - shouldn't truncate
        let html = str::repeat("foo ", 300);
        assert_eq!(PostSubmission::intro_limit(&html), None);

        // Case 4: Content with line breaks but still under the break limit
        let html = str::repeat("foo ", 100)
            + "<br>\n"
            + &str::repeat("bar ", 200)
            + "<br>\n"
            + &str::repeat("baz ", 100);
        assert_eq!(PostSubmission::intro_limit(&html), Some(1205));

        // Case 5: Content exactly at the byte limit boundary
        let html = str::repeat("x", MAX_INTRO_BYTES - 2) + " yy";
        assert_eq!(PostSubmission::intro_limit(&html), Some(1598));

        // Case 6: Content beyond the byte limit
        let html = str::repeat("x", MAX_INTRO_BYTES) + " y";
        assert_eq!(PostSubmission::intro_limit(&html), Some(1599));

        // Case 7: HTML entity at the boundary
        let html = str::repeat("x", MAX_INTRO_BYTES - 2) + "&quot;";
        assert_eq!(PostSubmission::intro_limit(&html), Some(1598));

        // Case 8: Multi-byte character at the boundary
        let html = str::repeat("x", MAX_INTRO_BYTES - 2) + "コ";
        assert_eq!(PostSubmission::intro_limit(&html), Some(1598));
    }

    /// Tests YouTube timestamp extraction from various URL formats
    #[tokio::test]
    async fn youtube_timestamp_extraction() {
        let submission = PostSubmission {
            body: concat!(
                "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=1m30s\n",
                "https://www.youtube.com/watch?t=25s&v=dQw4w9WgXcQ\n",
                "https://youtu.be/dQw4w9WgXcQ?t=42\n"
            )
            .to_owned(),
            ..Default::default()
        };

        // Check if test directory already exists
        let video_id = "dQw4w9WgXcQ";
        let youtube_dir = std::path::Path::new(YOUTUBE_DIR).join(video_id);
        let dir_existed = youtube_dir.exists();

        if !dir_existed {
            tokio::fs::create_dir_all(&youtube_dir)
                .await
                .expect("create test dir");

            // Create fake thumbnail file
            let test_thumbnail = youtube_dir.join("maxresdefault.jpg");
            tokio::fs::write(&test_thumbnail, b"test")
                .await
                .expect("write test thumbnail");
        }

        // Generate HTML with embeds containing timestamps
        let html = submission.body_to_html("testkey").await;

        // Verify timestamps were properly extracted and included
        assert!(html.contains("&amp;t=1m30s"));
        assert!(html.contains("&amp;t=25s"));
        assert!(html.contains("&amp;t=42"));

        // Clean up only if we created the directory for this test
        if !dir_existed {
            tokio::fs::remove_dir_all(youtube_dir).await.ok();
        }
    }
}
