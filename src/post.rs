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

pub mod media;
pub mod review;
pub mod submission;

use crate::{
    POSTGRES_HTML_DATETIME, POSTGRES_RFC5322_DATETIME,
    user::{AccountRole, User},
};
pub use review::{PostReview, ReviewAction, ReviewError};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Postgres, QueryBuilder};
use std::path::Path;
pub use submission::{PostHiding, PostSubmission};
use uuid::Uuid;

/// Post status indicates the moderation/approval state of a post
#[derive(sqlx::Type, Serialize, Deserialize, PartialEq, Clone, Debug, Copy, Default)]
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
#[derive(sqlx::Type, Serialize, Deserialize, PartialEq, Clone, Debug)]
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
#[derive(sqlx::FromRow, Serialize, Clone, Debug, Default)]
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
    /// Selects posts visible to the user according to their access level.
    ///
    /// Filters posts by status based on the user's role:
    /// - Admins: all posts except rejected
    /// - Mods: all except rejected and reported
    /// - Others: only approved posts
    ///
    /// Additionally shows posts created by the user regardless of status.
    ///
    /// # Parameters
    /// - `tx`: Database connection (mutable reference)
    /// - `user`: Current user with session and account info
    /// - `post_id`: Optional ID for pagination
    /// - `invert`: Whether to invert the sort order
    ///
    /// # Returns
    /// A vector of posts visible to the user.
    pub async fn select(
        tx: &mut PgConnection,
        user: &User,
        post_id: Option<i32>,
        invert: bool,
    ) -> Vec<Self> {
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("SELECT * FROM posts WHERE (");

        // Filter by status based on user role
        match user.account {
            Some(ref account) => match account.role {
                AccountRole::Admin => qb.push("status <> 'rejected' "),
                AccountRole::Mod => qb.push("status NOT IN ('rejected', 'reported') "),
                _ => qb.push("status = 'approved' "),
            },
            None => qb.push("status = 'approved' "),
        };

        // Always show user's own posts
        qb.push("OR session_token = ");
        qb.push_bind(user.session_token);

        if let Some(ref account) = user.account {
            qb.push(" OR account_id = ");
            qb.push_bind(account.id);
        }

        qb.push(") AND hidden = false");

        // Set up pagination parameters
        let (operator, order, limit) = if invert {
            (">", "ASC", crate::per_page()) // sanity limit
        } else {
            ("<=", "DESC", crate::per_page() + 1) // +1 to check if there are more pages
        };

        // Add pagination constraint if post_id is provided
        if let Some(post_id) = post_id {
            qb.push(format!(" AND id {} ", operator));
            qb.push_bind(post_id);
        }

        // Add ordering and limit
        qb.push(format!(" ORDER BY id {} LIMIT ", order));
        qb.push_bind(limit as i32);

        // Execute query
        qb.build_query_as()
            .fetch_all(&mut *tx)
            .await
            .expect("query succeeds")
    }

    /// Selects approved posts created by the specified account.
    ///
    /// Returns only posts with status 'approved' and limits the result to the system-defined page size.
    ///
    /// # Parameters
    /// - `tx`: Database connection (mutable reference)
    /// - `account_id`: Account ID of the author
    ///
    /// # Returns
    /// A vector of approved posts by the author.
    pub async fn select_by_author(tx: &mut PgConnection, account_id: i32) -> Vec<Self> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE account_id = $1 ",
            "AND status = 'approved' ORDER BY id DESC LIMIT $2",
        ))
        .bind(account_id)
        .bind(crate::per_page() as i32)
        .fetch_all(&mut *tx)
        .await
        .expect("query succeeds")
    }

    /// Checks if the user is the author of this post.
    ///
    /// Returns true if either:
    /// - The post's session token matches the user's session token
    /// - The post's account ID matches the user's account ID
    ///
    /// # Parameters
    /// - `user`: The user to check against
    ///
    /// # Returns
    /// `true` if the user is the author, `false` otherwise.
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

    /// Selects a post by its unique key with formatted timestamps.
    ///
    /// Also includes a flag indicating if the post is recent (less than 2 days old).
    ///
    /// # Parameters
    /// - `tx`: Database connection (mutable reference)
    /// - `key`: Unique key of the post
    ///
    /// # Returns
    /// An optional post matching the key, with formatted timestamps.
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
        .expect("query succeeds")
    }

    /// Permanently deletes a post from the database.
    ///
    /// # Parameters
    /// - `tx`: Database connection (mutable reference)
    pub async fn delete(&self, tx: &mut PgConnection) {
        sqlx::query("DELETE FROM posts WHERE id = $1")
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("query succeeds");
    }

    /// Updates the status of a post in the database.
    ///
    /// # Parameters
    /// - `tx`: Database connection (mutable reference)
    /// - `new_status`: The new status to set for the post
    pub async fn update_status(&self, tx: &mut PgConnection, new_status: PostStatus) {
        sqlx::query("UPDATE posts SET status = $1 WHERE id = $2")
            .bind(new_status)
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("query succeeds");
    }

    /// Updates thumbnail metadata for a post.
    ///
    /// # Parameters
    /// - `tx`: Database connection (mutable reference)
    /// - `thumbnail_path`: Path to the thumbnail image
    /// - `width`: Width of the thumbnail in pixels
    /// - `height`: Height of the thumbnail in pixels
    pub async fn update_thumbnail(
        &self,
        tx: &mut PgConnection,
        thumbnail_path: &Path,
        width: i32,
        height: i32,
    ) {
        let thumbnail_filename = thumbnail_path
            .file_name()
            .expect("filename exists")
            .to_str()
            .expect("filename to str");

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
        .expect("query succeeds");
    }

    /// Update the compatibility video filename for a post.
    ///
    /// This is used to store a fallback video format for browsers that do not support
    /// the primary video format (e.g., H.264 for non-Chromium browsers).
    ///
    /// # Parameters
    /// - `tx`: Database connection (mutable reference)
    /// - `compat_path`: Path to the compatibility video file
    ///
    /// # Panics
    /// Panics if the compatibility video filename cannot be extracted or converted to a string.
    pub async fn update_compat_video(&self, tx: &mut PgConnection, compat_path: &Path) {
        let compat_filename = compat_path
            .file_name()
            .expect("filename exists")
            .to_str()
            .expect("filename to str");
        sqlx::query("UPDATE posts SET compat_video = $1 WHERE id = $2")
            .bind(compat_filename)
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("query succeeds");
    }

    /// Updates the media dimensions for a post in the database.
    ///
    /// # Parameters
    /// - `tx`: Database connection (mutable reference)
    /// - `width`: Width of the media in pixels
    /// - `height`: Height of the media in pixels
    pub async fn update_media_dimensions(&self, tx: &mut PgConnection, width: i32, height: i32) {
        sqlx::query("UPDATE posts SET media_width = $1, media_height = $2 WHERE id = $3")
            .bind(width)
            .bind(height)
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("query succeeds");
    }

    /// Updates the poster filename for video posts.
    ///
    /// # Parameters
    /// - `tx`: Database connection (mutable reference)
    /// - `video_poster_path`: Path to the poster image file
    ///
    /// # Panics
    /// Panics if the poster filename cannot be extracted or converted to a string.
    pub async fn update_poster(&self, tx: &mut PgConnection, video_poster_path: &Path) {
        let media_poster_filename = video_poster_path
            .file_name()
            .expect("filename exists")
            .to_str()
            .expect("filename to str");

        sqlx::query("UPDATE posts SET video_poster = $1 WHERE id = $2")
            .bind(media_poster_filename)
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("query succeeds");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
