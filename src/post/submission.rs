//! Post submission logic and helpers.
//!
//! This module provides the `PostSubmission` struct and related logic for handling new post creation,
//! media uploads, YouTube embed processing, and intro preview truncation.

pub mod youtube;

use crate::{
    post::{Post, media},
    user::User,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::error::Error;
use uuid::Uuid;

/// Length (in characters) of randomly generated post keys for new posts.
pub const KEY_LENGTH: usize = 8;

/// Maximum number of bytes allowed for a post intro preview (truncation limit).
pub const MAX_INTRO_BYTES: usize = 1600;

/// Maximum number of line breaks allowed in a post intro preview.
pub const MAX_INTRO_BREAKS: usize = 24;

/// Represents a post submission from a user.
///
/// Contains all data needed to create a new post including the content,
/// associated media files, and user identification information. Handles converting
/// raw input into properly formatted post content with media processing.
#[derive(Default, Serialize, Deserialize)]
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
    /// Inserts a new post into the database.
    ///
    /// Handles determining the media type, generating the post key, and extracting the intro limit from the body content.
    pub async fn insert(
        &self,
        tx: &mut PgConnection,
        user: &User,
        key: &str,
    ) -> Result<Post, Box<dyn Error + Send + Sync>> {
        let (media_category, media_mime_type) =
            media::determine_media_type(self.media_filename.as_deref());
        let (session_token, account_id) = match user.account {
            Some(ref account) => (None, Some(account.id)),
            None => (Some(self.session_token), None),
        };
        let html_body = self
            .body_to_html(key)
            .await
            .map_err(|e| format!("convert post body to HTML: {e}"))?;
        let youtube = html_body.contains(r#"<a href="https://www.youtube.com"#);
        let intro_limit = intro_limit(&html_body);
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
        .bind(&user.ip_hash)
        .bind(self.media_filename.as_deref())
        .bind(media_category)
        .bind(media_mime_type.as_deref())
        .bind(youtube)
        .bind(intro_limit)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("insert post: {e}").into())
    }

    /// Converts the post body from plain text to HTML, escaping and linking URLs, and embedding YouTube thumbnails.
    pub async fn body_to_html(&self, key: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
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
        let url_pattern = Regex::new(r#"\b(https?://[^\s<]{4,256})\b"#).expect("build regex");
        let anchor_tag = r#"<a href="$1" rel="noopener" target="_blank">$1</a>"#;
        html = url_pattern.replace_all(&html, anchor_tag).to_string();
        youtube::embed_youtube(html, key).await
    }
}

/// Generates a unique key for a post.
pub async fn generate_key(tx: &mut PgConnection) -> Result<String, Box<dyn Error + Send + Sync>> {
    use rand::{Rng, distr::Alphanumeric};
    loop {
        let key = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(KEY_LENGTH)
            .map(char::from)
            .collect();
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM posts WHERE key = $1)")
            .bind(&key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| format!("check post key existence: {e}"))?;
        if !exists {
            return Ok(key);
        }
    }
}

/// Determines the intro limit for a post preview based on HTML content, line breaks, and YouTube embeds.
pub fn intro_limit(html: &str) -> Option<i32> {
    tracing::debug!("html.len(): {}", html.len());
    if html.is_empty() {
        return None;
    }
    // Get a slice of the maximum intro bytes limited to the last valid UTF-8 character
    let last_valid_utf8_index = html
        .char_indices()
        .take_while(|&(idx, _)| idx < MAX_INTRO_BYTES)
        .last()
        .map_or(0, |(idx, _)| idx);
    tracing::debug!(last_valid_utf8_index);
    let slice = if html.len() - 1 > last_valid_utf8_index {
        &html[..last_valid_utf8_index]
    } else {
        html
    };
    // Stop before a second YouTube video
    let youtube_pattern =
        Regex::new(r#"(?s)<div class="youtube">(?:.*?</div>){3}"#).expect("build regex");
    let mut youtube_iter = youtube_pattern.find_iter(slice);
    let first_youtube_match = youtube_iter.next();
    if let Some(mat) = first_youtube_match {
        tracing::debug!("First YouTube match start: {}", mat.start());
    } else {
        tracing::debug!("No YouTube match found");
    }
    let youtube_limit = match youtube_iter.next() {
        None => None,
        Some(mat) => {
            tracing::debug!("Second YouTube match start: {}", mat.start());
            let before_second_youtube = &slice[..mat.start()];
            // Strip any breaks or whitespace that might be present at the end
            let strip_breaks_pattern = Regex::new("(?:<br>\n)+$").expect("build regex");
            let stripped = strip_breaks_pattern.replace(before_second_youtube, "");
            Some(stripped.trim_end().len() as i32)
        }
    };
    // Check for the maximum breaks
    let single_break_pattern = Regex::new("<br>\n").expect("build regex");
    let break_limit = single_break_pattern
        .find_iter(slice)
        .nth(MAX_INTRO_BREAKS)
        .map(|mat| mat.start() as i32);
    // Take the smallest of YouTube and break limits
    tracing::debug!(youtube_limit = ?youtube_limit, break_limit = ?break_limit);
    let min_limit = match (youtube_limit, break_limit) {
        (None, None) => None,
        (Some(y), None) => Some(y),
        (None, Some(b)) => Some(b),
        (Some(y), Some(b)) => Some(y.min(b)),
    };
    tracing::debug!(min_limit = ?min_limit);
    if min_limit.is_some() {
        tracing::info!(min_limit, "Intro limit found via breaks or YouTubes");
        return min_limit;
    }
    // Do not truncate if beneath the maximum intro length
    if html.len() <= MAX_INTRO_BYTES {
        return None;
    }
    // Truncate to the last break(s) before the limit
    let multiple_breaks_pattern = Regex::new("(?:<br>\n)+").expect("build regex");
    if let Some(mat) = multiple_breaks_pattern.find_iter(slice).last() {
        tracing::info!(
            "Intro limit found via last break(s) at byte: {}",
            mat.start()
        );
        return Some(mat.start() as i32);
    }
    // If no breaks, truncate to the last space byte
    if let Some(last_space) = slice.rfind(' ') {
        return Some(last_space as i32);
    }
    // If no space found, use the last valid utf8 character index
    // Need to strip incomplete html entities
    // Check for & which is not terminated by a ;
    let incomplete_entity_pattern = Regex::new(r"&[^;]*$").expect("build regex");
    if let Some(mat) = incomplete_entity_pattern.find(slice) {
        tracing::info!(
            "Intro limit found via incomplete entity at byte: {}",
            mat.start()
        );
        return Some(mat.start() as i32);
    }
    // No incomplete entity, return last valid utf8 character index
    Some(last_valid_utf8_index as i32)
}

/// Represents a request to hide a post from personal view
///
/// This structure contains the session token of the user requesting to hide the post
/// and the unique key of the post to be hidden. Used primarily for users to hide the own posts
/// after they have been rejected.
#[derive(Serialize, Deserialize)]
pub struct PostHiding {
    /// Session token of the user requesting to hide the post
    pub session_token: Uuid,
    /// Unique key identifier of the post to be hidden
    pub key: String,
}

impl PostHiding {
    /// Sets a post's hidden flag to true in the database. Caller must ensure authorization.
    pub async fn hide_post(
        &self,
        tx: &mut PgConnection,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        sqlx::query("UPDATE posts SET hidden = true WHERE key = $1")
            .bind(&self.key)
            .execute(&mut *tx)
            .await
            .map(|_| ())
            .map_err(|e| format!("hide post: {e}").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_tracing_for_test;

    // Tests the intro_limit functionality for post previews.
    #[tokio::test]
    async fn test_intro_limit() {
        init_tracing_for_test();
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
        assert_eq!(super::intro_limit(&html), Some(120));

        // Case 2: YouTube content first, then line breaks beyond the limit
        let html = two_youtubes.to_string() + &str::repeat("<br>\n", MAX_INTRO_BREAKS + 1);
        assert_eq!(intro_limit(&html), Some(141));

        // Case 3: Content shorter than the limit - shouldn't truncate
        let html = str::repeat("foo ", 300);
        assert_eq!(intro_limit(&html), None);

        // Case 4: Content with line breaks but still under the break limit
        let html = str::repeat("foo ", 100)
            + "<br>\n"
            + &str::repeat("bar ", 200)
            + "<br>\n"
            + &str::repeat("baz ", 100);
        assert_eq!(intro_limit(&html), Some(1205));

        // Case 5: Content exactly at the byte limit boundary
        let html = str::repeat("x", MAX_INTRO_BYTES - 2) + " yy";
        assert_eq!(intro_limit(&html), Some(1598));

        // Case 6: Content beyond the byte limit
        let html = str::repeat("x", MAX_INTRO_BYTES) + " y";
        assert_eq!(intro_limit(&html), Some(1599));

        // Case 7: HTML entity at the boundary
        let html = str::repeat("x", MAX_INTRO_BYTES - 2) + "&quot;";
        assert_eq!(intro_limit(&html), Some(1598));

        // Case 8: Multi-byte character at the boundary
        let html = str::repeat("x", MAX_INTRO_BYTES - 2) + "コ";
        assert_eq!(intro_limit(&html), Some(1598));
    }

    // Tests YouTube timestamp extraction from various URL formats.
    // This needs to be moved to an integration test or else localized to avoid I/O.
    #[tokio::test]
    async fn youtube_timestamp_extraction() {
        let submission = PostSubmission {
            body: concat!(
                "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=1m30s\n",
                "https://www.youtube.com/watch?t=25s&v=dQw4w9WgXcQ\n",
                "https://youtu.be/dQw4w9WgXcQ?t=42\n"
            )
            .to_string(),
            ..PostSubmission::default()
        };

        // Generate HTML with embeds containing timestamps
        let html = submission.body_to_html("testkey").await.unwrap();

        // Verify timestamps were properly extracted and included
        assert!(html.contains("&amp;t=1m30s"));
        assert!(html.contains("&amp;t=25s"));
        assert!(html.contains("&amp;t=42"));
    }
}
