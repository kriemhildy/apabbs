//! Post submission logic and helpers.
//!
//! This module provides the `PostSubmission` struct and related logic for handling new post creation,
//! media uploads, YouTube embed processing, and intro preview truncation.

use crate::post::Post;
use crate::user::User;
use phf::phf_map;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::error::Error;
use std::path::PathBuf;
use url::Url;
use uuid::Uuid;

/// Length (in characters) of randomly generated post keys for new posts.
pub const KEY_LENGTH: usize = 8;

/// Directory path for caching downloaded YouTube thumbnails for posts.
pub const YOUTUBE_DIR: &str = "pub/youtube";

/// Maximum number of YouTube video embeds allowed per post.
pub const MAX_YOUTUBE_EMBEDS: usize = 16;

/// Maximum number of bytes allowed for a post intro preview (truncation limit).
pub const MAX_INTRO_BYTES: usize = 1600;

/// Maximum number of line breaks allowed in a post intro preview.
pub const MAX_INTRO_BREAKS: usize = 24;

/// Static map for YouTube thumbnail sizes with dimensions and short video flag.
static YOUTUBE_THUMBNAIL_SIZES: phf::Map<&'static str, (i32, i32, bool)> = phf_map! {
    "maxresdefault" => (1280, 720, false),
    "sddefault" => (640, 480, false),
    "hqdefault" => (480, 360, false),
    "mqdefault" => (320, 180, false),
    "default" => (120, 90, false),
    "oar2" => (1080, 1920, true),
};

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
    /// Generates a unique key for a post.
    ///
    /// # Parameters
    /// - `tx`: Database connection (mutable reference) for checking key uniqueness.
    ///
    /// # Returns
    /// A unique random string key for the post.
    pub async fn generate_key(tx: &mut PgConnection) -> Result<String, sqlx::Error> {
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
                    .await?;
            if !exists {
                return Ok(key);
            }
        }
    }

    /// Inserts a new post into the database.
    ///
    /// Handles determining the media type, generating the post key, and extracting the intro limit from the body content.
    ///
    /// # Parameters
    /// - `tx`: Database connection (mutable reference)
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
    ) -> Result<Post, Box<dyn Error>> {
        let (media_category, media_mime_type) =
            Self::determine_media_type(self.media_filename.as_deref());
        let (session_token, account_id) = match user.account {
            Some(ref account) => (None, Some(account.id)),
            None => (Some(self.session_token), None),
        };
        let html_body = self.body_to_html(key).await?;
        let youtube = html_body.contains(r#"<a href=\"https://www.youtube.com\"#);
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
        .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    /// Downloads a YouTube thumbnail for the given video ID.
    ///
    /// Tries to download the thumbnail in various sizes and returns the path to the downloaded thumbnail image along with its dimensions.
    ///
    /// # Parameters
    /// - `video_id`: The ID of the YouTube video
    /// - `youtube_short`: Whether the video is a YouTube Shorts video
    ///
    /// # Returns
    /// An optional tuple containing the thumbnail path and its width and height: `Option<(PathBuf, i32, i32)>`
    pub async fn download_youtube_thumbnail(
        video_id: &str,
        youtube_short: bool,
    ) -> Result<Option<(PathBuf, i32, i32)>, Box<dyn Error>> {
        println!("Downloading YouTube thumbnail for video ID: {}", video_id);
        let video_id_dir = std::path::Path::new(YOUTUBE_DIR).join(video_id);

        // Helper function only used in this function
        fn dimensions(size: &str) -> (i32, i32, bool) {
            *YOUTUBE_THUMBNAIL_SIZES.get(size).expect("size exists")
        }

        if video_id_dir.exists() {
            if let Some(first_entry) = video_id_dir.read_dir()?.next() {
                let existing_thumbnail_path = first_entry?.path();
                let size = existing_thumbnail_path
                    .file_name()
                    .ok_or("Filename does not exist")?
                    .to_str()
                    .ok_or("Filename is not valid UTF-8")?
                    .split('.')
                    .next()
                    .ok_or("Filename does not have a basename")?;
                let (width, height, _) = dimensions(size);
                return Ok(Some((existing_thumbnail_path, width, height)));
            }
        } else {
            tokio::fs::create_dir(&video_id_dir).await?;
        }

        let thumbnail_sizes: Vec<&str> = YOUTUBE_THUMBNAIL_SIZES
            .entries()
            .filter(|(_, value)| value.2 == youtube_short)
            .map(|(size, _)| *size)
            .collect();

        for size in thumbnail_sizes {
            let local_thumbnail_path = video_id_dir.join(format!("{}.jpg", size));
            let remote_thumbnail_url =
                format!("https://img.youtube.com/vi/{}/{}.jpg", video_id, size);
            let curl_status = tokio::process::Command::new("curl")
                .args(["--silent", "--fail", "--output"])
                .arg(&local_thumbnail_path)
                .arg(&remote_thumbnail_url)
                .status()
                .await?;
            if curl_status.success() {
                let (width, height, _) = dimensions(size);
                return Ok(Some((local_thumbnail_path, width, height)));
            }
        }

        Ok(None)
    }

    /// Converts the post body from plain text to HTML format.
    ///
    /// Performs basic HTML escaping and replaces URLs with anchor links. YouTube links are processed to embed thumbnails and video IDs.
    ///
    /// # Parameters
    /// - `key`: The unique key of the post, used for generating YouTube links
    ///
    /// # Returns
    /// The HTML-formatted body of the post as a `String`.
    pub async fn body_to_html(&self, key: &str) -> Result<String, Box<dyn Error>> {
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
        let url_pattern = Regex::new(r#"\b(https?://[^\s<]{4,256})\b"#).expect("builds regex");
        let anchor_tag = r#"<a href="$1">$1</a>"#;
        html = url_pattern.replace_all(&html, anchor_tag).to_string();
        Self::embed_youtube(html, key).await
    }

    /// Embeds YouTube video thumbnails in the post HTML.
    ///
    /// Scans the post HTML for YouTube links and replaces them with embedded thumbnail images and video IDs. Generates HTML for the YouTube embed.
    ///
    /// # Parameters
    /// - `html`: The HTML content of the post body
    /// - `key`: The unique key of the post, used in the embed HTML
    ///
    /// # Returns
    /// The HTML content with YouTube embeds as a `String`.
    pub async fn embed_youtube(mut html: String, key: &str) -> Result<String, Box<dyn Error>> {
        let youtube_link_pattern = concat!(
            r#"(?m)^ *<a href=""#,
            r#"(https?://(?:youtu\.be/|(?:www\.|m\.)?youtube\.com/"#,
            r#"(watch\S*(?:\?|&amp;)v=|shorts/))"#,
            r#"([^&\s\?]+)\S*)">\S+</a> *(?:<br>)?$"#,
        );
        let youtube_link_regex = Regex::new(youtube_link_pattern).expect("builds regex");
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
                let parsed_url = Url::parse(url_str)?;
                parsed_url
                    .query_pairs()
                    .find(|(k, _)| k == "t")
                    .map(|(_, v)| v.to_string())
            };
            println!("youtube_video_id: {}", youtube_video_id);
            println!("youtube_timestamp: {:?}", youtube_timestamp);
            let thumbnail_tuple =
                Self::download_youtube_thumbnail(youtube_video_id, youtube_short).await?;
            let (local_thumbnail_url, width, height) = match thumbnail_tuple {
                None => break,
                Some((path, width, height)) => (
                    path.to_str()
                        .expect("converts path")
                        .strip_prefix("pub")
                        .expect("strips pub")
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
        Ok(html)
    }

    /// Determines the intro limit for a post based on its HTML content.
    ///
    /// The intro limit is the byte offset where the post should be truncated in previews. It is determined by:
    /// - Maximum byte length (`MAX_INTRO_BYTES`)
    /// - Maximum number of line breaks (`MAX_INTRO_BREAKS`)
    /// - Presence of YouTube video embeds
    ///
    /// # Parameters
    /// - `html`: The HTML content of the post body
    ///
    /// # Returns
    /// An optional byte offset (`Option<i32>`) for truncating the post intro
    pub fn intro_limit(html: &str) -> Option<i32> {
        println!("html.len(): {}", html.len());
        if html.is_empty() {
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
            Regex::new(r#"(?s)<div class="youtube">(?:.*?</div>){3}"#).expect("builds regex");
        // debug
        let mut youtube_iter = youtube_pattern.find_iter(slice);
        println!("first youtube_pattern match: {:?}", youtube_iter.next());
        let youtube_limit = match youtube_iter.next() {
            None => None,
            Some(mat) => {
                println!("second youtube_pattern match: {:?}", mat);
                let before_second_youtube = &slice[..mat.start()];
                // strip any breaks or whitespace that might be present at the end
                let strip_breaks_pattern = Regex::new("(?:<br>\n)+$").expect("builds regex");
                let stripped = strip_breaks_pattern.replace(before_second_youtube, "");
                Some(stripped.trim_end().len() as i32)
            }
        };
        // check for the maximum breaks
        let single_break_pattern = Regex::new("<br>\n").expect("builds regex");
        let break_limit = single_break_pattern
            .find_iter(slice)
            .nth(MAX_INTRO_BREAKS)
            .map(|mat| mat.start() as i32);
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
        // Truncate to the last break(s) before the limit
        let multiple_breaks_pattern = Regex::new("(?:<br>\n)+").expect("builds regex");
        if let Some(mat) = multiple_breaks_pattern.find_iter(slice).last() {
            println!("Found last break(s) at byte: {}", mat.start());
            return Some(mat.start() as i32);
        }
        // If no breaks, truncate to the last space byte
        if let Some(last_space) = slice.rfind(' ') {
            return Some(last_space as i32);
        }
        // If no space found, use the last valid utf8 character index
        // Need to strip incomplete html entities
        // Check for & which is not terminated by a ;
        let incomplete_entity_pattern = Regex::new(r"&[^;]*$").expect("builds regex");
        if let Some(mat) = incomplete_entity_pattern.find(slice) {
            println!("Found incomplete entity at byte: {}", mat.start());
            return Some(mat.start() as i32);
        }
        // No incomplete entity, return last valid utf8 character index
        Some(last_valid_utf8_index as i32)
    }
}

/// Represents a request to hide a post from public view
///
/// This structure contains the session token of the user requesting to hide a post
/// and the unique key of the post to be hidden. Used primarily for moderation actions
/// or user-initiated content hiding.
#[derive(Serialize, Deserialize)]
pub struct PostHiding {
    /// Session token of the user requesting to hide the post
    pub session_token: Uuid,

    /// Unique key identifier of the post to be hidden
    pub key: String,
}

impl PostHiding {
    /// Sets a post's hidden flag to true in the database.
    ///
    /// This effectively removes the post from public view without deleting it. The post will no longer appear in feeds or search results, but remains in the database for record-keeping and potential future restoration.
    ///
    /// # Parameters
    /// - `tx`: Database connection (mutable reference) for executing the update
    ///
    /// # Note
    /// This method does not verify authorization - the caller must ensure that the user identified by `session_token` has permission to hide this post.
    pub async fn hide_post(&self, tx: &mut PgConnection) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE posts SET hidden = true WHERE key = $1")
            .bind(&self.key)
            .execute(&mut *tx)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests the conversion of post body text to HTML with YouTube embed generation
    ///
    /// This test verifies:
    /// - Basic HTML escaping (converting <, >, &, etc. to HTML entities)
    /// - URL recognition and conversion to anchor tags
    /// - YouTube link detection and conversion to embedded thumbnails
    /// - Handling of various YouTube URL formats (standard, mobile, shorts, etc.)
    /// - Proper timestamp handling in YouTube links
    #[tokio::test]
    pub async fn body_to_html() {
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
            submission.body_to_html(key).await.unwrap(),
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

        // Generate HTML with embeds containing timestamps
        let html = submission.body_to_html("testkey").await.unwrap();

        // Verify timestamps were properly extracted and included
        assert!(html.contains("&amp;t=1m30s"));
        assert!(html.contains("&amp;t=25s"));
        assert!(html.contains("&amp;t=42"));
    }
}
