//! Media module for posts.
//!
//! Provides core path helpers, constants, and utility functions for post media files.
//! Most media processing logic (encryption, image, and video handling) is delegated to submodules.
//!
//! Functions provided in this module:
//! - Post::encrypted_media_path
//! - Post::published_media_path
//! - Post::thumbnail_path
//! - Post::compat_video_path
//! - PostSubmission::determine_media_type
//! - PostReview::write_media_file
//! - PostReview::alternate_path
//! - PostReview::delete_media_key_dir
//! - PostReview::delete_upload_key_dir
//! - PostReview::publish_media

pub mod encryption;
pub mod images;
pub mod video;

use super::{MediaCategory, Post, review::PostReview, submission::PostSubmission};
use regex::Regex;
use sqlx::PgConnection;
use std::{
    error::Error,
    path::{Path, PathBuf},
};

/// Directory name for encrypted (at-rest) media file storage.
pub const UPLOADS_DIR: &str = "uploads";
/// Directory name for published (decrypted) media files accessible to users.
pub const MEDIA_DIR: &str = "pub/media";

/// Maximum allowed width (in pixels) for generated thumbnails.
pub const MAX_THUMB_WIDTH: i32 = 1280;
/// Maximum allowed height (in pixels) for generated thumbnails.
pub const MAX_THUMB_HEIGHT: i32 = 2160;

/// Default MIME type for unknown or binary file types.
pub const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";

impl Post {
    /// Returns the path to the encrypted media file for this post.
    pub fn encrypted_media_path(&self) -> PathBuf {
        let encrypted_filename = format!("{}.gpg", self.media_filename.as_ref().unwrap());
        std::path::Path::new(UPLOADS_DIR)
            .join(&self.key)
            .join(encrypted_filename)
    }

    /// Returns the path to the published (decrypted) media file for this post.
    pub fn published_media_path(&self) -> PathBuf {
        std::path::Path::new(MEDIA_DIR)
            .join(&self.key)
            .join(self.media_filename.as_ref().unwrap())
    }

    /// Returns the path to the thumbnail file for this post.
    pub fn thumbnail_path(&self) -> PathBuf {
        std::path::Path::new(MEDIA_DIR)
            .join(&self.key)
            .join(self.thumb_filename.as_ref().unwrap())
    }

    /// Returns the path of a compatibility video file for this post.
    pub fn compat_video_path(&self) -> PathBuf {
        std::path::Path::new(MEDIA_DIR)
            .join(&self.key)
            .join(self.compat_video.as_ref().unwrap())
    }
}

impl PostSubmission {
    /// Determines the media type and MIME type from the file extension.
    pub fn determine_media_type(
        media_filename: Option<&str>,
    ) -> (Option<MediaCategory>, Option<String>) {
        let media_filename = match media_filename {
            None => return (None, None),
            Some(media_filename) => media_filename,
        };
        use MediaCategory::*;
        let extension = media_filename.split('.').next_back();
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
                "mkv" => (Some(Video), "video/x-matroska"),
                "ts" => (Some(Video), "video/mp2t"),
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
        (media_category, Some(media_mime_type_str.to_string()))
    }
}

impl PostReview {
    /// Writes decrypted media file bytes to the public directory.
    pub async fn write_media_file(
        published_media_path: &Path,
        media_bytes: Vec<u8>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let media_key_dir = published_media_path
            .parent()
            .ok_or("failed to get parent directory for media file")?;
        tokio::fs::create_dir(media_key_dir)
            .await
            .map_err(|e| format!("failed to create media key directory: {e}"))?;
        tokio::fs::write(&published_media_path, media_bytes)
            .await
            .map_err(|e| format!("failed to write media file: {e}"))?;
        Ok(())
    }

    /// Constructs an alternate file path for a derived media file.
    pub fn alternate_path(media_path: &Path, prefix: &str, extension: &str) -> PathBuf {
        let media_filename = media_path
            .file_name()
            .expect("Get filename from Path")
            .to_str()
            .expect("Convert filename to str");

        let key_dir = media_path.parent().unwrap();
        let extension_pattern = Regex::new(r"\.[^\.]+$").expect("Build regular expression");

        // Create thumbnail filename with "tn_" prefix and specified extension
        let alternate_filename =
            prefix.to_string() + &extension_pattern.replace(media_filename, extension);

        key_dir.join(&alternate_filename)
    }

    /// Deletes all media files associated with a post.
    pub async fn delete_media_key_dir(key: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let media_key_dir = std::path::Path::new(MEDIA_DIR).join(key);

        tokio::fs::remove_dir_all(&media_key_dir)
            .await
            .map_err(|e| format!("failed to remove media key dir and its contents: {e}"))?;
        Ok(())
    }

    /// Deletes an encrypted media file and its containing directory.
    pub async fn delete_upload_key_dir(key: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let upload_key_dir = std::path::Path::new(UPLOADS_DIR).join(key);

        tokio::fs::remove_dir_all(&upload_key_dir)
            .await
            .map_err(|e| format!("failed to remove uploads key dir: {e}"))?;
        Ok(())
    }

    /// Decrypts and processes media for publication.
    pub async fn publish_media(
        tx: &mut PgConnection,
        post: &Post,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Decrypt the media file
        let media_bytes = post
            .decrypt_media_file()
            .await
            .map_err(|e| format!("failed to decrypt media file: {e}"))?;

        // Write the decrypted file to the published media directory
        let published_media_path = post.published_media_path();
        Self::write_media_file(&published_media_path, media_bytes)
            .await
            .map_err(|e| format!("failed to write decrypted media file: {e}"))?;

        // Process according to media type
        match post.media_category {
            Some(MediaCategory::Image) => Self::process_image(tx, post)
                .await
                .map_err(|e| format!("failed to process image media: {e}"))?,
            Some(MediaCategory::Video) => Self::process_video(tx, post)
                .await
                .map_err(|e| format!("failed to process video media: {e}"))?,
            // Audio files and posts without media don't need processing
            Some(MediaCategory::Audio) | None => (),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests MIME type and media category detection for different file extensions.
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

    /// Tests path construction for media files.
    #[tokio::test]
    async fn media_paths() {
        let post = Post {
            key: String::from("abcd1234"),
            media_filename: Some(String::from("test.jpg")),
            thumb_filename: Some(String::from("tn_test.webp")),
            ..Post::default()
        };

        // Test path construction
        assert_eq!(
            post.encrypted_media_path().to_str().unwrap(),
            format!("{UPLOADS_DIR}/abcd1234/test.jpg.gpg")
        );

        assert_eq!(
            post.published_media_path().to_str().unwrap(),
            format!("{MEDIA_DIR}/abcd1234/test.jpg")
        );

        assert_eq!(
            post.thumbnail_path().to_str().unwrap(),
            format!("{MEDIA_DIR}/abcd1234/tn_test.webp")
        );
    }
}
