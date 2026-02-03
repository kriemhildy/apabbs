//! Media module for posts.
//!
//! Provides core path helpers, constants, and utility functions for post media files.
//! Most media processing logic (encryption, image, and video handling) is delegated to submodules.

pub mod encryption;
pub mod images;
pub mod videos;

use super::{MediaCategory, Post};
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

/// Determines the media type and MIME type from the file extension.
pub fn determine_media_type(
    media_filename: Option<&str>,
) -> (Option<MediaCategory>, Option<String>) {
    let media_filename = match media_filename {
        None => return (None, None),
        Some(media_filename) => media_filename,
    };
    let extension = media_filename.split('.').next_back();
    let (media_category, media_mime_type_str) = match extension {
        Some(extension) => match extension.to_lowercase().as_str() {
            "jpg" | "jpeg" | "jpe" | "jfif" | "pjpeg" | "pjp" => {
                (Some(MediaCategory::Image), "image/jpeg")
            }
            "gif" => (Some(MediaCategory::Image), "image/gif"),
            "png" => (Some(MediaCategory::Image), "image/png"),
            "webp" => (Some(MediaCategory::Image), "image/webp"),
            "svg" => (Some(MediaCategory::Image), "image/svg+xml"),
            "avif" => (Some(MediaCategory::Image), "image/avif"),
            "ico" | "cur" => (Some(MediaCategory::Image), "image/x-icon"),
            "apng" => (Some(MediaCategory::Image), "image/apng"),
            "bmp" => (Some(MediaCategory::Image), "image/bmp"),
            "tiff" | "tif" => (Some(MediaCategory::Image), "image/tiff"),
            "avi" => (Some(MediaCategory::Video), "video/x-msvideo"),
            "mpeg" | "mpg" | "mpe" => (Some(MediaCategory::Video), "video/mpeg"),
            "mp4" | "m4v" => (Some(MediaCategory::Video), "video/mp4"),
            "webm" => (Some(MediaCategory::Video), "video/webm"),
            "ogv" => (Some(MediaCategory::Video), "video/ogg"),
            "flv" => (Some(MediaCategory::Video), "video/x-flv"),
            "mov" => (Some(MediaCategory::Video), "video/quicktime"),
            "wmv" => (Some(MediaCategory::Video), "video/x-ms-wmv"),
            "mkv" => (Some(MediaCategory::Video), "video/x-matroska"),
            "ts" => (Some(MediaCategory::Video), "video/mp2t"),
            "mp3" => (Some(MediaCategory::Audio), "audio/mpeg"),
            "ogg" => (Some(MediaCategory::Audio), "audio/ogg"),
            "wav" => (Some(MediaCategory::Audio), "audio/wav"),
            "flac" => (Some(MediaCategory::Audio), "audio/flac"),
            "opus" => (Some(MediaCategory::Audio), "audio/opus"),
            "m4a" => (Some(MediaCategory::Audio), "audio/mp4"),
            "aac" => (Some(MediaCategory::Audio), "audio/aac"),
            "wma" => (Some(MediaCategory::Audio), "audio/x-ms-wma"),
            "weba" => (Some(MediaCategory::Audio), "audio/webm"),
            "3gp" => (Some(MediaCategory::Audio), "audio/3gpp"),
            "3g2" => (Some(MediaCategory::Audio), "audio/3gpp2"),
            _ => (Some(MediaCategory::Other), APPLICATION_OCTET_STREAM),
        },
        None => (Some(MediaCategory::Other), APPLICATION_OCTET_STREAM),
    };
    (media_category, Some(media_mime_type_str.to_string()))
}

/// Writes decrypted media file bytes to the public directory.
pub async fn write_media_file(
    published_media_path: &Path,
    media_bytes: Vec<u8>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let media_key_dir = published_media_path.parent().unwrap();
    tokio::fs::create_dir(media_key_dir).await?;
    tokio::fs::write(&published_media_path, media_bytes).await?;
    Ok(())
}

/// Constructs an alternate file path for a derived media file.
pub fn alternate_path(media_path: &Path, prefix: &str, extension: &str) -> PathBuf {
    let media_filename = media_path.file_name().unwrap().to_str().unwrap();
    let key_dir = media_path.parent().unwrap();
    let extension_pattern = Regex::new(r"\.[^\.]+$").expect("build regex");
    let alternate_filename =
        prefix.to_string() + &extension_pattern.replace(media_filename, extension);
    key_dir.join(&alternate_filename)
}

/// Deletes all media files associated with a post.
pub async fn delete_media_key_dir(key: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let media_key_dir = std::path::Path::new(MEDIA_DIR).join(key);
    tokio::fs::remove_dir_all(&media_key_dir).await?;
    Ok(())
}

/// Deletes an encrypted media file and its containing directory.
pub async fn delete_upload_key_dir(key: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let upload_key_dir = std::path::Path::new(UPLOADS_DIR).join(key);
    tokio::fs::remove_dir_all(&upload_key_dir).await?;
    Ok(())
}

/// Decrypts and processes media for publication.
pub async fn publish_media(
    tx: &mut PgConnection,
    post: &Post,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    encryption::decrypt_media_file(post).await?;
    match post.media_category {
        Some(MediaCategory::Image) => images::process_image(tx, post).await?,
        Some(MediaCategory::Video) => videos::process_video(tx, post).await?,
        Some(MediaCategory::Audio) | Some(MediaCategory::Other) | None => (),
    }
    Ok(())
}

/// Unpublish a media file that has been published.
///
/// Used when media needs to be moved back from published to reported state.
pub async fn unpublish_media(post: &Post) -> Result<(), Box<dyn Error + Send + Sync>> {
    let published_media_path = post.published_media_path();
    let bytes = tokio::fs::read(&published_media_path).await?;
    encryption::encrypt_uploaded_file(post, bytes).await?;
    delete_media_key_dir(&post.key).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests MIME type and media category detection for different file extensions.
    #[tokio::test]
    async fn media_type_detection() {
        let (category, mime) = determine_media_type(Some("test.jpg"));
        assert_eq!(category, Some(MediaCategory::Image));
        assert_eq!(mime, Some("image/jpeg".to_string()));

        let (category, mime) = determine_media_type(Some("video.mp4"));
        assert_eq!(category, Some(MediaCategory::Video));
        assert_eq!(mime, Some("video/mp4".to_string()));

        let (category, mime) = determine_media_type(Some("audio.mp3"));
        assert_eq!(category, Some(MediaCategory::Audio));
        assert_eq!(mime, Some("audio/mpeg".to_string()));

        let (category, mime) = determine_media_type(Some("document.pdf"));
        assert_eq!(category, Some(MediaCategory::Other));
        assert_eq!(mime, Some(APPLICATION_OCTET_STREAM.to_string()));

        let (category, mime) = determine_media_type(None);
        assert_eq!(category, None);
        assert_eq!(mime, None);
    }

    // Tests path construction for media files.
    #[tokio::test]
    async fn media_paths() {
        let post = Post {
            key: String::from("abcd1234"),
            media_filename: Some(String::from("test.jpg")),
            thumb_filename: Some(String::from("tn_test.webp")),
            ..Post::default()
        };

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
