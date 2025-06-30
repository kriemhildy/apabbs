//! Media file management and processing for posts.
//!
//! Handles encryption, decryption, thumbnail and poster generation, compatibility conversion,
//! and file system operations for post media. Provides helpers for MIME type detection,
//! path construction, and media processing workflows.

use super::submission::PostSubmission;
use super::{MediaCategory, Post, PostReview};
use crate::{AppState, utilities::*};
use regex::Regex;
use sqlx::PgConnection;
use std::error::Error;
use std::path::{Path, PathBuf};

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

    /// Encrypts the provided bytes using GPG with the application's key.
    pub async fn gpg_encrypt(&self, bytes: Vec<u8>) -> Result<(), Box<dyn Error + Send + Sync>> {
        let encrypted_media_path = self.encrypted_media_path();
        let encrypted_media_path_str = encrypted_media_path
            .to_str()
            .ok_or("failed to convert encrypted media path to string")?
            .to_string();
        let mut child = tokio::process::Command::new("gpg")
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
            .map_err(|e| format!("failed to spawn gpg process: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            tokio::io::AsyncWriteExt::write_all(&mut stdin, &bytes)
                .await
                .map_err(|e| format!("failed to write to gpg stdin: {e}"))?;
        }
        let child_status = child
            .wait()
            .await
            .map_err(|e| format!("failed to wait for gpg process: {e}"))?;
        if !child_status.success() {
            return Err("gpg failed to encrypt file".into());
        }
        tracing::info!(
            "File encrypted successfully: {}",
            encrypted_media_path.display()
        );
        Ok(())
    }

    /// Re-encrypts a media file that has already been published.
    ///
    /// Used when media needs to be moved back from published to reported state.
    pub async fn reencrypt_media_file(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let encrypted_file_path = self.encrypted_media_path();
        let uploads_key_dir = encrypted_file_path
            .parent()
            .ok_or("encrypted file path has no parent directory")?;
        tokio::fs::create_dir(uploads_key_dir)
            .await
            .map_err(|e| format!("failed to create uploads key directory: {e}"))?;
        let media_file_path = self.published_media_path();
        let media_bytes = tokio::fs::read(&media_file_path)
            .await
            .map_err(|e| format!("failed to read published media file: {e}"))?;
        let result = self
            .gpg_encrypt(media_bytes)
            .await
            .map_err(|e| format!("failed to encrypt media during re-encryption: {e}"));
        match result {
            Ok(()) => PostReview::delete_media_key_dir(&self.key)
                .await
                .map_err(|e| {
                    format!("failed to delete media key directory after re-encryption: {e}")
                })?,
            Err(ref msg) => {
                tokio::fs::remove_dir(uploads_key_dir).await.map_err(|e| {
                    format!(
                        "failed to remove uploads key directory after failed re-encryption: {e}"
                    )
                })?;
                tracing::error!("Re-encryption failed: {msg}");
            }
        }
        result.map_err(|e| e.into())
    }

    /// Decrypts the post's media file using GPG.
    pub async fn decrypt_media_file(&self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        if self.media_filename.is_none() {
            return Err("cannot decrypt media: post has no media file".into());
        }
        let encrypted_file_path = self
            .encrypted_media_path()
            .to_str()
            .ok_or("failed to convert encrypted media path to string")?
            .to_string();
        let output = tokio::process::Command::new("gpg")
            .args(["--batch", "--decrypt", "--passphrase-file", "gpg.key"])
            .arg(&encrypted_file_path)
            .output()
            .await
            .map_err(|e| format!("failed to execute GPG for decryption: {e}"))?;
        if !output.status.success() {
            return Err(format!("GPG failed to decrypt file, status: {}", output.status).into());
        }
        tracing::info!(
            key = self.key,
            media_filename = self.media_filename,
            "Media file decrypted successfully"
        );
        Ok(output.stdout)
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

    /// Encrypts the uploaded file data for a post.
    pub async fn encrypt_uploaded_file(
        self,
        post: &Post,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if self.media_bytes.is_none() {
            return Err("no media bytes provided for encryption".into());
        }
        let encrypted_file_path = post.encrypted_media_path();
        let uploads_key_dir = encrypted_file_path
            .parent()
            .ok_or("encrypted file path has no parent directory")?;
        tokio::fs::create_dir(uploads_key_dir)
            .await
            .map_err(|e| format!("failed to create uploads key directory: {e}"))?;
        let result = post.gpg_encrypt(self.media_bytes.unwrap()).await;
        if result.is_err() {
            tokio::fs::remove_dir(uploads_key_dir).await.map_err(|e| {
                format!("failed to remove uploads key directory after failed encryption: {e}")
            })?;
        }
        result
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

    /// Generates a thumbnail image for a given media file.
    pub async fn generate_image_thumbnail(
        published_media_path: &Path,
    ) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
        let media_path_str = published_media_path
            .to_str()
            .ok_or("failed to convert published_media_path to string")?
            .to_string();
        let extension = media_path_str
            .split('.')
            .next_back()
            .ok_or("failed to get file extension from published media path")?;

        // For animated images (GIF, WebP), extract the last frame as the thumbnail
        let vips_input_file_path = media_path_str.to_string()
            + match extension.to_lowercase().as_str() {
                "gif" | "webp" => "[n=-1]", // animated image support
                _ => "",
            };

        // Run vipsthumbnail to generate the thumbnail
        let command_output = tokio::process::Command::new("vipsthumbnail")
            .args([
                // Max dimensions with aspect ratio preserved
                &format!("--size={MAX_THUMB_WIDTH}x{MAX_THUMB_HEIGHT}>"),
                "--output=tn_%s.webp", // Output format with prefix
            ])
            .arg(&vips_input_file_path)
            .output()
            .await
            .map_err(|e| format!("failed to complete vipsthumbnail: {e}"))?;

        tracing::debug!(
            status = ?command_output.status,
            stderr = ?String::from_utf8_lossy(&command_output.stderr),
            "vipsthumbnail output:"
        );

        if !command_output.status.success() {
            return Err(format!("vipsthumbnail failed, status: {}", command_output.status).into());
        }

        let thumb_path = Self::alternate_path(published_media_path, "tn_", ".webp");
        if !thumb_path.exists() {
            return Err("thumbnail was not created successfully".into());
        }
        Ok(thumb_path)
    }

    /// Constructs an alternate file path for a derived media file.
    pub fn alternate_path(media_path: &Path, prefix: &str, extension: &str) -> PathBuf {
        let media_filename = media_path
            .file_name()
            .expect("gets media filename")
            .to_str()
            .expect("converts media filename");

        let key_dir = media_path.parent().unwrap();
        let extension_pattern = Regex::new(r"\.[^\.]+$").expect("builds regex");

        // Create thumbnail filename with "tn_" prefix and specified extension
        let alternate_filename =
            prefix.to_string() + &extension_pattern.replace(media_filename, extension);

        key_dir.join(&alternate_filename)
    }

    /// Returns true if the thumbnail file is larger than the original media file.
    pub fn thumbnail_is_larger(
        thumbnail_path: &Path,
        published_media_path: &Path,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let thumbnail_len = thumbnail_path
            .metadata()
            .map_err(|e| format!("failed to get thumbnail metadata: {e}"))?
            .len();
        let media_file_len = published_media_path
            .metadata()
            .map_err(|e| format!("failed to get media file metadata: {e}"))?
            .len();
        Ok(thumbnail_len > media_file_len)
    }

    /// Deletes an encrypted media file and its containing directory.
    pub async fn delete_upload_key_dir(
        encrypted_media_path: &Path,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let uploads_key_dir = encrypted_media_path
            .parent()
            .ok_or("encrypted_media_path should have a parent directory")?;

        tokio::fs::remove_file(&encrypted_media_path)
            .await
            .map_err(|e| format!("failed to remove encrypted media: {e}"))?;

        tokio::fs::remove_dir(&uploads_key_dir)
            .await
            .map_err(|e| format!("failed to remove uploads key dir: {e}"))?;
        Ok(())
    }

    /// Deletes all media files associated with a post.
    pub async fn delete_media_key_dir(key: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let media_key_dir = std::path::Path::new(MEDIA_DIR).join(key);

        tokio::fs::remove_dir_all(&media_key_dir)
            .await
            .map_err(|e| format!("failed to remove media key dir and its contents: {e}"))?;
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

    /// Processes image media for a post.
    pub async fn process_image(
        tx: &mut PgConnection,
        post: &Post,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let published_media_path = post.published_media_path();

        // Generate a thumbnail for the image
        let thumbnail_path = Self::generate_image_thumbnail(&published_media_path)
            .await
            .map_err(|e| format!("failed to generate image thumbnail: {e}"))?;

        if !thumbnail_path.exists() {
            return Err("thumbnail was not created successfully".into());
        }

        // If thumbnail is larger than original, don't use it
        if Self::thumbnail_is_larger(&thumbnail_path, &published_media_path)? {
            tokio::fs::remove_file(&thumbnail_path)
                .await
                .map_err(|e| format!("failed to remove oversized thumbnail: {e}"))?;
        } else {
            // Update the database with thumbnail information
            let (width, height) = Self::image_dimensions(&thumbnail_path)
                .await
                .map_err(|e| format!("failed to get thumbnail dimensions: {e}"))?;
            post.update_thumbnail(tx, &thumbnail_path, width, height)
                .await
                .map_err(|e| format!("failed to update thumbnail in database: {e}"))?
        }

        // Update the media dimensions in the database
        let (width, height) = Self::image_dimensions(&published_media_path)
            .await
            .map_err(|e| format!("failed to get published image dimensions: {e}"))?;
        post.update_media_dimensions(tx, width, height)
            .await
            .map_err(|e| format!("failed to update media dimensions in database: {e}"))?;

        Ok(())
    }

    /// Processes video media for a post.
    pub async fn process_video(
        tx: &mut PgConnection,
        post: &Post,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let published_media_path = post.published_media_path();

        // If necessary, generate a compatibility video for browser playback
        if !Self::video_is_compatible(&published_media_path)
            .await
            .map_err(|e| format!("failed to check video compatibility: {e}"))?
        {
            let compatibility_path = Self::generate_compatibility_video(&published_media_path)
                .await
                .map_err(|e| format!("failed to generate compatibility video: {e}"))?;

            if !compatibility_path.exists() {
                return Err("compatibility video generation failed".into());
            }

            // Update the database with the compatibility video path
            post.update_compat_video(tx, &compatibility_path)
                .await
                .map_err(|e| format!("failed to update compatibility video in database: {e}"))?;
        }

        // Generate a poster image from the video
        let video_poster_path = Self::generate_video_poster(&published_media_path)
            .await
            .map_err(|e| format!("failed to generate video poster: {e}"))?;
        post.update_poster(tx, &video_poster_path)
            .await
            .map_err(|e| format!("failed to update video poster in database: {e}"))?;

        // Update the post with media dimensions and poster
        let (media_width, media_height) = Self::image_dimensions(&video_poster_path)
            .await
            .map_err(|e| format!("failed to get video poster dimensions: {e}"))?;
        post.update_media_dimensions(tx, media_width, media_height)
            .await
            .map_err(|e| format!("failed to update media dimensions in database: {e}"))?;

        // Check if dimensions are large enough to necessitate a thumbnail
        if media_width > MAX_THUMB_WIDTH || media_height > MAX_THUMB_HEIGHT {
            let thumbnail_path = Self::generate_image_thumbnail(&video_poster_path)
                .await
                .map_err(|e| format!("failed to generate video thumbnail: {e}"))?;

            if !thumbnail_path.exists() {
                return Err("thumbnail was not created successfully".into());
            }

            let (thumb_width, thumb_height) = Self::image_dimensions(&thumbnail_path)
                .await
                .map_err(|e| format!("failed to get video thumbnail dimensions: {e}"))?;

            // Update the post with thumbnail info
            post.update_thumbnail(tx, &thumbnail_path, thumb_width, thumb_height)
                .await
                .map_err(|e| format!("failed to update video thumbnail in database: {e}"))?;
        }

        Ok(())
    }

    /// Returns the dimensions (width, height) of an image using vipsheader.
    pub async fn image_dimensions(
        image_path: &Path,
    ) -> Result<(i32, i32), Box<dyn Error + Send + Sync>> {
        tracing::debug!(image_path = ?image_path, "Getting image dimensions");
        let image_path_str = image_path
            .to_str()
            .ok_or("failed to convert image_path to string")?;

        async fn vipsheader(
            field: &str,
            image_path_str: &str,
        ) -> Result<i32, Box<dyn Error + Send + Sync>> {
            let output = tokio::process::Command::new("vipsheader")
                .args(["-f", field, image_path_str])
                .output()
                .await
                .map_err(|e| format!("failed to run vipsheader: {e}"))?;

            let value = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<i32>()
                .map_err(|e| format!("failed to parse vipsheader output as i32: {e}"))?;
            Ok(value)
        }

        let width = vipsheader("width", image_path_str).await?;
        let height = vipsheader("height", image_path_str).await?;
        tracing::info!(
            image_path = ?image_path,
            width = width,
            height = height,
            "Processed image dimensions",
        );
        Ok((width, height))
    }

    /// Returns true if the video is compatible for web playback using ffprobe.
    pub async fn video_is_compatible(
        video_path: &Path,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        tracing::debug!(video_path = ?video_path, "Checking video compatibility");
        let video_path_str = video_path
            .to_str()
            .ok_or("failed to convert video_path to string")?
            .to_string();

        // Helper to probe a single stream
        async fn probe_stream(
            video_path: &str,
            select: &str,
        ) -> Result<Option<StreamInfo>, Box<dyn Error + Send + Sync>> {
            let output = tokio::process::Command::new("ffprobe")
                .args([
                    "-v",
                    "error",
                    "-select_streams",
                    select,
                    "-show_entries",
                    "stream=codec_name,pix_fmt,profile,level",
                    "-of",
                    "default=noprint_wrappers=1",
                    video_path,
                ])
                .output()
                .await
                .map_err(|e| format!("failed to run ffprobe: {e}"))?;
            if !output.status.success() {
                return Err(format!(
                    "ffprobe failed, status: {}. stderr: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                tracing::debug!(select, "ffprobe: {line}");
            }
            let mut info = StreamInfo::default();
            for line in output_str.lines() {
                if let Some((key, value)) = line.trim().split_once('=') {
                    match key {
                        "codec_name" => info.codec_name = Some(value.to_string()),
                        "pix_fmt" => info.pix_fmt = Some(value.to_string()),
                        "profile" => info.profile = Some(value.to_string()),
                        "level" => info.level = value.parse::<i32>().ok(),
                        _ => {}
                    }
                }
            }
            if info.codec_name.is_some() {
                Ok(Some(info))
            } else {
                Ok(None)
            }
        }

        #[derive(Debug, Default)]
        struct StreamInfo {
            codec_name: Option<String>,
            pix_fmt: Option<String>,
            profile: Option<String>,
            level: Option<i32>,
        }

        // Ensure the file extension is mp4
        let is_mp4 = match video_path.extension().and_then(|e| e.to_str()) {
            Some(ext) => ext.eq_ignore_ascii_case("mp4"),
            None => false,
        };

        let video_stream = probe_stream(&video_path_str, "v:0").await?;
        let audio_stream = probe_stream(&video_path_str, "a:0").await?;

        let video_ok = video_stream.as_ref().is_some_and(|v| {
            v.codec_name.as_deref() == Some("h264")
                && v.pix_fmt.as_deref() == Some("yuv420p")
                && matches!(
                    v.profile.as_deref(),
                    Some("Baseline") | Some("Constrained Baseline") | Some("Main") | Some("High")
                )
                && v.level.unwrap_or(0) <= 42
        });
        let audio_ok = match &audio_stream {
            None => true, // silent video is fine
            Some(a) => matches!(a.codec_name.as_deref(), Some("aac") | Some("mp3")),
        };

        let compatible = video_ok && audio_ok && is_mp4;

        if compatible {
            tracing::info!(video_path = ?video_path, "Video is compatible for web playback");
        } else {
            tracing::info!(
                video_path = ?video_path,
                video_ok,
                audio_ok,
                is_mp4,
                video_stream = ?video_stream,
                audio_stream = ?audio_stream,
                "Video is not compatible for web playback",
            );
        }
        Ok(compatible)
    }

    /// Generates a browser-compatible video variant for playback.
    pub async fn generate_compatibility_video(
        video_path: &Path,
    ) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
        tracing::debug!(video_path = ?video_path, "Generating compatibility video");
        let video_path_str = video_path
            .to_str()
            .ok_or("failed to convert video_path to string")?
            .to_string();
        let compatibility_path = Self::alternate_path(video_path, "cm_", ".mp4");
        let compatibility_path_str = compatibility_path
            .to_str()
            .ok_or("failed to convert compatibility path to string")?
            .to_string();

        // Run ffmpeg to convert the video
        let ffmpeg_output = tokio::process::Command::new("ffmpeg")
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
            .await
            .map_err(|e| format!("failed to execute ffmpeg: {e}"))?;

        if !ffmpeg_output.status.success() {
            return Err(format!("ffmpeg failed, status: {}", ffmpeg_output.status).into());
        }

        if !compatibility_path.exists() {
            return Err("compatibility video was not created successfully".into());
        }

        tracing::info!(
            compatibility_path = ?compatibility_path,
            "Compatibility video generated successfully"
        );
        Ok(compatibility_path)
    }

    /// Generates a poster image (still frame) from a video file.
    pub async fn generate_video_poster(
        video_path: &Path,
    ) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
        tracing::debug!(video_path = ?video_path, "Generating video poster");
        let poster_path = video_path.with_extension("webp");

        let video_path_str = video_path
            .to_str()
            .ok_or("failed to convert video_path to string")?
            .to_string();
        let poster_path_str = poster_path
            .to_str()
            .ok_or("failed to convert poster_path to string")?
            .to_string();

        // Generate the poster image using ffmpeg
        let ffmpeg_output = tokio::process::Command::new("ffmpeg")
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
            .await
            .map_err(|e| format!("failed to complete ffmpeg: {e}"))?;

        if !ffmpeg_output.status.success() {
            return Err(format!("ffmpeg failed, status: {}", ffmpeg_output.status).into());
        }

        if !poster_path.exists() {
            return Err("poster image was not created successfully".into());
        }

        tracing::info!(
            poster_path = ?poster_path,
            "Video poster generated successfully"
        );
        Ok(poster_path)
    }

    // =========================
    // Background Media Tasks
    // =========================

    /// Background task for publishing media and updating post status.
    pub async fn publish_media_task(state: AppState, post: Post, post_review: PostReview) {
        let result: Result<(), Box<dyn Error + Send + Sync>> = async {
            let mut tx = begin_transaction(&state.db).await?;

            // Attempt media publication
            PostReview::publish_media(&mut tx, &post).await?;

            // Update post status
            let post = post.update_status(&mut tx, post_review.status).await?;

            commit_transaction(tx).await?;

            // Clean up and notify clients
            let encrypted_media_path = post.encrypted_media_path();
            PostReview::delete_upload_key_dir(&encrypted_media_path)
                .await
                .map_err(|e| format!("failed to delete upload directory: {e}"))?;
            send_to_websocket(&state.sender, post);
            Ok(())
        }
        .await;

        if let Err(e) = result {
            tracing::error!("Error in publish_media_task: {e}");
        }
    }

    /// Background task for re-encrypting media and updating post status.
    pub async fn reencrypt_media_task(state: AppState, post: Post, post_review: PostReview) {
        let result: Result<(), Box<dyn Error + Send + Sync>> = async {
            let mut tx = begin_transaction(&state.db).await?;

            // Attempt media re-encryption
            post.reencrypt_media_file()
                .await
                .map_err(|e| format!("failed to re-encrypt media: {e}"))?;

            // Update post status
            let post = post.update_status(&mut tx, post_review.status).await?;

            commit_transaction(tx).await?;

            // Notify clients
            send_to_websocket(&state.sender, post);
            Ok(())
        }
        .await;

        if let Err(e) = result {
            tracing::error!("Error in reencrypt_media_task: {e}");
        }
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
