//! Media file management and processing for posts.
//!
//! Handles encryption, decryption, thumbnail and poster generation, compatibility conversion,
//! and file system operations for post media. Provides helpers for MIME type detection,
//! path construction, and media processing workflows. All error messages and panics are
//! descriptive and actionable for maintainability.

use super::submission::PostSubmission;
use super::{MediaCategory, Post, PostReview};
use regex::Regex;
use sqlx::PgConnection;
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

/// Error message used when thumbnail generation fails.
pub const ERR_THUMBNAIL_FAILED: &str = "Thumbnail was not created successfully";

impl Post {
    /// Returns the path where an encrypted media file is stored.
    ///
    /// # Panics
    /// Panics if the post has no associated media file.
    pub fn encrypted_media_path(&self) -> PathBuf {
        if self.media_filename.is_none() {
            panic!("Cannot get encrypted_media_path: post has no media file");
        }
        let encrypted_filename = format!("{}.gpg", self.media_filename.as_ref().unwrap());
        std::path::Path::new(UPLOADS_DIR)
            .join(&self.key)
            .join(encrypted_filename)
    }

    /// Returns the path where published media is stored after processing.
    ///
    /// # Panics
    /// Panics if the post has no associated media file.
    pub fn published_media_path(&self) -> PathBuf {
        if self.media_filename.is_none() {
            panic!("Cannot get published_media_path: post has no media file");
        }
        std::path::Path::new(MEDIA_DIR)
            .join(&self.key)
            .join(self.media_filename.as_ref().unwrap())
    }

    /// Returns the path where a thumbnail is stored after processing.
    ///
    /// # Panics
    /// Panics if the post has no associated thumbnail.
    pub fn thumbnail_path(&self) -> PathBuf {
        if self.thumb_filename.is_none() {
            panic!("Cannot get thumbnail_path: post has no thumbnail");
        }
        std::path::Path::new(MEDIA_DIR)
            .join(&self.key)
            .join(self.thumb_filename.as_ref().unwrap())
    }

    /// Encrypts the provided bytes using GPG with the application's key.
    ///
    /// Creates necessary directories, runs GPG to encrypt data, and handles cleanup on error.
    ///
    /// # Returns
    /// - Ok(()) if encryption succeeded
    /// - Err with a message if encryption failed
    pub async fn gpg_encrypt(&self, bytes: Vec<u8>) -> Result<(), &str> {
        let encrypted_media_path = self.encrypted_media_path();
        let encrypted_media_path_str = encrypted_media_path
            .to_str()
            .expect("converts path")
            .to_owned();
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
                .expect("spawns gpg");
            if let Some(mut stdin) = child.stdin.take() {
                std::io::Write::write_all(&mut stdin, &bytes).expect("writes to gpg");
            }
            let child_status = child.wait().expect("waits for gpg process");
            child_status.success()
        })
        .await
        .expect("completes gpg encryption");
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

    /// Re-encrypts a media file that has already been published.
    ///
    /// Used when media needs to be moved back from published to reported state.
    pub async fn reencrypt_media_file(&self) -> Result<(), &str> {
        let encrypted_file_path = self.encrypted_media_path();
        let uploads_key_dir = encrypted_file_path.parent().expect("has parent");
        tokio::fs::create_dir(uploads_key_dir)
            .await
            .expect("creates uploads key dir");
        let media_file_path = self.published_media_path();
        let media_bytes = tokio::fs::read(&media_file_path)
            .await
            .expect("reads published media");
        let result = self.gpg_encrypt(media_bytes).await;
        match result {
            Ok(()) => PostReview::delete_media_key_dir(&self.key).await,
            Err(msg) => {
                tokio::fs::remove_dir(uploads_key_dir)
                    .await
                    .expect("removes uploads key dir");
                eprintln!("Re-encryption failed: {}", msg);
            }
        }
        result
    }

    /// Decrypts the post's media file using GPG.
    ///
    /// Returns the decrypted file content as bytes. This operation is CPU-intensive and runs in a separate thread.
    pub async fn decrypt_media_file(&self) -> Vec<u8> {
        if self.media_filename.is_none() {
            panic!("Cannot decrypt media: post has no media file");
        }
        let encrypted_file_path = self
            .encrypted_media_path()
            .to_str()
            .expect("converts path")
            .to_owned();
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new("gpg")
                .args(["--batch", "--decrypt", "--passphrase-file", "gpg.key"])
                .arg(&encrypted_file_path)
                .output()
                .expect("decrypts")
        })
        .await
        .expect("completes gpg decryption");
        println!("Media file decrypted successfully");
        output.stdout
    }
}

impl PostSubmission {
    /// Determines the media type (category and MIME type) based on the file extension
    ///
    /// # Examples
    ///
    /// ```
    /// use apabbs::post::{PostSubmission, MediaCategory};
    /// let (cat, mime) = PostSubmission::determine_media_type(Some("foo.jpg"));
    /// assert_eq!(cat, Some(MediaCategory::Image));
    /// assert_eq!(mime, Some("image/jpeg".to_owned()));
    ///
    /// let (cat, mime) = PostSubmission::determine_media_type(Some("foo.mp3"));
    /// assert_eq!(cat, Some(MediaCategory::Audio));
    /// assert_eq!(mime, Some("audio/mpeg".to_owned()));
    ///
    /// let (cat, mime) = PostSubmission::determine_media_type(Some("foo.unknown"));
    /// assert_eq!(cat, None);
    /// assert_eq!(mime, Some("application/octet-stream".to_owned()));
    /// ```
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
            .expect("creates uploads key dir");
        let result = post.gpg_encrypt(self.media_bytes.unwrap()).await;
        if result.is_err() {
            tokio::fs::remove_dir(uploads_key_dir)
                .await
                .expect("removes uploads key dir");
        }
        result
    }
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
    pub async fn write_media_file(published_media_path: &Path, media_bytes: Vec<u8>) {
        let media_key_dir = published_media_path.parent().unwrap();
        tokio::fs::create_dir(media_key_dir)
            .await
            .expect("creates media key dir");
        tokio::fs::write(&published_media_path, media_bytes)
            .await
            .expect("writes media file");
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
    pub async fn generate_image_thumbnail(published_media_path: &Path) -> PathBuf {
        let media_path_str = published_media_path.to_str().unwrap();
        let extension = media_path_str
            .split('.')
            .next_back()
            .expect("gets file extension");

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
                .expect("generates thumbnail");

            println!("vipsthumbnail output: {:?}", command_output);
        })
        .await
        .expect("completes vipsthumbnail");

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
    pub fn thumbnail_is_larger(thumbnail_path: &Path, published_media_path: &Path) -> bool {
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
    pub async fn delete_upload_key_dir(encrypted_media_path: &Path) {
        let uploads_key_dir = encrypted_media_path.parent().unwrap();

        tokio::fs::remove_file(&encrypted_media_path)
            .await
            .expect("removes encrypted media");

        tokio::fs::remove_dir(&uploads_key_dir)
            .await
            .expect("removes uploads key dir");
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
            .expect("removes media key dir and its contents");
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
                .expect("removes thumbnail file");
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
    pub async fn image_dimensions(image_path: &Path) -> (i32, i32) {
        println!("Getting image dimensions for: {:?}", image_path);
        let image_path_str = image_path.to_str().unwrap();

        // Helper function to extract specific field from vipsheader
        let vipsheader = async |field: &str| -> i32 {
            let output = tokio::process::Command::new("vipsheader")
                .args(["-f", field, image_path_str])
                .output()
                .await
                .expect("gets image dimension");

            String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse()
                .expect("parses i32")
        };

        // Get both dimensions in parallel
        let (width, height) = tokio::join!(vipsheader("width"), vipsheader("height"));
        println!(
            "Image dimensions for {:?}: {}x{}",
            image_path, width, height
        );
        (width, height)
    }

    /// Determines if a video is compatible for web playback using ffprobe.
    ///
    /// Checks for H.264 video codec, AAC audio codec, 8-bit YUV 4:2:0 pixel format, and MP4 container.
    ///
    /// # Parameters
    /// - `video_path`: Path to the video file
    ///
    /// # Returns
    /// `true` if the video is compatible, `false` if it needs conversion
    pub async fn video_is_compatible(video_path: &Path) -> bool {
        println!("Checking video compatibility for: {:?}", video_path);
        let video_path_str = video_path.to_str().expect("converts path").to_owned();

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
            .expect("runs ffprobe");

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
        let is_compatible = codec == "h264"
            && pix_fmt == "yuv420p"
            && ["Baseline", "Constrained Baseline", "Main", "High"].contains(&profile)
            && level.parse::<i32>().unwrap_or(0) <= 42;

        if is_compatible {
            println!("Video is compatible for web playback: {}", video_path_str);
            true
        } else {
            println!(
                "Video is not compatible for web playback: {}",
                video_path_str
            );
            false
        }
    }

    /// Generates a browser-compatible video variant for playback.
    ///
    /// Converts the input video to an H.264/AVC MP4 file with AAC audio, suitable for maximum browser compatibility.
    /// The output is intended as a fallback for browsers that do not support the original video format. The
    /// generated file is saved alongside the original with a "cm_" prefix and ".mp4" extension.
    ///
    /// # Parameters
    /// - `video_path`: Path to the original video file
    ///
    /// # Returns
    /// Path to the generated compatibility video file (MP4)
    pub async fn generate_compatibility_video(video_path: &Path) -> PathBuf {
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
                .expect("generates video thumbnail");

            println!("ffmpeg output: {:?}", ffmpeg_output);
        })
        .await
        .expect("completes ffmpeg");

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
    pub async fn generate_video_poster(video_path: &Path) -> PathBuf {
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
                .expect("generates video poster");

            println!("ffmpeg output: {:?}", ffmpeg_output);
        })
        .await
        .expect("completes poster");

        println!("Video poster generated at: {:?}", poster_path);
        poster_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests MIME type and media category detection for different file extensions
    #[tokio::test]
    async fn media_type_detection() {
        // Test image file types
        let (category, mime) = PostSubmission::determine_media_type(Some("test.jpg"));
        assert_eq!(category, Some(MediaCategory::Image));
        assert_eq!(mime, Some("image/jpeg".to_owned()));

        // Test video file types
        let (category, mime) = PostSubmission::determine_media_type(Some("video.mp4"));
        assert_eq!(category, Some(MediaCategory::Video));
        assert_eq!(mime, Some("video/mp4".to_owned()));

        // Test audio file types
        let (category, mime) = PostSubmission::determine_media_type(Some("audio.mp3"));
        assert_eq!(category, Some(MediaCategory::Audio));
        assert_eq!(mime, Some("audio/mpeg".to_owned()));

        // Test unknown file type
        let (category, mime) = PostSubmission::determine_media_type(Some("document.pdf"));
        assert_eq!(category, None);
        assert_eq!(mime, Some(APPLICATION_OCTET_STREAM.to_owned()));

        // Test no file
        let (category, mime) = PostSubmission::determine_media_type(None);
        assert_eq!(category, None);
        assert_eq!(mime, None);
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
