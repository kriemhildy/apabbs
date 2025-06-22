use super::MAX_THUMB_HEIGHT;
use super::MAX_THUMB_WIDTH;
use super::MEDIA_DIR;
use super::MediaCategory;
use super::Post;
use super::PostStatus;
use crate::user::AccountRole;
use regex::Regex;
use sqlx::PgConnection;
use std::path::PathBuf;
use uuid::Uuid;

/// Error messages
const ERR_THUMBNAIL_FAILED: &str = "Thumbnail not created successfully";

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
