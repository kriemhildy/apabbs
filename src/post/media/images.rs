//! Image media processing helpers for posts.
//!
//! Handles thumbnail generation, image dimension extraction, and related utilities for image files.
//!
//! Functions provided in this module:
//! - PostReview::generate_image_thumbnail
//! - PostReview::thumbnail_is_larger
//! - PostReview::process_image
//! - PostReview::image_dimensions

use super::{
    super::{Post, review::PostReview},
    MAX_THUMB_HEIGHT, MAX_THUMB_WIDTH,
};
use sqlx::PgConnection;
use std::{
    error::Error,
    path::{Path, PathBuf},
};

impl PostReview {
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
}
