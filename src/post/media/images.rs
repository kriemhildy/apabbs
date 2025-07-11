//! Image media processing helpers for posts.
//!
//! Handles thumbnail generation, image dimension extraction, and related utilities for image files.

use super::{super::Post, MAX_THUMB_HEIGHT, MAX_THUMB_WIDTH};
use sqlx::PgConnection;
use std::{
    error::Error,
    path::{Path, PathBuf},
};

/// Generates a thumbnail image for a given media file.
pub async fn generate_image_thumbnail(
    published_media_path: &Path,
) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
    let media_path_str = published_media_path.to_str().unwrap();
    let extension = media_path_str.split('.').next_back().unwrap();
    let vips_input_file_path = media_path_str.to_string()
        + match extension.to_lowercase().as_str() {
            "gif" | "webp" => "[n=-1]",
            _ => "",
        };
    let command_output = tokio::process::Command::new("vipsthumbnail")
        .args([
            &format!("--size={MAX_THUMB_WIDTH}x{MAX_THUMB_HEIGHT}>"),
            "--output=tn_%s.webp",
        ])
        .arg(&vips_input_file_path)
        .output()
        .await
        .map_err(|e| format!("execute vipsthumbnail: {e}"))?;
    if !command_output.status.success() {
        return Err(format!("vipsthumbnail failed, status: {}", command_output.status).into());
    }
    let thumb_path = super::alternate_path(published_media_path, "tn_", ".webp");
    if !thumb_path.exists() {
        return Err("thumbnail path does not exist".into());
    }
    Ok(thumb_path)
}

/// Returns true if the thumbnail file is larger than the original media file.
pub fn thumbnail_is_larger(
    thumbnail_path: &Path,
    published_media_path: &Path,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let thumbnail_len = thumbnail_path.metadata().unwrap().len();
    let media_file_len = published_media_path.metadata().unwrap().len();
    Ok(thumbnail_len > media_file_len)
}

/// Processes image media for a post.
pub async fn process_image(
    tx: &mut PgConnection,
    post: &Post,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let published_media_path = post.published_media_path();
    let thumbnail_path = generate_image_thumbnail(&published_media_path).await?;
    if thumbnail_is_larger(&thumbnail_path, &published_media_path)? {
        tokio::fs::remove_file(&thumbnail_path).await?;
    } else {
        let (width, height) = image_dimensions(&thumbnail_path).await?;
        post.update_thumbnail(tx, &thumbnail_path, width, height)
            .await?;
    }
    let (width, height) = image_dimensions(&published_media_path).await?;
    post.update_media_dimensions(tx, width, height).await?;
    Ok(())
}

/// Returns the dimensions (width, height) of an image using vipsheader.
pub async fn image_dimensions(
    image_path: &Path,
) -> Result<(i32, i32), Box<dyn Error + Send + Sync>> {
    async fn vipsheader(
        field: &str,
        image_path_str: &str,
    ) -> Result<i32, Box<dyn Error + Send + Sync>> {
        let output = tokio::process::Command::new("vipsheader")
            .args(["-f", field, image_path_str])
            .output()
            .await
            .map_err(|e| format!("execute vipsheader: {e}"))?;
        let value = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<i32>()
            .map_err(|e| format!("parse vipsheader output as i32: {e}"))?;
        Ok(value)
    }
    tracing::debug!(image_path = ?image_path, "Getting image dimensions");
    let image_path_str = image_path.to_str().unwrap();
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
