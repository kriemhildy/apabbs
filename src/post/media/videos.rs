//! Video media processing helpers for posts.
//!
//! Handles video compatibility checks, transcoding, poster generation, and related utilities for video files.

use super::{super::Post, MAX_THUMB_HEIGHT, MAX_THUMB_WIDTH, images};
use sqlx::PgConnection;
use std::{
    error::Error,
    path::{Path, PathBuf},
};

/// Processes video media for a post.
pub async fn process_video(
    tx: &mut PgConnection,
    post: &Post,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let published_media_path = post.published_media_path();
    if !video_is_compatible(&published_media_path).await? {
        let compat_video_path = generate_compatibility_video(&published_media_path).await?;
        post.update_compat_video(tx, &compat_video_path).await?
    }

    let video_poster_path = generate_video_poster(&published_media_path).await?;
    post.update_poster(tx, &video_poster_path).await?;

    let (media_width, media_height) = images::image_dimensions(&video_poster_path).await?;
    post.update_media_dimensions(tx, media_width, media_height)
        .await?;

    if media_width > MAX_THUMB_WIDTH || media_height > MAX_THUMB_HEIGHT {
        let thumbnail_path = images::generate_image_thumbnail(&video_poster_path).await?;
        let (thumb_width, thumb_height) = images::image_dimensions(&thumbnail_path).await?;
        post.update_thumbnail(tx, &thumbnail_path, thumb_width, thumb_height)
            .await?;
    }
    Ok(())
}

/// Represents information about a video stream extracted by ffprobe.
#[derive(Debug, Default)]
pub struct StreamInfo {
    /// The codec name of the stream.
    codec_name: Option<String>,
    /// The pixel format of the stream.
    pix_fmt: Option<String>,
    /// The profile of the stream.
    profile: Option<String>,
    /// The level of the stream.
    level: Option<i32>,
}

/// Probes a video stream using ffprobe and returns its information.
pub async fn probe_stream(
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
        .map_err(|e| format!("execute ffprobe: {e}"))?;
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

/// Returns true if the video is compatible for web playback.
pub async fn video_is_compatible(video_path: &Path) -> Result<bool, Box<dyn Error + Send + Sync>> {
    tracing::debug!(video_path = ?video_path, "Checking video compatibility");
    let video_path_str = video_path.to_str().unwrap().to_string();
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
    let video_path_str = video_path.to_str().unwrap();
    let compat_video_path = super::alternate_path(video_path, "cm_", ".mp4");
    let compat_video_path_str = compat_video_path.to_str().unwrap();
    let ffmpeg_output = tokio::process::Command::new("ffmpeg")
        .args([
            "-nostdin", // No stdin interaction
            "-i",
            video_path_str, // Input file
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
            "128k",                // Audio bitrate
            compat_video_path_str, // Output file
        ])
        .output()
        .await
        .map_err(|e| format!("execute ffmpeg: {e}"))?;
    if !ffmpeg_output.status.success() {
        return Err(format!(
            "ffmpeg failed, status: {}. stderr: {}",
            ffmpeg_output.status,
            String::from_utf8_lossy(&ffmpeg_output.stderr)
        )
        .into());
    }
    if !compat_video_path.exists() {
        return Err("compatibility video was not created successfully".into());
    }
    tracing::info!(
        compat_video_path = ?compat_video_path,
        "Compatibility video generated successfully"
    );
    Ok(compat_video_path)
}

/// Generates a poster image (still frame) from a video file.
pub async fn generate_video_poster(
    video_path: &Path,
) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
    tracing::debug!(video_path = ?video_path, "Generating video poster");
    let video_path_str = video_path.to_str().unwrap();
    let poster_path = video_path.with_extension("jpg");
    let poster_path_str = poster_path.to_str().unwrap();
    let ffmpeg_output = tokio::process::Command::new("ffmpeg")
        .args([
            "-nostdin", // No stdin interaction
            "-i",
            video_path_str, // Input file
            "-ss",
            "0", // Seek to start
            "-vframes",
            "1", // Extract a single video frame
            "-c:v",
            "mjpeg", // JPEG format
            "-q:v",
            "80",            // Quality
            poster_path_str, // Output file
        ])
        .output()
        .await
        .map_err(|e| format!("execute ffmpeg: {e}"))?;
    if !ffmpeg_output.status.success() {
        return Err(format!(
            "ffmpeg failed, status: {}. stderr: {}",
            ffmpeg_output.status,
            String::from_utf8_lossy(&ffmpeg_output.stderr)
        )
        .into());
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
