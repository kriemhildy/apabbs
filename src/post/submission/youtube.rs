//! YouTube video embedding helpers.

use regex::Regex;
use std::{error::Error, path::PathBuf};
use url::Url;

/// Directory path for caching downloaded YouTube thumbnails for posts.
pub const YOUTUBE_DIR: &str = "pub/youtube";

/// Maximum number of YouTube video embeds allowed per post.
pub const MAX_YOUTUBE_EMBEDS: usize = 10;

/// Embeds YouTube video thumbnails in the post HTML, replacing links with embed markup.
pub async fn embed_youtube(
    mut html: String,
    key: &str,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    // If this changes, will need to update the regex as well
    const STANDARD_PATH: &str = "watch?v=";
    const SHORTS_PATH: &str = "shorts/";
    const LINK_PATTERN: &str = concat!(
        r#"(?m)^ *<a href=""#,
        r#"(https?://(?:youtu\.be/|(?:www\.|m\.)?youtube\.com/"#,
        r#"(watch\S*(?:\?|&amp;)v=|shorts/))"#,
        r#"([^&\s\?]+)\S*)" rel="noopener" target="_blank">\S+</a> *(?:<br>)?$"#,
    );
    let link_regex = Regex::new(LINK_PATTERN).expect("build regex");
    for _ in 0..MAX_YOUTUBE_EMBEDS {
        let captures = match link_regex.captures(&html) {
            None => break,
            Some(captures) => captures,
        };
        // youtu.be has no match for 2, but is always not a short
        let short = captures.get(2).is_some_and(|m| m.as_str() == SHORTS_PATH);
        let video_id = &captures[3];
        tracing::debug!("Regex captures: {:?}", captures);
        let timestamp = if short {
            None
        } else {
            let url_str = &captures[1].replace("&amp;", "&");
            let parsed_url = Url::parse(url_str)?;
            parsed_url
                .query_pairs()
                .find(|(k, _)| k == "t")
                .map(|(_, v)| v.to_string())
        };
        tracing::debug!(video_id, timestamp, "Parsed YouTube URL");
        let thumbnail_tuple = download_youtube_thumbnail(video_id, short).await?;
        let (local_thumbnail_url, width, height) = match thumbnail_tuple {
            None => break,
            Some((path, width, height)) => (
                path.to_str()
                    .ok_or("convert thumbnail path to string")?
                    .strip_prefix("pub")
                    .ok_or("strip 'pub' prefix from thumbnail path")?
                    .to_string(),
                width,
                height,
            ),
        };
        let url_path = if short { SHORTS_PATH } else { STANDARD_PATH };
        let thumbnail_link = format!(
            concat!(
                "<div class=\"youtube\">\n",
                "    <div class=\"youtube-logo\">\n",
                "        <a href=\"https://www.youtube.com/{url_path}{video_id}{timestamp}\" ",
                "rel=\"noopener\" target=\"_blank\">",
                "<img src=\"/youtube.svg\" alt=\"YouTube {video_id}\" ",
                "width=\"20\" height=\"20\" loading=\"lazy\">",
                "</a>\n",
                "    </div>\n",
                "    <div class=\"youtube-thumbnail\">\n",
                "        <a href=\"/p/{key}\">",
                "<img src=\"{thumbnail_url}\" alt=\"Post {key}\" ",
                "width=\"{width}\" height=\"{height}\" loading=\"lazy\">",
                "</a>\n",
                "    </div>\n",
                "</div>",
            ),
            url_path = url_path,
            video_id = video_id,
            thumbnail_url = local_thumbnail_url,
            key = key,
            timestamp = timestamp.map(|t| format!("&amp;t={t}")).unwrap_or_default(),
            width = width,
            height = height,
        );
        html = link_regex.replace(&html, thumbnail_link).to_string();
    }
    Ok(html)
}

/// Downloads a YouTube thumbnail for the given video ID, returning its path and dimensions if successful.
pub async fn download_youtube_thumbnail(
    video_id: &str,
    short: bool,
) -> Result<Option<(PathBuf, i32, i32)>, Box<dyn Error + Send + Sync>> {
    tracing::debug!(video_id, "Downloading YouTube thumbnail...");
    let video_id_dir = std::path::Path::new(YOUTUBE_DIR).join(video_id);

    // Compact array of size tuples (name, width, height)
    const THUMBNAIL_SIZES: &[(&str, i32, i32)] = &[
        ("maxresdefault", 1280, 720),
        ("sddefault", 640, 480),
        ("hqdefault", 480, 360),
        ("mqdefault", 320, 180),
        ("default", 120, 90),
        ("oar2", 1080, 1920),
    ];

    if video_id_dir.exists() {
        if let Some(first_entry) = video_id_dir.read_dir()?.next() {
            let existing_thumbnail_path = first_entry?.path();
            let size = existing_thumbnail_path
                .file_name()
                .ok_or("filename does not exist")?
                .to_str()
                .ok_or("filename is not valid utf-8")?
                .split('.')
                .next()
                .ok_or("filename does not have a basename")?;
            let (width, height) = THUMBNAIL_SIZES
                .iter()
                .find(|s| s.0 == size)
                .map(|s| (s.1, s.2))
                .unwrap();
            return Ok(Some((existing_thumbnail_path, width, height)));
        }
    } else {
        tokio::fs::create_dir(&video_id_dir).await?;
    }

    for size in THUMBNAIL_SIZES.iter().filter(|s| (s.2 > s.1) == short) {
        let name = size.0;
        let local_thumbnail_path = video_id_dir.join(format!("{name}.jpg"));
        let remote_thumbnail_url = format!("https://img.youtube.com/vi/{video_id}/{name}.jpg");
        let curl_status = tokio::process::Command::new("curl")
            .args(["--silent", "--fail", "--output"])
            .arg(&local_thumbnail_path)
            .arg(&remote_thumbnail_url)
            .status()
            .await
            .map_err(|e| format!("execute curl: {e}"))?;
        if curl_status.success() {
            let (width, height) = (size.1, size.2);
            return Ok(Some((local_thumbnail_path, width, height)));
        }
    }

    Ok(None)
}
