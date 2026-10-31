//! X post media embedding helpers.

use serde_json::Value;
use std::{collections::HashSet, error::Error, path::PathBuf};
use url::Url;
use uuid::Uuid;

/// Directory path for caching downloaded X post media.
pub const X_DIR: &str = "pub/x";

const MAX_X_EMBEDS: usize = 10;

enum XMedia {
    Image { url: Url, extension: String },
    Video { url: Url },
}

/// Replaces standalone X post links with locally cached media and a link to the original post.
pub async fn embed_x(mut html: String) -> Result<String, Box<dyn Error + Send + Sync>> {
    let link_regex = regex::Regex::new(concat!(
        r#"(?m)^ *<a href="(https?://(?:(?:www|mobile)\.)?(?:x|twitter)\.com/[^"]+)" "#,
        r#"rel="noopener" target="_blank">[^<]*</a> *(?:<br>)?$"#
    ))
    .expect("build regex");

    let mut attempted = HashSet::new();
    for _ in 0..MAX_X_EMBEDS {
        let target = match link_regex.captures_iter(&html).find_map(|captures| {
            let href = captures.get(1)?.as_str();
            let (post_url, post_id) = parse_post_url(href)?;
            if attempted.contains(&post_id) {
                return None;
            }
            Some((captures.get(0)?.as_str().to_string(), post_url, post_id))
        }) {
            Some(target) => target,
            None => break,
        };
        let (matched, post_url, post_id) = target;
        attempted.insert(post_id.clone());
        let Some(media) = fetch_x_media(&post_id).await? else {
            tracing::debug!(post_id, "X post has no downloadable media");
            continue;
        };
        let Some(media_markup) = cache_and_render_media(&post_id, media).await? else {
            continue;
        };
        let embed_markup = format!(
            concat!(
                "<a class=\"x-link\" href=\"{post_url}\" rel=\"noopener\" ",
                "target=\"_blank\"><img class=\"x-logo\" src=\"/x.svg\" ",
                "alt=\"View post on X\" width=\"20\" height=\"20\"></a>\n",
                "{media_markup}"
            ),
            post_url = post_url,
            media_markup = media_markup,
        );
        html = html.replacen(&matched, &embed_markup, 1);
    }

    Ok(html)
}

fn parse_post_url(value: &str) -> Option<(String, String)> {
    let url = Url::parse(value).ok()?;
    let host = url.host_str()?.to_ascii_lowercase();
    if !matches!(
        host.as_str(),
        "x.com"
            | "www.x.com"
            | "twitter.com"
            | "www.twitter.com"
            | "mobile.x.com"
            | "mobile.twitter.com"
    ) {
        return None;
    }

    let segments: Vec<_> = url.path_segments()?.collect();
    let status_index = segments.iter().position(|segment| *segment == "status")?;
    let post_id = *segments.get(status_index + 1)?;
    if post_id.is_empty()
        || post_id.len() > 20
        || !post_id.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }

    let post_path = segments[..=status_index + 1].join("/");
    Some((format!("https://x.com/{post_path}"), post_id.to_string()))
}

async fn fetch_x_media(post_id: &str) -> Result<Option<XMedia>, Box<dyn Error + Send + Sync>> {
    let mut endpoint = Url::parse("https://cdn.syndication.twimg.com/tweet-result")?;
    endpoint
        .query_pairs_mut()
        .append_pair("id", post_id)
        .append_pair("lang", "en")
        // The endpoint returns an empty object without a token, but does not validate its value
        .append_pair("token", "1");
    let output = tokio::process::Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "15",
            "--fail",
        ])
        .arg(endpoint.as_str())
        .output()
        .await
        .map_err(|error| format!("execute curl for X post media: {error}"))?;
    if !output.status.success() {
        tracing::warn!(post_id, status = %output.status, "X syndication request failed");
        return Ok(None);
    }
    let response: Value = match serde_json::from_slice(&output.stdout) {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(post_id, %error, "Could not parse X syndication response");
            return Ok(None);
        }
    };
    let media = extract_media(&response);
    if media.is_none() {
        tracing::warn!(post_id, "No usable media in X syndication response");
    }
    Ok(media)
}

fn extract_media(response: &Value) -> Option<XMedia> {
    if let Some(media) = response.get("mediaDetails").and_then(Value::as_array) {
        for item in media {
            match item.get("type").and_then(Value::as_str) {
                Some("photo") => {
                    if let Some(url) = item
                        .get("media_url_https")
                        .and_then(Value::as_str)
                        .and_then(parse_image_url)
                    {
                        return Some(url);
                    }
                }
                Some("video" | "animated_gif") => {
                    if let Some(url) = item.get("video_info").and_then(parse_video_variants) {
                        return Some(url);
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(photo) = response
        .get("photos")
        .and_then(Value::as_array)
        .and_then(|photos| photos.first())
        .and_then(|photo| photo.get("url"))
        .and_then(Value::as_str)
        .and_then(parse_image_url)
    {
        return Some(photo);
    }

    response.get("video").and_then(parse_video_variants)
}

fn parse_image_url(value: &str) -> Option<XMedia> {
    let url = Url::parse(value).ok()?;
    if url.scheme() != "https" || url.host_str()? != "pbs.twimg.com" {
        return None;
    }
    let extension = url
        .path_segments()?
        .next_back()?
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .or_else(|| {
            url.query_pairs()
                .find(|(key, _)| key == "format")
                .map(|(_, value)| value.to_ascii_lowercase())
        })?;
    if !matches!(extension.as_str(), "jpg" | "jpeg" | "png" | "webp" | "gif") {
        return None;
    }
    Some(XMedia::Image { url, extension })
}

fn parse_video_variants(info: &Value) -> Option<XMedia> {
    let variants = info.get("variants")?.as_array()?;
    let url = variants
        .iter()
        .filter(|variant| variant.get("content_type").and_then(Value::as_str) == Some("video/mp4"))
        .filter_map(|variant| {
            let bitrate = variant.get("bitrate").and_then(Value::as_u64).unwrap_or(0);
            let url = variant.get("url").and_then(Value::as_str)?;
            let url = Url::parse(url).ok()?;
            if url.scheme() != "https" || url.host_str()? != "video.twimg.com" {
                return None;
            }
            Some((bitrate, url))
        })
        .max_by_key(|(bitrate, _)| *bitrate)?
        .1;
    Some(XMedia::Video { url })
}

async fn cache_and_render_media(
    post_id: &str,
    media: XMedia,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    let directory = PathBuf::from(X_DIR).join(post_id);
    tokio::fs::create_dir_all(&directory)
        .await
        .map_err(|error| format!("create X media directory: {error}"))?;

    let local_name = match &media {
        XMedia::Image { extension, .. } => format!("media.{extension}"),
        XMedia::Video { .. } => "video.mp4".to_string(),
    };
    let local_path = directory.join(&local_name);
    if !tokio::fs::try_exists(&local_path)
        .await
        .map_err(|error| format!("check cached X media: {error}"))?
    {
        let temporary_path = directory.join(format!("{local_name}.part-{}", Uuid::new_v4()));
        let status = tokio::process::Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--max-time",
                "30",
                "--max-filesize",
                "52428800",
                "--fail",
                "--write-out",
                "%{http_code}",
                "--output",
            ])
            .arg(&temporary_path)
            .arg(match &media {
                XMedia::Image { url, .. } | XMedia::Video { url } => url.as_str(),
            })
            .output()
            .await
            .map_err(|error| format!("execute curl to download X media: {error}"))?;
        let response_status = String::from_utf8_lossy(&status.stdout);
        if !status.status.success() || !response_status.starts_with("2") {
            tokio::fs::remove_file(&temporary_path)
                .await
                .map_err(|error| format!("remove incomplete X media download: {error}"))?;
            tracing::warn!(
                post_id,
                curl_status = %status.status,
                http_status = %response_status,
                "Could not download X media; keeping the original post link"
            );
            return Ok(None);
        }
        tokio::fs::rename(&temporary_path, &local_path)
            .await
            .map_err(|error| format!("cache downloaded X media: {error}"))?;
    }

    let media_url = format!("/x/{post_id}/{local_name}");
    Ok(Some(match media {
        XMedia::Image { .. } => format!(
            "<img class=\"x-media\" src=\"{media_url}\" alt=\"X post media\" loading=\"lazy\">"
        ),
        XMedia::Video { .. } => format!(
            concat!(
                "<video class=\"x-media\" controls preload=\"none\">",
                "<source src=\"{media_url}\" type=\"video/mp4\">",
                "</video>"
            ),
            media_url = media_url,
        ),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_x_status_urls() {
        assert_eq!(
            parse_post_url("https://twitter.com/user/status/123456789?s=20"),
            Some((
                "https://x.com/user/status/123456789".to_string(),
                "123456789".to_string()
            ))
        );
        assert_eq!(
            parse_post_url("https://x.com/i/status/123456789"),
            Some((
                "https://x.com/i/status/123456789".to_string(),
                "123456789".to_string()
            ))
        );
        assert!(parse_post_url("https://evil.example/user/status/123456789").is_none());
        assert!(parse_post_url("https://x.com/user/status/not-a-number").is_none());
    }

    #[test]
    fn extracts_first_supported_media() {
        let response = serde_json::json!({
            "mediaDetails": [
                {"type": "photo", "media_url_https": "https://pbs.twimg.com/media/example.jpg"},
                {"type": "photo", "media_url_https": "https://pbs.twimg.com/media/second.jpg"}
            ]
        });
        assert!(matches!(
            extract_media(&response),
            Some(XMedia::Image { extension, .. }) if extension == "jpg"
        ));

        let response = serde_json::json!({
            "video": {
                "variants": [
                    {"content_type": "application/x-mpegURL", "url": "https://video.twimg.com/playlist.m3u8"},
                    {"content_type": "video/mp4", "bitrate": 256000, "url": "https://video.twimg.com/low.mp4"},
                    {"content_type": "video/mp4", "bitrate": 832000, "url": "https://video.twimg.com/high.mp4"}
                ]
            }
        });
        assert!(matches!(
            extract_media(&response),
            Some(XMedia::Video { url }) if url.path() == "/high.mp4"
        ));
    }

    #[test]
    fn rejects_media_from_untrusted_hosts() {
        assert!(parse_image_url("https://evil.example/image.jpg").is_none());
        let video = serde_json::json!({
            "variants": [
                {"content_type": "video/mp4", "url": "https://evil.example/video.mp4"}
            ]
        });
        assert!(parse_video_variants(&video).is_none());
    }
}
