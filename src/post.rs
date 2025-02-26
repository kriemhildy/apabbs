use crate::{init, user::User, POSTGRES_TIMESTAMP_FORMAT};
use regex::Regex;
use sqlx::{PgConnection, Postgres, QueryBuilder};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

const APPLICATION_OCTET_STREAM: &'static str = "application/octet-stream";
const UPLOADS_DIR: &'static str = "uploads";
const MEDIA_DIR: &'static str = "pub/media";
const YOUTUBE_DIR: &'static str = "pub/youtube";
const MAX_YOUTUBE_EMBEDS: usize = 3;

#[derive(sqlx::Type, serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "post_status", rename_all = "snake_case")]
pub enum PostStatus {
    Pending,
    Approved,
    Rejected,
    Banned,
}

#[derive(sqlx::Type, serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "post_media_category", rename_all = "snake_case")]
pub enum PostMediaCategory {
    Image,
    Video,
    Audio,
}

#[derive(sqlx::FromRow, serde::Serialize, Clone, Debug)]
pub struct Post {
    pub id: i32,
    pub body: String,
    pub account_id: Option<i32>,
    pub username: Option<String>, // cache
    pub session_token: Option<Uuid>,
    pub status: PostStatus,
    pub key: String,
    pub media_file_name: Option<String>,
    pub media_category: Option<PostMediaCategory>,
    pub media_mime_type: Option<String>,
    pub ip_hash: Option<String>,
    #[sqlx(default)]
    pub created_at_str: Option<String>,
    pub thumbnail_file_name: Option<String>,
}

impl Post {
    pub async fn select(
        tx: &mut PgConnection,
        user: &User,
        post_id_opt: Option<i32>,
        invert: bool,
    ) -> Vec<Self> {
        let mut query_builder: QueryBuilder<Postgres> =
            QueryBuilder::new("SELECT * FROM posts WHERE (");
        if user.admin() {
            query_builder.push("status <> 'rejected' ")
        } else {
            query_builder.push("status = 'approved' ")
        };
        query_builder.push("OR session_token = ");
        query_builder.push_bind(&user.session_token);
        if let Some(account) = &user.account {
            query_builder.push(" OR account_id = ");
            query_builder.push_bind(account.id);
        }
        query_builder.push(") AND hidden = false");
        // invert interim order
        // add one to "until" limit to check if there are more pages
        let (operator, order, limit) = if invert {
            (">", "ASC", init::per_page()) // sanity limit
        } else {
            ("<=", "DESC", init::per_page() + 1)
        };
        if let Some(post_id) = post_id_opt {
            query_builder.push(&format!(" AND id {} ", operator));
            query_builder.push_bind(post_id);
        }
        query_builder.push(&format!(" ORDER BY id {} LIMIT {}", order, limit));
        query_builder
            .build_query_as()
            .fetch_all(&mut *tx)
            .await
            .expect("select posts")
    }

    pub async fn select_by_author(tx: &mut PgConnection, account_id: i32) -> Vec<Self> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE account_id = $1 ",
            "AND status = 'approved' ORDER BY id DESC LIMIT $2",
        ))
        .bind(account_id)
        .bind(init::per_page() as i32)
        .fetch_all(&mut *tx)
        .await
        .expect("select posts by account")
    }

    pub fn author(&self, user: &User) -> bool {
        self.session_token
            .as_ref()
            .is_some_and(|uuid| uuid == &user.session_token)
            || user
                .account
                .as_ref()
                .is_some_and(|a| self.account_id.is_some_and(|id| id == a.id))
    }

    pub async fn select_by_key(tx: &mut PgConnection, key: &str) -> Option<Self> {
        sqlx::query_as(concat!(
            "SELECT *, ",
            "to_char(created_at, $1) AS created_at_str ",
            "FROM posts WHERE key = $2"
        ))
        .bind(POSTGRES_TIMESTAMP_FORMAT)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await
        .expect("select post by key")
    }

    pub async fn delete(&self, tx: &mut PgConnection) {
        sqlx::query("DELETE FROM posts WHERE id = $1")
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("delete post");
    }

    pub async fn decrypt_media_file(&self) -> Vec<u8> {
        let output = tokio::process::Command::new("gpg")
            .args(["--batch", "--decrypt", "--passphrase-file", "gpg.key"])
            .arg(&self.encrypted_media_path())
            .output()
            .await
            .expect("decrypt media file");
        output.stdout
    }

    pub fn encrypted_media_path(&self) -> PathBuf {
        let encrypted_file_name = self.media_file_name.as_ref().unwrap().to_owned() + ".gpg";
        std::path::Path::new(UPLOADS_DIR)
            .join(&self.key)
            .join(encrypted_file_name)
    }

    pub fn published_media_path(&self) -> PathBuf {
        std::path::Path::new(MEDIA_DIR)
            .join(&self.key)
            .join(&self.media_file_name.as_ref().unwrap())
    }

    pub fn thumbnail_path(&self) -> PathBuf {
        std::path::Path::new(MEDIA_DIR)
            .join(&self.key)
            .join(&self.thumbnail_file_name.as_ref().unwrap())
    }
}

#[derive(Default)]
pub struct PostSubmission {
    pub session_token: Uuid,
    pub body: String,
    pub media_file_name: Option<String>,
    pub media_bytes: Option<Vec<u8>>,
}

impl PostSubmission {
    pub async fn insert(&self, tx: &mut PgConnection, user: &User, ip_hash: &str) -> Post {
        let (media_category, media_mime_type) =
            Self::determine_media_type(self.media_file_name.as_deref());
        let (session_token, account_id, username) = match user.account {
            Some(ref account) => (None, Some(account.id), Some(&account.username)),
            None => (Some(self.session_token), None, None),
        };
        sqlx::query_as(concat!(
            "INSERT INTO posts (session_token, account_id, username, body, ip_hash, ",
            "media_file_name, media_category, media_mime_type) ",
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
        ))
        .bind(session_token)
        .bind(account_id)
        .bind(username)
        .bind(&self.body_as_html())
        .bind(ip_hash)
        .bind(self.media_file_name.as_deref())
        .bind(media_category)
        .bind(media_mime_type.as_deref())
        .fetch_one(&mut *tx)
        .await
        .expect("insert new post")
    }

    fn download_youtube_thumbnail(video_id: &str, size: &str) -> Option<String> {
        let remote_thumbnail_url = format!("https://img.youtube.com/vi/{}/{}.jpg", video_id, size);
        let video_id_dir = std::path::Path::new(YOUTUBE_DIR).join(video_id);
        let local_thumbnail_path = video_id_dir.join(format!("{}.jpg", size));
        let local_thumbnail_url = local_thumbnail_path
            .to_str()
            .unwrap()
            .to_owned()
            .replacen("pub", "", 1);
        if !video_id_dir.exists() {
            std::fs::create_dir(&video_id_dir).expect("create youtube video id dir");
        }
        let curl_status = std::process::Command::new("curl")
            .args(["--silent", "--fail", "--output"])
            .arg(&local_thumbnail_path)
            .arg(&remote_thumbnail_url)
            .status()
            .expect("download youtube thumbnail");
        if curl_status.success() {
            Some(local_thumbnail_url)
        } else {
            None
        }
    }

    fn body_as_html(&self) -> String {
        let mut html = self
            .body
            .trim_end()
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("  ", " &nbsp;");
        let url_pattern = Regex::new(r#"\b(https?://\S+)"#).expect("build regex pattern");
        let anchor_tag = r#"<a href="$1" target="_blank">$1</a>"#;
        html = url_pattern.replace_all(&html, anchor_tag).to_string();
        let youtube_link_pattern = concat!(
            r#"(?m)^\ *<a href=""#,
            r#"https?://(?:youtu\.be/|(?:www\.|m\.)?youtube\.com/(watch\S*[\?&]v=|shorts/))"#,
            r#"([^&\s\?]+)\S*"#,
            r#"" target="_blank">\S+</a>\ *$"#,
        );
        let youtube_link_regex = Regex::new(youtube_link_pattern).expect("build regex pattern");
        for _ in 0..MAX_YOUTUBE_EMBEDS {
            let captures = match youtube_link_regex.captures(&html) {
                Some(captures) => captures,
                None => break,
            };
            // youtu.be has no match for 1, but is always not a short
            let youtube_short = captures.get(1).is_some_and(|m| m.as_str() == "shorts/");
            let youtube_video_id = &captures[2];
            println!("youtube_video_id: {}", youtube_video_id);
            let thumbnail_sizes = if youtube_short {
                vec!["oar2"]
            } else {
                vec!["maxresdefault", "sddefault", "hqdefault", "mqdefault"]
            };
            let local_thumbnail_url = thumbnail_sizes
                .iter()
                .find_map(|s| Self::download_youtube_thumbnail(&youtube_video_id, s));
            let local_thumbnail_url = match local_thumbnail_url {
                Some(url) => url,
                None => break,
            };
            let youtube_url_path = if youtube_short { "shorts/" } else { "watch?v=" };
            let youtube_thumbnail_link = format!(
                concat!(
                    r#"<a class="youtube" href="https://www.youtube.com/{url_path}{video_id}" "#,
                    r#"target="_blank"><img src="/youtube.svg" alt></a>"#,
                    r#"<img src="{thumbnail_url}" alt="YouTube {video_id}">"#,
                ),
                url_path = youtube_url_path,
                video_id = youtube_video_id,
                thumbnail_url = local_thumbnail_url
            );
            html = youtube_link_regex
                .replace(&html, youtube_thumbnail_link)
                .to_string();
        }
        html.replace("\n", "<br>")
    }

    fn determine_media_type(
        media_file_name: Option<&str>,
    ) -> (Option<PostMediaCategory>, Option<String>) {
        if media_file_name.is_none() {
            return (None, None);
        }
        let media_file_name = media_file_name.unwrap();
        use PostMediaCategory::*;
        let extension = media_file_name.split('.').last();
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

    pub async fn save_encrypted_media_file(self, key: &str) -> Result<(), String> {
        if self.media_bytes.is_none() {
            return Err(String::from("no media bytes"));
        }
        let encrypted_file_name = self.media_file_name.unwrap() + ".gpg";
        let encrypted_file_path = std::path::Path::new(UPLOADS_DIR)
            .join(key)
            .join(&encrypted_file_name);
        let uploads_key_dir = encrypted_file_path.parent().unwrap();
        std::fs::create_dir(uploads_key_dir).expect("create uploads key dir");
        let mut child = tokio::process::Command::new("gpg")
            .args([
                "--batch",
                "--symmetric",
                "--passphrase-file",
                "gpg.key",
                "--output",
            ])
            .arg(&encrypted_file_path)
            .stdin(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn gpg to encrypt media file");
        let mut stdin = child.stdin.take().expect("open stdin");
        tokio::spawn(async move {
            stdin
                .write_all(&self.media_bytes.unwrap())
                .await
                .expect("write data to stdin");
        });
        let child_status = child.wait().await.expect("wait for gpg to finish");
        if child_status.success() {
            println!(
                "file uploaded and encrypted as: {}",
                encrypted_file_path.to_str().unwrap()
            );
            Ok(())
        } else {
            std::fs::remove_dir(uploads_key_dir).expect("remove uploads key dir");
            Err(String::from("gpg failed to encrypt media file"))
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PostReview {
    pub session_token: Uuid,
    pub key: String,
    pub status: PostStatus,
}

impl PostReview {
    pub async fn update_status(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE posts SET status = $1 WHERE key = $2")
            .bind(&self.status)
            .bind(&self.key)
            .execute(&mut *tx)
            .await
            .expect("update post status");
    }

    pub fn thumbnail_file_name(media_file_name: &str) -> String {
        let extension_pattern = Regex::new(r"\.[^\.]+$").expect("build extension regex pattern");
        String::from("tn_") + &extension_pattern.replace(media_file_name, ".webp")
    }

    pub fn thumbnail_path(&self, media_file_name: &str) -> PathBuf {
        std::path::Path::new(MEDIA_DIR)
            .join(&self.key)
            .join(Self::thumbnail_file_name(media_file_name))
    }

    pub async fn update_thumbnail(&self, tx: &mut PgConnection, media_file_name: &str) {
        let thumbnail_file_name = Self::thumbnail_file_name(media_file_name);
        println!("thumbnail_file_name: {}", thumbnail_file_name);
        sqlx::query("UPDATE posts SET thumbnail_file_name = $1 WHERE key = $2")
            .bind(thumbnail_file_name)
            .bind(&self.key)
            .execute(&mut *tx)
            .await
            .expect("update post thumbnail");
    }

    pub async fn generate_thumbnail(media_path_str: &str) {
        let extension = media_path_str
            .split('.')
            .last()
            .expect("get file extension");
        let vips_input_file_path = media_path_str.to_owned()
            + match extension.to_lowercase().as_str() {
                "gif" | "webp" => "[n=-1]", // animated image support
                _ => "",
            };
        let command_output = tokio::process::Command::new("vipsthumbnail")
            .args(["--size=1200x1600>", "--output=tn_%s.webp"])
            .arg(&vips_input_file_path)
            .output()
            .await
            .expect("generate thumbnail");
        println!("vipsthumbnail output: {:?}", command_output);
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PostHiding {
    pub session_token: Uuid,
    pub key: String,
}

impl PostHiding {
    pub async fn hide_post(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE posts SET hidden = true WHERE key = $1")
            .bind(&self.key)
            .execute(&mut *tx)
            .await
            .expect("set hidden flag to true");
    }
}

#[derive(Clone, Debug)]
pub struct PostMessage {
    pub post: Post,
    pub html: String,
    pub admin: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_body_as_html() {
        let submission = PostSubmission {
            body: concat!(
                "<&test body\n\n",
                "https://example.com\n",
                " https://m.youtube.com/watch?v=jNQXAC9IVRw\n",
                "https://youtu.be/kixirmHePCc?si=q9OkPEWRQ0RjoWg\n",
                "http://youtube.com/shorts/cHMCGCWit6U?si=q9OkPEWRQ0RjoWg \n",
                "https://example.com?m.youtube.com/watch?v=jNQXAC9IVRw\n",
                "foo https://www.youtube.com/watch?v=ySrBS4ulbmQ\n\n",
                "https://www.youtube.com/watch?v=ySrBS4ulbmQ bar",
            )
            .to_owned(),
            ..Default::default()
        };
        assert_eq!(
            submission.body_as_html(),
            concat!(
                "&lt;&amp;test body<br><br>",
                r#"<a href="https://example.com" target="_blank">https://example.com</a>"#,
                r#"<br>"#,
                r#"<a class="youtube" href="https://www.youtube.com/watch?v=jNQXAC9IVRw" "#,
                r#"target="_blank"><img src="/youtube.svg" alt></a>"#,
                r#"<img src="/youtube/jNQXAC9IVRw/hqdefault.jpg" "#,
                r#"alt="YouTube jNQXAC9IVRw">"#,
                r#"<br>"#,
                r#"<a class="youtube" href="https://www.youtube.com/watch?v=kixirmHePCc" "#,
                r#"target="_blank"><img src="/youtube.svg" alt></a>"#,
                r#"<img src="/youtube/kixirmHePCc/maxresdefault.jpg" "#,
                r#"alt="YouTube kixirmHePCc">"#,
                r#"<br>"#,
                r#"<a class="youtube" href="https://www.youtube.com/shorts/cHMCGCWit6U" "#,
                r#"target="_blank"><img src="/youtube.svg" alt></a>"#,
                r#"<img src="/youtube/cHMCGCWit6U/oar2.jpg" "#,
                r#"alt="YouTube cHMCGCWit6U">"#,
                r#"<br>"#,
                r#"<a href="https://example.com?m.youtube.com/watch?v=jNQXAC9IVRw" "#,
                r#"target="_blank">https://example.com?m.youtube.com/watch?v=jNQXAC9IVRw</a>"#,
                r#"<br>"#,
                r#"foo <a href="https://www.youtube.com/watch?v=ySrBS4ulbmQ" "#,
                r#"target="_blank">https://www.youtube.com/watch?v=ySrBS4ulbmQ</a>"#,
                r#"<br><br>"#,
                r#"<a href="https://www.youtube.com/watch?v=ySrBS4ulbmQ" "#,
                r#"target="_blank">https://www.youtube.com/watch?v=ySrBS4ulbmQ</a> bar"#,
            )
        );
    }
}
