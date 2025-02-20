use crate::{user::User, POSTGRES_TIMESTAMP_FORMAT};
use regex::Regex;
use sqlx::{PgConnection, Postgres, QueryBuilder};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

const APPLICATION_OCTET_STREAM: &'static str = "application/octet-stream";
const UPLOADS_DIR: &'static str = "uploads";
const MEDIA_DIR: &'static str = "pub/media";

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
    pub anon_token: Option<Uuid>,
    pub status: PostStatus,
    pub pub_id: String,
    pub media_file_name: Option<String>,
    pub media_category: Option<PostMediaCategory>,
    pub media_mime_type: Option<String>,
    pub ip_hash: Option<String>,
    #[sqlx(default)]
    pub created_at_str: Option<String>,
    pub thumbnail_file_name: Option<String>,
}

impl Post {
    pub async fn select_latest(
        tx: &mut PgConnection,
        user: &User,
        until_id: Option<i32>,
        from_id: Option<i32>,
        limit: i32,
    ) -> Vec<Self> {
        let mut query_builder: QueryBuilder<Postgres> =
            QueryBuilder::new("SELECT * FROM posts WHERE (");
        if user.admin() {
            query_builder.push("status <> 'rejected' ")
        } else {
            query_builder.push("status = 'approved' ")
        };
        query_builder.push("OR anon_token = ");
        query_builder.push_bind(&user.anon_token);
        if let Some(account) = &user.account {
            query_builder.push(" OR account_id = ");
            query_builder.push_bind(account.id);
        }
        query_builder.push(") AND hidden = false ");
        if let Some(until_id) = until_id {
            query_builder.push("AND id <= ");
            query_builder.push_bind(until_id);
        }
        if let Some(from_id) = from_id {
            query_builder.push("AND id > ");
            query_builder.push_bind(from_id);
        }
        query_builder.push(" ORDER BY id ");
        // invert interim order
        query_builder.push(if from_id.is_some() { "ASC" } else { "DESC" });
        query_builder.push(" LIMIT ");
        query_builder.push_bind(limit);
        query_builder
            .build_query_as()
            .fetch_all(&mut *tx)
            .await
            .expect("select latest posts")
    }

    pub fn posted_by(&self, user: &User) -> bool {
        self.anon_token
            .as_ref()
            .is_some_and(|uuid| uuid == &user.anon_token)
            || user
                .account
                .as_ref()
                .is_some_and(|a| self.account_id.is_some_and(|id| id == a.id))
    }

    pub async fn select_by_pub_id(tx: &mut PgConnection, pub_id: &str) -> Option<Self> {
        sqlx::query_as(concat!(
            "SELECT *, ",
            "to_char(created_at, $1) AS created_at_str ",
            "FROM posts WHERE pub_id = $2"
        ))
        .bind(POSTGRES_TIMESTAMP_FORMAT)
        .bind(pub_id)
        .fetch_optional(&mut *tx)
        .await
        .expect("select post by pub_id")
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
            .join(&self.pub_id)
            .join(encrypted_file_name)
    }

    pub fn published_media_path(&self) -> PathBuf {
        std::path::Path::new(MEDIA_DIR)
            .join(&self.pub_id)
            .join(&self.media_file_name.as_ref().unwrap())
    }

    pub fn thumbnail_path(&self) -> PathBuf {
        std::path::Path::new(MEDIA_DIR)
            .join(&self.pub_id)
            .join(&self.thumbnail_file_name.as_ref().unwrap())
    }
}

pub struct PostSubmission {
    pub body: String,
    pub anon: Option<String>,
    pub media_file_name: Option<String>,
    pub media_bytes: Option<Vec<u8>>,
    pub pub_id: String,
}

impl PostSubmission {
    pub async fn insert(&self, tx: &mut PgConnection, user: &User, ip_hash: &str) -> Post {
        let (media_category, media_mime_type) =
            Self::determine_media_type(self.media_file_name.as_deref());
        let (anon_token, account_id, username) = if user.anon() {
            (Some(&user.anon_token), None, None)
        } else {
            let account = user.account.as_ref().expect("get account");
            (None, Some(account.id), Some(&account.username))
        };
        sqlx::query_as(concat!(
            "INSERT INTO posts (anon_token, account_id, username, body, ip_hash, pub_id, ",
            "media_file_name, media_category, media_mime_type) ",
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *",
        ))
        .bind(anon_token)
        .bind(account_id)
        .bind(username)
        .bind(&self.body_as_html())
        .bind(ip_hash)
        .bind(&self.pub_id)
        .bind(self.media_file_name.as_deref())
        .bind(media_category)
        .bind(media_mime_type.as_deref())
        .fetch_one(&mut *tx)
        .await
        .expect("insert new post")
    }

    pub fn anon(&self) -> bool {
        self.anon.as_ref().is_some_and(|a| a == "on")
    }

    fn body_as_html(&self) -> String {
        let html = self
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
        let html = url_pattern.replace_all(&html, anchor_tag);
        let youtube_link_pattern = concat!(
            r#"<a href=""#,
            r"https?://(?:(?:(?:www|m)\.)?youtube\.com/(?:watch?(?:\S*)v=|shorts/)([^&\s\?]+)|",
            r"youtu.be/([^&\s\?]+))\S*",
            r#"" target="_blank">\S+</a>"#,
        );
        let youtube_link_regex = Regex::new(youtube_link_pattern).expect("build regex pattern");
        let youtube_thumbnail_link = concat!(
            r#"<a href="https://www.youtube.com/watch?v=$1$2" target="_blank">"#,
            r#"<img src="https://img.youtube.com/vi/$1$2/mqdefault.jpg" "#,
            r#"width="320" height="180"></a>"#,
        );
        let html = youtube_link_regex.replace_all(&html, youtube_thumbnail_link);
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

    pub async fn save_encrypted_media_file(self) -> Result<(), String> {
        if self.media_bytes.is_none() {
            return Err(String::from("no media bytes"));
        }
        let encrypted_file_name = self.media_file_name.unwrap() + ".gpg";
        let encrypted_file_path = std::path::Path::new(UPLOADS_DIR)
            .join(&self.pub_id)
            .join(&encrypted_file_name);
        let uploads_pub_id_dir = encrypted_file_path.parent().unwrap();
        std::fs::create_dir(uploads_pub_id_dir).expect("create uploads pub_id dir");
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
            std::fs::remove_dir(uploads_pub_id_dir).expect("remove uploads pub_id dir");
            Err(String::from("gpg failed to encrypt media file"))
        }
    }

    pub fn generate_alphanumeric_id() -> String {
        use rand::distributions::Alphanumeric;
        use rand::Rng;
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(12)
            .map(char::from)
            .collect()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PostReview {
    pub pub_id: String,
    pub status: PostStatus,
}

impl PostReview {
    pub async fn update_status(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE posts SET status = $1 WHERE pub_id = $2")
            .bind(&self.status)
            .bind(&self.pub_id)
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
            .join(&self.pub_id)
            .join(Self::thumbnail_file_name(media_file_name))
    }

    pub async fn update_thumbnail(&self, tx: &mut PgConnection, media_file_name: &str) {
        let thumbnail_file_name = Self::thumbnail_file_name(media_file_name);
        println!("thumbnail_file_name: {}", thumbnail_file_name);
        sqlx::query("UPDATE posts SET thumbnail_file_name = $1 WHERE pub_id = $2")
            .bind(thumbnail_file_name)
            .bind(&self.pub_id)
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
    pub pub_id: String,
}

impl PostHiding {
    pub async fn hide_post(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE posts SET hidden = true WHERE pub_id = $1")
            .bind(&self.pub_id)
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
        let mut submission = PostSubmission {
            body: "<&test body".to_owned(),
            anon: None,
            media_file_name: None,
            pub_id: PostSubmission::generate_alphanumeric_id(),
            media_bytes: None,
        };
        assert_eq!(submission.body_as_html(), "&lt;&amp;test body");
        submission.body = "<&test body\n\nhttps://example.com".to_owned();
        assert_eq!(
            submission.body_as_html(),
            "&lt;&amp;test body<br><br><a href=\"https://example.com\" target=\"_blank\">https://example.com</a>"
        );
        submission.body = "<&test body\n\nhttps://www.youtube.com/watch?v=12345678ab".to_owned();
        assert_eq!(
            submission.body_as_html(),
            concat!(
                "&lt;&amp;test body<br><br>",
                r#"<a href="https://www.youtube.com/watch?v=12345678ab" target="_blank">"#,
                r#"<img src="https://img.youtube.com/vi/12345678ab/mqdefault.jpg" "#,
                r#"width="320" height="180"></a>"#,
            )
        );
        submission.body = "<&test body\n\nhttps://youtube.com/shorts/rb3fj3ADILJ".to_owned();
        assert_eq!(
            submission.body_as_html(),
            concat!(
                "&lt;&amp;test body<br><br>",
                r#"<a href="https://www.youtube.com/watch?v=rb3fj3ADILJ" target="_blank">"#,
                r#"<img src="https://img.youtube.com/vi/rb3fj3ADILJ/mqdefault.jpg" "#,
                r#"width="320" height="180"></a>"#,
            )
        );
        submission.body = "<&test body\n\nhttps://youtu.be/2Uc9WTDBSI8?si=q9OkPEWRQ0RjoWg".to_owned();
        assert_eq!(
            submission.body_as_html(),
            concat!(
                "&lt;&amp;test body<br><br>",
                r#"<a href="https://www.youtube.com/watch?v=2Uc9WTDBSI8" target="_blank">"#,
                r#"<img src="https://img.youtube.com/vi/2Uc9WTDBSI8/mqdefault.jpg" "#,
                r#"width="320" height="180"></a>"#,
            )
        );
    }
}
