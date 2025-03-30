use crate::{
    POSTGRES_HTML_DATETIME, POSTGRES_RFC5322_DATETIME,
    user::{AccountRole, User},
};
use regex::Regex;
use sqlx::{PgConnection, Postgres, QueryBuilder};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use url::Url;
use uuid::Uuid;

const APPLICATION_OCTET_STREAM: &'static str = "application/octet-stream";
const UPLOADS_DIR: &'static str = "uploads";
const MEDIA_DIR: &'static str = "pub/media";
const YOUTUBE_DIR: &'static str = "pub/youtube";
const MAX_YOUTUBE_EMBEDS: usize = 16;
const MAX_INTRO_BYTES: usize = 1600;
const MAX_INTRO_BREAKS: usize = 24;

#[derive(sqlx::Type, serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "post_status", rename_all = "snake_case")]
pub enum PostStatus {
    Pending,
    Approved,
    Delisted,
    Reported,
    Rejected,
    Banned,
}

#[derive(sqlx::Type, serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "media_category", rename_all = "snake_case")]
pub enum MediaCategory {
    Image,
    Video,
    Audio,
}

#[derive(sqlx::FromRow, serde::Serialize, Clone, Debug)]
pub struct Post {
    pub id: i32,
    pub body: String,
    pub account_id_opt: Option<i32>,
    pub session_token_opt: Option<Uuid>,
    pub status: PostStatus,
    pub key: String,
    pub media_filename_opt: Option<String>,
    pub media_category_opt: Option<MediaCategory>,
    pub media_mime_type_opt: Option<String>,
    pub ip_hash_opt: Option<String>,
    #[sqlx(default)]
    pub created_at_rfc5322_opt: Option<String>,
    #[sqlx(default)]
    pub created_at_html_opt: Option<String>,
    pub thumbnail_opt: Option<String>,
    #[sqlx(default)]
    pub recent_opt: Option<bool>,
    pub youtube: bool,
    pub intro_limit_opt: Option<i32>,
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
        match user.account_opt {
            Some(ref account) => match account.role {
                AccountRole::Admin => query_builder.push("status <> 'rejected' "),
                AccountRole::Mod => query_builder.push("status NOT IN ('rejected', 'reported') "),
                _ => query_builder.push("status = 'approved' "),
            },
            None => query_builder.push("status = 'approved' "),
        };
        query_builder.push("OR session_token_opt = ");
        query_builder.push_bind(&user.session_token);
        if let Some(ref account) = user.account_opt {
            query_builder.push(" OR account_id_opt = ");
            query_builder.push_bind(account.id);
        }
        query_builder.push(") AND hidden = false");
        // invert interim order
        // add one to "until" limit to check if there are more pages
        let (operator, order, limit) = if invert {
            (">", "ASC", crate::per_page()) // sanity limit
        } else {
            ("<=", "DESC", crate::per_page() + 1)
        };
        if let Some(post_id) = post_id_opt {
            query_builder.push(&format!(" AND id {} ", operator));
            query_builder.push_bind(post_id);
        }
        query_builder.push(&format!(" ORDER BY id {} LIMIT ", order));
        query_builder.push_bind(limit as i32);
        query_builder
            .build_query_as()
            .fetch_all(&mut *tx)
            .await
            .expect("select posts")
    }

    pub async fn select_by_author(tx: &mut PgConnection, account_id: i32) -> Vec<Self> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE account_id_opt = $1 ",
            "AND status = 'approved' ORDER BY id DESC LIMIT $2",
        ))
        .bind(account_id)
        .bind(crate::per_page() as i32)
        .fetch_all(&mut *tx)
        .await
        .expect("select posts by account")
    }

    pub fn author(&self, user: &User) -> bool {
        self.session_token_opt
            .as_ref()
            .is_some_and(|uuid| uuid == &user.session_token)
            || user
                .account_opt
                .as_ref()
                .is_some_and(|a| self.account_id_opt.is_some_and(|id| id == a.id))
    }

    pub async fn select_by_key(tx: &mut PgConnection, key: &str) -> Option<Self> {
        sqlx::query_as(concat!(
            "SELECT *, to_char(created_at, $1) AS created_at_rfc5322_opt, ",
            "to_char(created_at, $2) AS created_at_html_opt, ",
            "now() - interval '2 days' < created_at AS recent_opt FROM posts WHERE key = $3"
        ))
        .bind(POSTGRES_RFC5322_DATETIME)
        .bind(POSTGRES_HTML_DATETIME)
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
        let encrypted_filename = self.media_filename_opt.as_ref().unwrap().to_owned() + ".gpg";
        std::path::Path::new(UPLOADS_DIR)
            .join(&self.key)
            .join(encrypted_filename)
    }

    pub fn published_media_path(&self) -> PathBuf {
        std::path::Path::new(MEDIA_DIR)
            .join(&self.key)
            .join(&self.media_filename_opt.as_ref().unwrap())
    }

    pub fn thumbnail_path(&self) -> PathBuf {
        std::path::Path::new(MEDIA_DIR).join(&self.key).join(
            &self
                .thumbnail_opt
                .as_ref()
                .expect("thumbnail_filename is some"),
        )
    }

    async fn gpg_encrypt(&self, bytes: Vec<u8>) -> Result<(), &str> {
        let encrypted_media_path = self.encrypted_media_path();
        let mut child = tokio::process::Command::new("gpg")
            .args([
                "--batch",
                "--symmetric",
                "--passphrase-file",
                "gpg.key",
                "--output",
            ])
            .arg(&encrypted_media_path)
            .stdin(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn gpg to encrypt media file");
        let mut stdin = child.stdin.take().expect("open stdin");
        tokio::spawn(async move {
            stdin.write_all(&bytes).await.expect("write data to stdin");
        });
        let child_status = child.wait().await.expect("wait for gpg to finish");
        if child_status.success() {
            println!(
                "file encrypted as: {}",
                encrypted_media_path.to_str().unwrap()
            );
            Ok(())
        } else {
            Err("gpg failed to encrypt file")
        }
    }

    pub async fn update_status(&self, tx: &mut PgConnection, new_status: &PostStatus) {
        sqlx::query("UPDATE posts SET status = $1 WHERE id = $2")
            .bind(new_status)
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("update post status");
    }

    async fn update_thumbnail(&self, tx: &mut PgConnection, thumbnail_filename: &str) {
        sqlx::query("UPDATE posts SET thumbnail_opt = $1 WHERE id = $2")
            .bind(thumbnail_filename)
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("update post thumbnail");
    }

    pub async fn reencrypt_media_file(&self) -> Result<(), &str> {
        let encrypted_file_path = self.encrypted_media_path();
        let uploads_key_dir = encrypted_file_path.parent().unwrap();
        std::fs::create_dir(uploads_key_dir).expect("create uploads key dir");
        let media_file_path = self.published_media_path();
        let media_bytes = std::fs::read(&media_file_path).expect("read media file");
        let result = self.gpg_encrypt(media_bytes).await;
        match result {
            Ok(()) => PostReview::delete_media_key_dir(&self.key),
            Err(msg) => {
                std::fs::remove_dir(uploads_key_dir).expect("remove uploads key dir");
                eprintln!("{}", msg);
            }
        }
        result
    }
}

#[derive(Default)]
pub struct PostSubmission {
    pub session_token: Uuid,
    pub body: String,
    pub media_filename_opt: Option<String>,
    pub media_bytes_opt: Option<Vec<u8>>,
}

impl PostSubmission {
    pub async fn generate_key(tx: &mut PgConnection) -> String {
        sqlx::query_scalar("SELECT alphanumeric(8)")
            .fetch_one(&mut *tx)
            .await
            .expect("key is generated")
    }

    pub async fn insert(
        &self,
        tx: &mut PgConnection,
        user: &User,
        ip_hash: &str,
        key: &str,
    ) -> Post {
        let (media_category_opt, media_mime_type_opt) =
            Self::determine_media_type(self.media_filename_opt.as_deref());
        let (session_token_opt, account_id_opt) = match user.account_opt {
            Some(ref account) => (None, Some(account.id)),
            None => (Some(self.session_token), None),
        };
        let html_body = self.body_to_html(key);
        let youtube = html_body.contains(r#"<a href="https://www.youtube.com"#);
        let intro_limit_opt = Self::intro_limit(&html_body);
        sqlx::query_as(concat!(
            "INSERT INTO posts (key, session_token_opt, account_id_opt, body, ip_hash_opt, ",
            "media_filename_opt, media_category_opt, media_mime_type_opt, youtube, ",
            "intro_limit_opt) ",
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *",
        ))
        .bind(key)
        .bind(session_token_opt)
        .bind(account_id_opt)
        .bind(&html_body)
        .bind(ip_hash)
        .bind(self.media_filename_opt.as_deref())
        .bind(media_category_opt)
        .bind(media_mime_type_opt.as_deref())
        .bind(youtube)
        .bind(intro_limit_opt)
        .fetch_one(&mut *tx)
        .await
        .expect("insert new post")
    }

    fn download_youtube_thumbnail(
        video_id: &str,
        video_id_dir: &PathBuf,
        size: &str,
    ) -> Option<PathBuf> {
        let remote_thumbnail_url = format!("https://img.youtube.com/vi/{}/{}.jpg", video_id, size);
        let local_thumbnail_path = video_id_dir.join(format!("{}.jpg", size));
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
            Some(local_thumbnail_path)
        } else {
            None
        }
    }

    fn body_to_html(&self, key: &str) -> String {
        let mut html = self
            .body
            .trim_end()
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&apos;")
            .replace("  ", " &nbsp;")
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .replace("\n", "\n<br>\n")
            .replace("\n\n", "\n");
        let url_pattern =
            Regex::new(r#"(?m)(^|\s)(https?://\S{4,256})(\s|$)"#).expect("build regex pattern");
        let anchor_tag = r#"$1<a href="$2">$2</a>$3"#;
        html = url_pattern.replace_all(&html, anchor_tag).to_string();
        html = Self::embed_youtube(html, key);
        let sentence_pattern = Regex::new(concat!(
            r#"([\.!\?,;:\-"#,
            "\u{2013}\u{2014}",
            "][\"'",
            "\u{201d}\u{2019}",
            "]?) +"
        ))
        .expect("build regex pattern");
        sentence_pattern.replace_all(&html, "$1\n").to_string()
    }

    fn embed_youtube(mut html: String, key: &str) -> String {
        let youtube_link_pattern = concat!(
            r#"(?m)^ *<a href=""#,
            r#"(https?://(?:youtu\.be/|(?:www\.|m\.)?youtube\.com/"#,
            r#"(watch\S*(?:\?|&amp;)v=|shorts/))"#,
            r#"([^&\s\?]+)\S*)">\S+</a> *$"#,
        );
        let youtube_link_regex = Regex::new(youtube_link_pattern).expect("build regex pattern");
        for _ in 0..MAX_YOUTUBE_EMBEDS {
            let captures = match youtube_link_regex.captures(&html) {
                None => break,
                Some(captures) => captures,
            };
            // youtu.be has no match for 2, but is always not a short
            let youtube_short = captures.get(2).is_some_and(|m| m.as_str() == "shorts/");
            let youtube_video_id = &captures[3];
            let youtube_timestamp_opt = if youtube_short {
                None
            } else {
                let url_str = &captures[1].replace("&amp;", "&");
                let parsed_url = Url::parse(&url_str).expect("parse youtube url");
                parsed_url
                    .query_pairs()
                    .find(|(k, _)| k == "t")
                    .map(|(_, v)| v.to_string())
            };
            println!("youtube_video_id: {}", youtube_video_id);
            println!("youtube_timestamp_opt: {:?}", youtube_timestamp_opt);
            let thumbnail_sizes = if youtube_short {
                vec!["oar2"]
            } else {
                vec!["maxresdefault", "sddefault", "hqdefault", "mqdefault"]
            };
            let video_id_dir = std::path::Path::new(YOUTUBE_DIR).join(&youtube_video_id);
            let local_thumbnail_path_opt = if video_id_dir.exists() {
                Some(
                    video_id_dir
                        .read_dir()
                        .expect("read video id dir")
                        .next()
                        .expect("get first entry")
                        .expect("unwrap entry")
                        .path(),
                )
            } else {
                thumbnail_sizes.iter().find_map(|s| {
                    Self::download_youtube_thumbnail(&youtube_video_id, &video_id_dir, s)
                })
            };
            let local_thumbnail_url = match local_thumbnail_path_opt {
                None => break,
                Some(path) => path
                    .to_str()
                    .expect("path to str")
                    .to_owned()
                    .replacen("pub", "", 1),
            };
            let youtube_url_path = if youtube_short { "shorts/" } else { "watch?v=" };
            let youtube_thumbnail_link = format!(
                concat!(
                    "<div class=\"youtube\">\n",
                    "    <div class=\"logo\">\n",
                    "        <a href=\"https://www.youtube.com/{url_path}{video_id}{timestamp}\">\n",
                    "            <img src=\"/youtube.svg\" alt>\n",
                    "        </a>\n",
                    "    </div>\n",
                    "    <a href=\"/post/{key}\">\n",
                    "        <img src=\"{thumbnail_url}\" alt=\"YouTube {video_id}\">\n",
                    "    </a>\n",
                    "</div>",
                ),
                url_path = youtube_url_path,
                video_id = youtube_video_id,
                thumbnail_url = local_thumbnail_url,
                key = key,
                timestamp = youtube_timestamp_opt
                    .map(|t| format!("&amp;t={}", t))
                    .unwrap_or_default(),
            );
            html = youtube_link_regex
                .replace(&html, youtube_thumbnail_link)
                .to_string();
        }
        html
    }

    fn determine_media_type(
        media_filename_opt: Option<&str>,
    ) -> (Option<MediaCategory>, Option<String>) {
        let media_filename = match media_filename_opt {
            None => return (None, None),
            Some(media_filename) => media_filename,
        };
        use MediaCategory::*;
        let extension = media_filename.split('.').last();
        let (media_category_opt, media_mime_type_str) = match extension {
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
        (media_category_opt, Some(media_mime_type_str.to_owned()))
    }

    pub async fn encrypt_uploaded_file(self, post: &Post) -> Result<(), &str> {
        if self.media_bytes_opt.is_none() {
            return Err("no media bytes");
        }
        let encrypted_file_path = post.encrypted_media_path();
        let uploads_key_dir = encrypted_file_path.parent().unwrap();
        std::fs::create_dir(uploads_key_dir).expect("create uploads key dir");
        let result = post.gpg_encrypt(self.media_bytes_opt.unwrap()).await;
        if result.is_err() {
            std::fs::remove_dir(uploads_key_dir).expect("remove uploads key dir");
        }
        result
    }

    fn intro_limit(html: &str) -> Option<i32> {
        // get a slice of the maximum intro bytes limited to the last valid utf8 character
        let last_valid_utf8_index = html
            .char_indices()
            .take_while(|&(idx, _)| idx < MAX_INTRO_BYTES)
            .last()
            .map_or(0, |(idx, _)| idx);
        let slice = if html.len() > last_valid_utf8_index {
            &html[..last_valid_utf8_index]
        } else {
            html
        };
        // stop before a second youtube video
        let youtube_pattern =
            Regex::new(r#"<div class="youtube">\s+<div class="logo">.*?</div>.*?</div>"#)
                .expect("regex builds");
        let youtube_limit_opt = match youtube_pattern.find_iter(slice).nth(1) {
            None => None,
            Some(mat) => {
                let before_second_youtube = &slice[..mat.start()];
                // strip any breaks or whitespace that might be present at the end
                let strip_breaks_pattern = Regex::new(r#"(?:<br>)+$"#).expect("regex builds");
                let stripped = strip_breaks_pattern.replace(before_second_youtube, "");
                Some(stripped.trim_end().len() as i32)
            }
        };
        // check for the maximum breaks
        let single_break_pattern = Regex::new("<br>").expect("regex builds");
        let break_limit_opt = match single_break_pattern.find_iter(slice).nth(MAX_INTRO_BREAKS) {
            None => None,
            Some(mat) => Some(mat.start() as i32),
        };
        // take the smallest of youtube and break limits
        println!(
            "youtube_limit_opt: {:?}, break_limit_opt: {:?}",
            youtube_limit_opt, break_limit_opt
        );
        let min_limit_opt = match (youtube_limit_opt, break_limit_opt) {
            (None, None) => None,
            (Some(y), None) => Some(y),
            (None, Some(b)) => Some(b),
            (Some(y), Some(b)) => Some(y.min(b)),
        };
        println!("min_limit_opt: {:?}", min_limit_opt);
        if min_limit_opt.is_some() {
            println!("intro: {}", &html[..min_limit_opt.unwrap() as usize]);
            return min_limit_opt;
        }
        // do not truncate if beneath the maximum intro length
        println!("html.len(): {}", html.len());
        if html.len() <= MAX_INTRO_BYTES {
            return None;
        }
        // truncate to the last break(s)
        let multiple_breaks_pattern = Regex::new("(?:<br>)+").expect("regex builds");
        if let Some(mat) = multiple_breaks_pattern.find_iter(slice).last() {
            println!("found last break: {}", mat.start());
            return Some(mat.start() as i32);
        }
        // if no breaks, truncate to the last space byte.
        let last_space = slice.rfind(' ');
        if last_space.is_some() {
            return last_space.map(|p| p as i32);
        }
        // if no space found, use the last utf8 character index
        // need to strip incomplete html entities
        // check for & which is not terminated by a ;
        let incomplete_entity_pattern = Regex::new(r"&[^;]*$").expect("regex builds");
        if let Some(mat) = incomplete_entity_pattern.find(slice) {
            println!("found incomplete entity: {}", mat.start());
            return Some(mat.start() as i32);
        }
        // no incomplete entity, return last valid utf8 character index.
        println!("last valid utf8 index: {}", last_valid_utf8_index);
        Some(last_valid_utf8_index as i32)
    }
}

#[derive(PartialEq)]
pub enum ReviewAction {
    DecryptMedia,
    DeleteEncryptedMedia,
    DeletePublishedMedia,
    ReencryptMedia,
    NoAction,
}

#[derive(PartialEq)]
pub enum ReviewError {
    SameStatus,
    ReturnToPending,
    ModOnly,
    AdminOnly,
    RejectedOrBanned,
    RecentOnly,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PostReview {
    pub session_token: Uuid,
    pub status: PostStatus,
}

impl PostReview {
    pub fn write_media_file(published_media_path: &PathBuf, media_bytes: Vec<u8>) {
        let media_key_dir = published_media_path.parent().unwrap();
        std::fs::create_dir(media_key_dir).expect("create media key dir");
        std::fs::write(&published_media_path, media_bytes).expect("write media file");
    }

    async fn generate_thumbnail(published_media_path: &PathBuf) {
        let media_path_str = published_media_path.to_str().unwrap();
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

    pub fn new_thumbnail_info(post: &Post) -> (String, PathBuf) {
        let media_filename = post
            .media_filename_opt
            .as_ref()
            .expect("media_filename is some");
        let extension_pattern = Regex::new(r"\.[^\.]+$").expect("build extension regex pattern");
        let thumbnail_filename =
            String::from("tn_") + &extension_pattern.replace(media_filename, ".webp");
        let thumbnail_path = std::path::Path::new(MEDIA_DIR)
            .join(&post.key)
            .join(&thumbnail_filename);
        (thumbnail_filename, thumbnail_path)
    }

    pub fn thumbnail_is_larger(thumbnail_path: &PathBuf, published_media_path: &PathBuf) -> bool {
        let thumbnail_len = thumbnail_path.metadata().unwrap().len();
        let media_file_len = published_media_path.metadata().unwrap().len();
        thumbnail_len > media_file_len
    }

    pub fn delete_upload_key_dir(encrypted_media_path: &PathBuf) {
        let uploads_key_dir = encrypted_media_path.parent().unwrap();
        std::fs::remove_file(&encrypted_media_path).expect("remove encrypted media file");
        std::fs::remove_dir(&uploads_key_dir).expect("remove uploads key dir");
    }

    pub fn delete_media_key_dir(key: &str) {
        let media_key_dir = std::path::Path::new(MEDIA_DIR).join(key);
        std::fs::remove_dir_all(&media_key_dir).expect("remove media key dir and its contents");
    }

    pub async fn insert(&self, tx: &mut PgConnection, account_id: i32, post_id: i32) {
        sqlx::query("INSERT INTO reviews (account_id, post_id, status) VALUES ($1, $2, $3)")
            .bind(account_id)
            .bind(post_id)
            .bind(&self.status)
            .execute(&mut *tx)
            .await
            .expect("insert post review");
    }

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
            Pending => match self.status {
                Pending => Err(SameStatus),
                Approved | Delisted => Ok(DecryptMedia),
                Reported => Ok(NoAction),
                Rejected | Banned => Ok(DeleteEncryptedMedia),
            },
            Approved | Delisted => {
                if post.status == Approved
                    && *reviewer_role == Mod
                    && !post.recent_opt.expect("recent is some")
                {
                    return Err(RecentOnly);
                }
                match self.status {
                    Pending => Err(ReturnToPending),
                    Approved | Delisted => Ok(NoAction),
                    Reported => {
                        if *reviewer_role != Mod {
                            return Err(ModOnly);
                        }
                        Ok(ReencryptMedia)
                    }
                    Rejected | Banned => Ok(DeletePublishedMedia),
                }
            }
            Reported => {
                if *reviewer_role != Admin {
                    return Err(AdminOnly);
                }
                match self.status {
                    Pending => Err(ReturnToPending),
                    Approved | Delisted => Ok(DecryptMedia),
                    Rejected | Banned => Ok(DeleteEncryptedMedia),
                    Reported => Err(SameStatus),
                }
            }
            Rejected | Banned => Err(RejectedOrBanned),
        }
    }

    pub async fn handle_decrypt_media(tx: &mut PgConnection, post: &Post) -> Result<(), String> {
        let media_bytes = post.decrypt_media_file().await;
        let published_media_path = post.published_media_path();
        Self::write_media_file(&published_media_path, media_bytes);
        if post
            .media_category_opt
            .as_ref()
            .is_some_and(|c| *c == MediaCategory::Image)
        {
            Self::generate_thumbnail(&published_media_path).await;
            let (thumbnail_filename, thumbnail_path) = Self::new_thumbnail_info(&post);
            if !thumbnail_path.exists() {
                return Err("thumbnail not created successfully".to_owned());
            }
            if Self::thumbnail_is_larger(&thumbnail_path, &published_media_path) {
                std::fs::remove_file(&thumbnail_path).expect("remove thumbnail file");
            } else {
                post.update_thumbnail(tx, &thumbnail_filename).await;
            }
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn body_to_html() {
        let submission = PostSubmission {
            body: concat!(
                "<&test body\"' コンピューター\n\n",
                "https://example.com\n",
                " https://m.youtube.com/watch?v=jNQXAC9IVRw\n",
                "https://youtu.be/kixirmHePCc?si=q9OkPEWRQ0RjoWg&t=3\n",
                "http://youtube.com/shorts/cHMCGCWit6U?si=q9OkPEWRQ0RjoWg \n",
                "https://example.com?m.youtube.com/watch?v=jNQXAC9IVRw\n",
                "foo https://www.youtube.com/watch?v=ySrBS4ulbmQ&t=2m1s\n\n",
                "https://www.youtube.com/watch?v=ySrBS4ulbmQ bar\n",
                "https://www.youtube.com/watch?t=10s&app=desktop&v=28jr-6-XDPM",
            )
            .to_owned(),
            ..Default::default()
        };
        let test_ids = ["jNQXAC9IVRw", "kixirmHePCc", "cHMCGCWit6U", "28jr-6-XDPM"];
        let mut existing_ids = Vec::new();
        for id in test_ids {
            if std::path::Path::new(YOUTUBE_DIR).join(id).exists() {
                existing_ids.push(id);
            }
        }
        let key = "testkey1";
        assert_eq!(
            submission.body_to_html(key),
            concat!(
                "&lt;&amp;test body&quot;&apos; コンピューター\n",
                "<br>\n",
                "<br>\n",
                "<a href=\"https://example.com\">https://example.com</a>\n",
                "<br>\n",
                "<div class=\"youtube\">\n",
                "    <div class=\"logo\">\n",
                "        <a href=\"https://www.youtube.com/watch?v=jNQXAC9IVRw\">\n",
                "            <img src=\"/youtube.svg\" alt>\n",
                "        </a>\n",
                "    </div>\n",
                "    <a href=\"/post/testkey1\">\n",
                "        <img src=\"/youtube/jNQXAC9IVRw/hqdefault.jpg\"",
                " alt=\"YouTube jNQXAC9IVRw\">\n",
                "    </a>\n",
                "</div>\n",
                "<br>\n",
                "<div class=\"youtube\">\n",
                "    <div class=\"logo\">\n",
                "        <a href=\"https://www.youtube.com/watch?v=kixirmHePCc&amp;t=3\">\n",
                "            <img src=\"/youtube.svg\" alt>\n",
                "        </a>\n",
                "    </div>\n",
                "    <a href=\"/post/testkey1\">\n",
                "        <img src=\"/youtube/kixirmHePCc/maxresdefault.jpg\"",
                " alt=\"YouTube kixirmHePCc\">\n",
                "    </a>\n",
                "</div>\n",
                "<br>\n",
                "<div class=\"youtube\">\n",
                "    <div class=\"logo\">\n",
                "        <a href=\"https://www.youtube.com/shorts/cHMCGCWit6U\">\n",
                "            <img src=\"/youtube.svg\" alt>\n",
                "        </a>\n",
                "    </div>\n",
                "    <a href=\"/post/testkey1\">\n",
                "        <img src=\"/youtube/cHMCGCWit6U/oar2.jpg\"",
                " alt=\"YouTube cHMCGCWit6U\">\n",
                "    </a>\n",
                "</div>\n",
                "<br>\n",
                "<a href=\"https://example.com?m.youtube.com/watch?v=jNQXAC9IVRw\">",
                "https://example.com?m.youtube.com/watch?v=jNQXAC9IVRw",
                "</a>\n",
                "<br>\n",
                "foo ",
                "<a href=\"https://www.youtube.com/watch?v=ySrBS4ulbmQ&amp;t=2m1s\">",
                "https://www.youtube.com/watch?v=ySrBS4ulbmQ&amp;t=2m1s",
                "</a>\n",
                "<br>\n",
                "<br>\n",
                "<a href=\"https://www.youtube.com/watch?v=ySrBS4ulbmQ\">",
                "https://www.youtube.com/watch?v=ySrBS4ulbmQ",
                "</a> bar\n",
                "<br>\n",
                "<div class=\"youtube\">\n",
                "    <div class=\"logo\">\n",
                "        <a href=\"https://www.youtube.com/watch?v=28jr-6-XDPM&amp;t=10s\">\n",
                "            <img src=\"/youtube.svg\" alt>\n",
                "        </a>\n",
                "    </div>\n",
                "    <a href=\"/post/testkey1\">\n",
                "        <img src=\"/youtube/28jr-6-XDPM/hqdefault.jpg\"",
                " alt=\"YouTube 28jr-6-XDPM\">\n",
                "    </a>\n",
                "</div>",
            )
        );
        for id in test_ids {
            if !existing_ids.contains(&id) {
                std::fs::remove_dir_all(std::path::Path::new(YOUTUBE_DIR).join(id))
                    .expect("remove dir and its contents");
            }
        }
    }

    #[tokio::test]
    async fn intro_limit() {
        let two_youtubes = concat!(
            "<div class=\"youtube\">\n    <div class=\"logo\">foo</div>bar</div>",
            "<div class=\"youtube\">\n    <div class=\"logo\">baz</div>quux</div>",
        );
        let html = str::repeat("<br>", MAX_INTRO_BREAKS + 1) + two_youtubes;
        assert_eq!(PostSubmission::intro_limit(&html), Some(96));
        let html = two_youtubes.to_owned() + &str::repeat("<br>", MAX_INTRO_BREAKS + 1);
        assert_eq!(PostSubmission::intro_limit(&html), Some(62));
        let html = str::repeat("foo ", 300);
        assert_eq!(PostSubmission::intro_limit(&html), None);
        let html = str::repeat("foo ", 100)
            + "<br>"
            + &str::repeat("bar ", 200)
            + "<br>"
            + &str::repeat("baz ", 100);
        assert_eq!(PostSubmission::intro_limit(&html), Some(1204));
        let html = str::repeat("x", MAX_INTRO_BYTES - 2) + " yy";
        assert_eq!(PostSubmission::intro_limit(&html), Some(1598));
        let html = str::repeat("x", MAX_INTRO_BYTES) + " y";
        assert_eq!(PostSubmission::intro_limit(&html), Some(1599));
        let html = str::repeat("x", MAX_INTRO_BYTES - 2) + "&quot;";
        assert_eq!(PostSubmission::intro_limit(&html), Some(1598));
        let html = str::repeat("x", MAX_INTRO_BYTES - 2) + "コ";
        assert_eq!(PostSubmission::intro_limit(&html), Some(1598));
    }
}
