use crate::user::User;
use sqlx::{PgConnection, Postgres, QueryBuilder};

const APPLICATION_OCTET_STREAM: &'static str = "application/octet-stream";

#[derive(sqlx::Type, serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "post_status", rename_all = "snake_case")]
pub enum PostStatus {
    Pending,
    Approved,
    Rejected,
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
    pub anon_token: Option<String>,
    pub anon_hash: Option<String>, // cache
    pub status: PostStatus,
    pub uuid: String,
    pub media_file_name: Option<String>,
    pub media_category: Option<PostMediaCategory>,
    pub media_mime_type: Option<String>,
}

impl Post {
    pub async fn select_latest(
        tx: &mut PgConnection,
        user: &User,
        from_id: Option<i32>,
        limit: i32,
    ) -> Vec<Self> {
        let mut query_builder: QueryBuilder<Postgres> =
            QueryBuilder::new("SELECT * FROM posts WHERE (");
        match user.admin() {
            true => query_builder.push("status <> 'rejected' "),
            false => query_builder.push("status = 'approved' "),
        };
        query_builder.push("OR anon_token = ");
        query_builder.push_bind(&user.anon_token);
        match &user.account {
            Some(account) => {
                query_builder.push(" OR account_id = ");
                query_builder.push_bind(account.id);
            }
            None => (),
        }
        query_builder.push(") AND hidden = false ");
        if let Some(from_id) = from_id {
            query_builder.push("AND id <= ");
            query_builder.push_bind(from_id);
        }
        query_builder.push(" ORDER BY id DESC LIMIT ");
        query_builder.push_bind(limit);
        query_builder
            .build_query_as()
            .fetch_all(&mut *tx)
            .await
            .expect("select latest posts")
    }

    pub fn authored_by(&self, user: &User) -> bool {
        self.anon_token
            .as_ref()
            .is_some_and(|uuid| uuid == &user.anon_token)
            || user
                .account
                .as_ref()
                .is_some_and(|a| self.account_id.is_some_and(|id| id == a.id))
    }

    pub async fn select_by_uuid(tx: &mut PgConnection, uuid: &str) -> Option<Self> {
        sqlx::query_as("SELECT * FROM posts WHERE uuid = $1")
            .bind(uuid)
            .fetch_optional(&mut *tx)
            .await
            .expect("select post by uuid")
    }
}

pub struct PostSubmission {
    pub body: String,
    pub anon: Option<String>,
    pub media_file_name: Option<String>,
    pub uuid: String,
}

impl PostSubmission {
    pub async fn insert(&self, tx: &mut PgConnection, user: &User, ip_hash: &str) -> Post {
        let (media_category, media_mime_type) =
            Self::determine_media_type(self.media_file_name.as_deref());
        let mut query_builder: QueryBuilder<Postgres> = QueryBuilder::new("INSERT INTO posts (");
        query_builder.push(match user.anon() {
            true => "anon_token, anon_hash",
            false => "account_id, username",
        });
        query_builder.push(
            ", body, ip_hash, uuid, media_file_name, media_category, media_mime_type) VALUES (",
        );
        let mut separated = query_builder.separated(", ");
        match user.anon() {
            true => {
                separated.push_bind(&user.anon_token);
                separated.push_bind(user.anon_hash());
            }
            false => {
                let account = user.account.as_ref().unwrap();
                separated.push_bind(account.id);
                separated.push_bind(&account.username);
            }
        }
        query_builder.push(", $3, $4, $5, $6, $7, $8) RETURNING *");
        query_builder
            .build_query_as()
            .bind(&self.body_as_html())
            .bind(ip_hash)
            .bind(&self.uuid)
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
        let escaped = self
            .body
            .trim_end()
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br>\n")
            .replace("  ", " &nbsp;");
        let pattern = regex::Regex::new(r"(https?://\S+)").expect("build regex pattern");
        pattern
            .replace_all(&escaped, "<a href=\"$1\" target=\"_blank\">$1</a>")
            .to_string()
    }

    fn determine_media_type(
        media_file_name: Option<&str>,
    ) -> (Option<PostMediaCategory>, Option<String>) {
        if media_file_name.is_none() {
            return (None, None);
        }
        let media_file_name = media_file_name.unwrap();
        use PostMediaCategory::*;
        let path = std::path::Path::new(&media_file_name);
        let (media_category, media_mime_type_str) = match path.extension() {
            Some(ext_os_str) => {
                let ext_os_string = ext_os_str.to_ascii_lowercase();
                match ext_os_string.to_str() {
                    Some(ext_str) => match ext_str {
                        "jpg" | "jpeg" | "jpe" | "jfif" | "pjpeg" | "pjp" => {
                            (Some(Image), "image/jpeg")
                        }
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
                }
            }
            None => (None, APPLICATION_OCTET_STREAM),
        };
        (media_category, Some(media_mime_type_str.to_owned()))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PostReview {
    pub uuid: String,
    pub status: PostStatus,
}

impl PostReview {
    pub async fn update_status(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE posts SET status = $1 WHERE uuid = $2")
            .bind(&self.status)
            .bind(&self.uuid)
            .execute(&mut *tx)
            .await
            .expect("update post status");
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PostHiding {
    pub uuid: String,
}

impl PostHiding {
    pub async fn hide_post(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE posts SET hidden = true WHERE uuid = $1")
            .bind(&self.uuid)
            .execute(&mut *tx)
            .await
            .expect("set hidden flag to true");
    }
}

#[derive(Clone, Debug)]
pub struct PostMessage {
    pub post: Post,
    pub html: String,
}
