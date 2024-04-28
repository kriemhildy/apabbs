#[derive(sqlx::FromRow, serde::Serialize)]
pub struct Post {
    pub id: i32,
    pub body: String,
    pub user_id: Option<i32>,
    pub username: Option<String>, // cache
    pub anon_uuid: Option<String>,
    pub anon_hash: Option<String>, // cache
    pub status: String,
}

#[derive(serde::Deserialize)]
pub struct PostSubmission {
    pub body: String,
}

#[derive(serde::Deserialize)]
pub struct PostModeration {
    pub id: i32,
    pub status: String,
}

#[derive(serde::Deserialize)]
pub struct PostHiding {
    pub id: i32,
}

use crate::User;
use sqlx::PgConnection;

impl Post {
    pub async fn select_latest_as_anon(tx: &mut PgConnection, anon_uuid: &str) -> Vec<Post> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE (status = 'approved' OR anon_uuid = $1) ",
            "AND hidden = false ORDER BY id DESC LIMIT 100"
        ))
        .bind(anon_uuid)
        .fetch_all(&mut *tx)
        .await
        .expect("select latest 100 posts as anon")
    }

    pub async fn select_latest_as_user(tx: &mut PgConnection, user: &User) -> Vec<Post> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE (status = 'approved' OR user_id = $1) ",
            "AND hidden = false ORDER BY id DESC LIMIT 100"
        ))
        .bind(user.id)
        .fetch_all(&mut *tx)
        .await
        .expect("select latest 100 posts as user")
    }

    pub async fn select_latest_as_admin(tx: &mut PgConnection, user: &User) -> Vec<Post> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE (status <> 'rejected' OR user_id = $1) ",
            "AND hidden = false ORDER BY id DESC LIMIT 100"
        ))
        .bind(user.id)
        .fetch_all(&mut *tx)
        .await
        .expect("select latest 100 posts as admin")
    }

    pub async fn select(tx: &mut PgConnection, id: i32) -> Option<Post> {
        sqlx::query_as("SELECT * FROM posts WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .expect("select post by id")
    }
}

impl PostSubmission {
    pub async fn insert_as_user(&self, tx: &mut PgConnection, user: User, ip: &str) -> i32 {
        sqlx::query_scalar(concat!(
            "INSERT INTO posts (body, user_id, username, ip) ",
            "VALUES ($1, $2, $3, $4) RETURNING id",
        ))
        .bind(Self::convert_to_html(&self.body))
        .bind(user.id)
        .bind(user.username)
        .bind(ip)
        .fetch_one(&mut *tx)
        .await
        .expect("insert new post as user")
    }

    pub async fn insert_as_anon(&self, tx: &mut PgConnection, anon_uuid: &str, ip: &str) -> i32 {
        sqlx::query_scalar(concat!(
            "INSERT INTO posts (body, anon_uuid, anon_hash, ip) ",
            "VALUES ($1, $2, $3, $4) RETURNING id",
        ))
        .bind(Self::convert_to_html(&self.body))
        .bind(anon_uuid)
        .bind(Self::anon_hash(anon_uuid))
        .bind(ip)
        .fetch_one(&mut *tx)
        .await
        .expect("insert new post as anon")
    }

    pub fn anon_hash(anon_uuid: &str) -> String {
        sha256::digest(anon_uuid)[..8].to_owned()
    }

    fn convert_to_html(input: &str) -> String {
        input
            .trim()
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br>\n")
    }
}

impl PostModeration {
    pub async fn update_status(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE posts SET status = $1 WHERE id = $2")
            .bind(&self.status)
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("update post status");
    }
}

impl PostHiding {
    pub async fn hide_post(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE posts SET hidden = true WHERE id = $1")
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("set hidden flag to true");
    }
}
