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

use sqlx::PgConnection;
use crate::User;

impl Post {
    pub async fn select_latest_as_anon(tx: &mut PgConnection, anon_uuid: &str) -> Vec<Post> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE status = 'approved' OR anon_uuid = $1 ",
            "ORDER BY id DESC LIMIT 100"
        ))
        .bind(anon_uuid)
        .fetch_all(&mut *tx)
        .await
        .expect("select latest 100 posts as anon")
    }

    pub async fn select_latest_as_user(tx: &mut PgConnection, user: &User) -> Vec<Post> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE status = 'approved' OR user_id = $1 ",
            "ORDER BY id DESC LIMIT 100"
        ))
        .bind(user.id)
        .fetch_all(&mut *tx)
        .await
        .expect("select latest 100 posts as user")
    }

    pub async fn select_latest_as_admin(tx: &mut PgConnection) -> Vec<Post> {
        sqlx::query_as(
            "SELECT * FROM posts WHERE status <> 'rejected' ORDER BY id DESC LIMIT 100"
        )
        .fetch_all(&mut *tx)
        .await
        .expect("select latest 100 posts as admin")
    }

    pub fn anon_hash(anon_uuid: &str) -> String {
        sha256::digest(anon_uuid)[..8].to_owned()
    }
}

impl PostSubmission {
    pub async fn insert_as_user(&self, tx: &mut PgConnection, user: User) -> i32 {
        sqlx::query_scalar("INSERT INTO posts (body, user_id, username) VALUES ($1, $2, $3) RETURNING id")
            .bind(&self.body)
            .bind(user.id)
            .bind(user.username)
            .fetch_one(&mut *tx)
            .await
            .expect("insert new post as user")
    }

    pub async fn insert_as_anon(&self, tx: &mut PgConnection, anon_uuid: &str) -> i32 {
        sqlx::query_scalar(concat!(
            "INSERT INTO posts (body, anon_uuid, anon_hash) VALUES ($1, $2, $3) RETURNING id"
        ))
            .bind(&self.body)
            .bind(anon_uuid)
            .bind(Post::anon_hash(anon_uuid))
            .fetch_one(&mut *tx)
            .await
            .expect("insert new post as anon")
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
