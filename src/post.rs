#[derive(sqlx::FromRow, serde::Serialize)]
pub struct PostDisplay {
    pub id: i32,
    pub body: String,
    pub user_id: Option<i32>,
    pub username: Option<String>,
    pub anon_hash: Option<String>,
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

impl PostDisplay {
    pub async fn select_latest_as_anon(tx: &mut PgConnection, anon_uuid: &str) -> Vec<PostDisplay> {
        sqlx::query_as(concat!(
            "SELECT posts.id, posts.body, posts.status, posts.user_id, users.username, ",
            "left(encode(sha256(posts.anon_uuid::bytea), 'hex'), 6) AS anon_hash FROM posts ",
            "LEFT OUTER JOIN users ON users.id = posts.user_id ",
            "WHERE posts.status = 'approved' OR posts.anon_uuid = $1 ",
            "ORDER BY id DESC LIMIT 100"
        ))
        .bind(anon_uuid)
        .fetch_all(&mut *tx)
        .await
        .expect("select latest 100 posts as anon")
    }

    pub async fn select_latest_as_user(tx: &mut PgConnection, user_id: i32) -> Vec<PostDisplay> {
        sqlx::query_as(concat!(
            "SELECT posts.id, posts.body, posts.status, posts.user_id, users.username, ",
            "left(encode(sha256(posts.anon_uuid::bytea), 'hex'), $2) AS anon_hash FROM posts ",
            "LEFT OUTER JOIN users ON users.id = posts.user_id ",
            "WHERE posts.status = 'approved' OR posts.user_id = $1 ",
            "ORDER BY posts.id DESC LIMIT 100"
        ))
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .expect("select latest 100 posts as user")
    }

    pub async fn select_latest_as_admin(tx: &mut PgConnection) -> Vec<PostDisplay> {
        sqlx::query_as(concat!(
            "SELECT posts.id, posts.body, posts.status, posts.user_id, users.username, ",
            "left(encode(sha256(posts.anon_uuid::bytea), 'hex'), 6) AS anon_hash FROM posts ",
            "LEFT OUTER JOIN users ON users.id = posts.user_id ",
            "WHERE posts.status <> 'rejected' ",
            "ORDER BY posts.id DESC LIMIT 100"
        ))
        .fetch_all(&mut *tx)
        .await
        .expect("select latest 100 posts as admin")
    }
}

impl PostSubmission {
    pub async fn insert_as_user(&self, tx: &mut PgConnection, user_id: i32) -> i32 {
        sqlx::query_scalar("INSERT INTO posts (body, user_id) VALUES ($1, $2) RETURNING id")
            .bind(&self.body)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .expect("insert new post as user")
    }

    pub async fn insert_as_anon(&self, tx: &mut PgConnection, anon_uuid: &str) -> i32 {
        sqlx::query_scalar("INSERT INTO posts (body, anon_uuid) VALUES ($1, $2) RETURNING id")
            .bind(&self.body)
            .bind(anon_uuid)
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
