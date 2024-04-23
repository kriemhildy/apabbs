#[derive(sqlx::FromRow, serde::Serialize)]
pub struct Post {
    pub id: i32,
    pub body: String,
    pub user_id: Option<i32>,
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

    pub async fn select_latest_as_user(tx: &mut PgConnection, user_id: i32) -> Vec<Post> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE status = 'approved' OR user_id = $1 ",
            "ORDER BY id DESC LIMIT 100"
        ))
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .expect("select latest 100 posts as user")
    }

    pub async fn select_latest_as_admin(tx: &mut PgConnection) -> Vec<Post> {
        sqlx::query_as("SELECT * FROM posts WHERE status <> 'rejected' ORDER BY id DESC LIMIT 100")
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
