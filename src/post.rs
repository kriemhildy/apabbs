#[derive(sqlx::FromRow, serde::Serialize)]
pub struct Post {
    pub id: i32,
    pub body: String,
    pub user_id: Option<i32>,
    pub status: String,
}

#[derive(serde::Deserialize)]
pub struct PostInput {
    pub body: String,
}

use sqlx::PgConnection;

impl PostInput {
    pub async fn insert(&self, tx: &mut PgConnection, user_id: Option<i32>) -> i32 {
        sqlx::query_scalar("INSERT INTO posts (body, user_id) VALUES ($1, $2) RETURNING id")
            .bind(&self.body)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .expect("insert new post")
    }
}

impl Post {
    pub async fn select_latest_approved(tx: &mut PgConnection) -> Vec<Post> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE status = 'approved' ORDER BY id DESC LIMIT 100",
        ))
        .fetch_all(&mut *tx)
        .await
        .expect("select latest 100 posts")
    }

    pub async fn select_latest_admin(tx: &mut PgConnection) -> Vec<Post> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE status <> 'rejected' ORDER BY id DESC LIMIT 100",
        ))
        .fetch_all(&mut *tx)
        .await
        .expect("select latest 100 posts")
    }
}
