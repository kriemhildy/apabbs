#[derive(sqlx::FromRow, serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
pub struct Post {
    pub id: i32,
    pub body: String,
    pub user_id: Option<i32>,
}

use sqlx::PgConnection;

impl Post {
    // posts that are unapproved should probably wait in a separate queue before
    // being added to the official posts table. alternatively, we can use published_at
    // instead of id.
    pub async fn select_latest_approved_100(tx: &mut PgConnection) -> Vec<Post> {
        sqlx::query_as("SELECT * FROM posts ORDER BY id DESC LIMIT 100")
            .fetch_all(&mut *tx)
            .await
            .expect("select latest 100 posts")
    }

    pub async fn insert(self, tx: &mut PgConnection, user_id_option: Option<i32>) -> i32 {
        sqlx::query_scalar("INSERT INTO posts (body, user_id) VALUES ($1, $2) RETURNING id")
            .bind(self.body.as_str())
            .bind(user_id_option)
            .fetch_one(&mut *tx)
            .await
            .expect("insert new post")
    }
}
