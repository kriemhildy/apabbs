#[derive(sqlx::FromRow, serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
pub struct Post {
    pub id: i32,
    pub body: String,
    pub user_id: Option<i32>,
    #[serde(default = "default_anon")]
    pub anon: bool,
}

fn default_anon() -> bool {
    true
}

use sqlx::PgConnection;

impl Post {
    // pub async fn select(tx: &mut PgConnection, token: &str) -> Option<User> {
    //     sqlx::query_as("SELECT * FROM users WHERE token = $1")
    //         .bind(token)
    //         .fetch_optional(&mut *tx)
    //         .await
    //         .expect("select user by token")
    // }

    // pub async fn insert(tx: &mut PgConnection) -> User {
    //     sqlx::query_as("INSERT INTO users DEFAULT VALUES RETURNING *")
    //         .fetch_one(&mut *tx)
    //         .await
    //         .expect("insert default user")
    // }

    // posts that are unapproved should probably wait in a separate queue before
    // being added to the official posts table. alternatively, we can use published_at
    // instead of id.
    pub async fn select_latest_approved_100(tx: &mut PgConnection) -> Vec<Post> {
        sqlx::query_as("SELECT * FROM posts ORDER BY id DESC LIMIT 100")
            .fetch_all(&mut *tx)
            .await
            .expect("select latest 100 posts")
    }

    pub async fn insert(self, tx: &mut PgConnection, user_id: i32) -> i32 {
        sqlx::query_scalar("INSERT INTO posts (body) VALUES ($1) RETURNING id")
            .bind(self.body.as_str())
            .fetch_one(&mut *tx)
            .await
            .expect("insert new post")
    }
}