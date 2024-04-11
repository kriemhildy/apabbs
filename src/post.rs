#[derive(sqlx::FromRow, serde::Serialize)]
pub struct Post {
    pub id: i32,
    pub body: String,
    pub user_id: Option<i32>,
    pub anon: bool,
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
}
