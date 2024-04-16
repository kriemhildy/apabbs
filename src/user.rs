#[derive(sqlx::FromRow, serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
pub struct User {
    pub id: i32,
    pub name: String,
    #[serde(skip)]
    pub token: String,
    #[sqlx(skip)]
    pub password: String,
    #[sqlx(skip)]
    pub password_confirmation: String,
}

use sqlx::PgConnection;

impl User {
    pub async fn select(tx: &mut PgConnection, token: &str) -> Option<User> {
        sqlx::query_as("SELECT * FROM users WHERE token = $1")
            .bind(token)
            .fetch_optional(&mut *tx)
            .await
            .expect("select user by token")
    }

    pub async fn insert_anon(tx: &mut PgConnection) -> User {
        sqlx::query_as("INSERT INTO users DEFAULT VALUES RETURNING *")
            .fetch_one(&mut *tx)
            .await
            .expect("insert default user")
    }
}
