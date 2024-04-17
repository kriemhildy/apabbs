#[derive(sqlx::FromRow, serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
pub struct User {
    pub id: i32,
    pub name: Option<String>,
    #[serde(skip)]
    pub token: String,
    #[sqlx(skip)]
    pub password: String,
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

    pub async fn name_taken(tx: &mut PgConnection, name: &str) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE name = $1")
            .bind(name)
            .fetch_one(&mut *tx)
            .await
            .expect("selects whether username exists")
    }

    pub fn acceptable_password(name: &str, password: &str) -> bool {
        let lowercase_name = name.to_lowercase();
        let lowercase_password = password.to_lowercase();
        password.len() >= 8
        && !lowercase_password.contains(lowercase_name.as_str())
    }

    pub async fn register(&self, tx: &mut PgConnection, name: &str, password: &str) -> User {
        // time zone? utc? password encryption?
        sqlx::query_as(concat!(
            "UPDATE users SET name = $1, encrypted_password = $2, ",
            "registered_at = now() WHERE id = $3 RETURNING *"
        ))
        .bind(name)
        .bind(password)
        .bind(self.id)
        .fetch_one(&mut *tx)
        .await
        .expect("updates user name, encrypted_password, and registered_at")
    }
}
