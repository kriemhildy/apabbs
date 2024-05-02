use crate::{
    crypto,
    validation::{val, ValidationError},
};
use sqlx::PgConnection;

pub fn is_admin(user: &Option<User>) -> bool {
    user.as_ref().is_some_and(|u| u.admin)
}

#[derive(sqlx::FromRow, serde::Serialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub token: String,
    pub password_hash: String,
    pub password_salt: String,
    pub admin: bool,
}

impl User {
    pub async fn select_by_token(tx: &mut PgConnection, token: &str) -> Option<Self> {
        sqlx::query_as("SELECT * FROM users WHERE token = $1")
            .bind(token)
            .fetch_optional(&mut *tx)
            .await
            .expect("select user by token")
    }
}

#[derive(serde::Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl Credentials {
    pub async fn username_exists(&self, tx: &mut PgConnection) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)")
            .bind(&self.username)
            .fetch_one(&mut *tx)
            .await
            .expect("select whether username exists")
    }

    pub fn validate(&self) -> Result<(), Vec<ValidationError>> {
        let mut errors: Vec<ValidationError> = Vec::new();
        let pattern = regex::Regex::new(r"^\w{4,16}$").expect("build regex pattern");
        if !pattern.is_match(&self.username) {
            val!(errors, "username must be 4 to 16 word characters");
        }
        if !(8..=64).contains(&self.password.len()) {
            val!(errors, "password must be 8 to 64 chars");
        }
        let lowercase_username = self.username.to_lowercase();
        let lowercase_password = self.password.to_lowercase();
        if lowercase_password.contains(&lowercase_username) {
            val!(errors, "password cannot contain username");
        }
        match errors.is_empty() {
            true => Ok(()),
            false => Err(errors),
        }
    }

    pub async fn register(&self, tx: &mut PgConnection, ip_hash: &str) -> User {
        let phc_salt_string = crypto::generate_phc_salt_string();
        let password_hash = crypto::hash_password(&self.password, &phc_salt_string);
        let password_salt = phc_salt_string.as_str();
        sqlx::query_as(concat!(
            "INSERT INTO users (username, password_hash, password_salt, ip_hash) ",
            "VALUES ($1, $2, $3, $4) RETURNING *"
        ))
        .bind(&self.username)
        .bind(password_hash)
        .bind(password_salt)
        .bind(ip_hash)
        .fetch_one(&mut *tx)
        .await
        .expect("insert a new registered user")
    }

    pub async fn authenticate(&self, tx: &mut PgConnection) -> Option<User> {
        let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE username = $1")
            .bind(&self.username)
            .fetch_optional(&mut *tx)
            .await
            .expect("select user by username");
        if user.is_none() {
            return None;
        }
        let user = user.unwrap();
        let phc_salt_string = crypto::convert_b64_salt(&user.password_salt);
        let input_password_hash = crypto::hash_password(&self.password, &phc_salt_string);
        match user.password_hash == input_password_hash {
            true => Some(user),
            false => None,
        }
    }
}
