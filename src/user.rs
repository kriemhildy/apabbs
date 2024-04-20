#[derive(sqlx::FromRow, serde::Serialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub token: String,
    pub password_hash: String,
    pub password_salt: String,
    pub admin: bool,
}

#[derive(serde::Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

use sqlx::PgConnection;

impl User {
    pub async fn select_by_token(tx: &mut PgConnection, token: &str) -> Option<User> {
        sqlx::query_as("SELECT * FROM users WHERE token = $1")
            .bind(token)
            .fetch_optional(&mut *tx)
            .await
            .expect("select user by token")
    }

    pub async fn select_by_username(tx: &mut PgConnection, username: &str) -> Option<User> {
        sqlx::query_as("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&mut *tx)
            .await
            .expect("select user by username")
    }
}

// PHC salt string used in password hashing
use argon2::password_hash::SaltString;

use crate::{valerr, ValidationError};

impl Credentials {
    pub async fn validate(&self, tx: &mut PgConnection) -> Result<(), Vec<ValidationError>> {
        let mut errors: Vec<ValidationError> = Vec::new();
        // maybe rework this to check for case sensitivity
        if User::select_by_username(tx, &self.username).await.is_some() {
            valerr!(errors, "username is already taken");
        }
        let pattern = regex::Regex::new(r"^\w{4,16}$").expect("build regex pattern");
        if !pattern.is_match(&self.username) {
            valerr!(errors, "username must be within 4 to 16 word characters");
        }
        if !(8..=64).contains(&self.password.len()) {
            valerr!(errors, "password must be within 8 to 64 chars");
        }
        let lowercase_username = self.username.to_lowercase();
        let lowercase_password = self.password.to_lowercase();
        if lowercase_password.contains(&lowercase_username) {
            valerr!(errors, "password cannot contain username");
        }
        match errors.is_empty() {
            true => Ok(()),
            false => Err(errors),
        }
    }

    fn generate_phc_salt_string() -> SaltString {
        use argon2::password_hash::rand_core::OsRng;
        SaltString::generate(&mut OsRng)
    }

    fn convert_b64_salt(b64_salt: &str) -> SaltString {
        SaltString::from_b64(b64_salt).expect("convert B64 str to PHC SaltString")
    }

    fn hash_password(password: &str, phc_salt_string: &SaltString) -> String {
        // resources used:
        // modern rust hashing guide: https://www.lpalmieri.com/posts/password-authentication-in-rust/
        // argon2 docs: https://docs.rs/argon2/latest/argon2/
        use argon2::{password_hash::PasswordHasher, Algorithm, Argon2, Params, Version};
        let password = password.as_bytes();

        // Argon2 with OWASP params
        let params = Params::new(15000, 2, 1, None).expect("build Argon2 params");
        let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // Hash password to PHC string ($argon2id$v=19$...)
        let password_hash = hasher
            .hash_password(password, phc_salt_string)
            .expect("hash password");
        password_hash.to_string()
    }

    pub async fn register(&self, tx: &mut PgConnection) -> User {
        let phc_salt_string = Credentials::generate_phc_salt_string();
        let password_hash = Credentials::hash_password(&self.password, &phc_salt_string);
        sqlx::query_as(concat!(
            "INSERT INTO users (username, password_hash, password_salt) ",
            "VALUES ($1, $2, $3) RETURNING *"
        ))
        .bind(&self.username)
        .bind(password_hash)
        .bind(phc_salt_string.as_str()) // converts PHC SaltString to B64 str
        .fetch_one(&mut *tx)
        .await
        .expect("insert a new registered user")
    }

    pub async fn authenticate(&self, tx: &mut PgConnection) -> Option<User> {
        let user = match User::select_by_username(tx, &self.username).await {
            Some(user) => user,
            None => return None,
        };
        let phc_salt_string = Credentials::convert_b64_salt(&user.password_salt);
        let input_password_hash = Credentials::hash_password(&self.password, &phc_salt_string);
        match user.password_hash == input_password_hash {
            true => Some(user),
            false => None,
        }
    }
}
