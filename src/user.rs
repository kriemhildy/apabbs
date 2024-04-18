#[derive(sqlx::FromRow, serde::Serialize)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub token: String,
    pub password_hash: String,
    pub password_salt: String,
}

#[derive(serde::Deserialize)]
pub struct Credentials {
    pub username: String,
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
}

// PHC salt string used in password hashing
use argon2::password_hash::SaltString;

impl Credentials {
    pub async fn username_taken(&self, tx: &mut PgConnection) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE name = $1)")
            .bind(&self.username)
            .fetch_one(&mut *tx)
            .await
            .expect("selects whether username exists")
    }

    pub fn acceptable_username(&self) -> bool {
        use regex::Regex;
        let pattern = Regex::new(r"^\w{4,16}$").expect("build regex pattern");
        pattern.is_match(&self.username)
    }

    pub fn acceptable_password(&self) -> bool {
        let lowercase_username = self.username.to_lowercase();
        let lowercase_password = self.password.to_lowercase();
        self.password.len() >= 8 && !lowercase_password.contains(&lowercase_username)
    }

    fn generate_phc_salt_string() -> SaltString {
        use argon2::password_hash::rand_core::OsRng;
        SaltString::generate(&mut OsRng)
    }

    fn convert_b64_salt(b64_salt: &str) -> SaltString {
        SaltString::from_b64(b64_salt).expect("convert B64 str to PHC SaltString")
    }

    fn hash_password(password: &str, salt_string: &SaltString) -> String {
        // resources used:
        // modern rust hashing guide: https://www.lpalmieri.com/posts/password-authentication-in-rust/
        // argon2 docs: https://docs.rs/argon2/latest/argon2/
        use argon2::{password_hash::PasswordHasher, Algorithm, Argon2, Params, Version};
        let password = password.as_bytes();

        // Argon2 with OWASP params
        let hasher = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).expect("build Argon2 params"),
        );

        // Hash password to PHC string ($argon2id$v=19$...)
        let password_hash = hasher
            .hash_password(password, salt_string)
            .expect("hashes password");
        password_hash.to_string()
    }

    pub async fn register(&self, tx: &mut PgConnection) -> User {
        let phc_salt_string = Credentials::generate_phc_salt_string();
        let password_hash = Credentials::hash_password(&self.password, &phc_salt_string);
        sqlx::query_as(concat!(
            "INSERT INTO users (name, password_hash, password_salt) ",
            "VALUES ($1, $2, $3) RETURNING *"
        ))
        .bind(&self.username)
        .bind(password_hash)
        .bind(phc_salt_string.as_str()) // converts PHC SaltString to B64 str
        .fetch_one(&mut *tx)
        .await
        .expect("inserts a new registered user")
    }

    pub async fn authenticate(&self, tx: &mut PgConnection) -> Option<User> {
        let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE name = $1")
            .bind(&self.username)
            .fetch_optional(&mut *tx)
            .await
            .expect("selects user based on name");
        if user.is_none() {
            return None;
        }
        let user = user.expect("extract user");
        let phc_salt_string = Credentials::convert_b64_salt(&user.password_salt);
        let input_password_hash = Credentials::hash_password(&self.password, &phc_salt_string);
        if user.password_hash == input_password_hash {
            Some(user)
        } else {
            None
        }
    }
}
