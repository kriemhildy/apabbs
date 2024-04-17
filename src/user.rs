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
        password.len() >= 8 && !lowercase_password.contains(lowercase_name.as_str())
    }

    fn encrypt_password(password: &str) -> (String, String) {
        // resources used:
        // modern rust hashing guide: https://www.lpalmieri.com/posts/password-authentication-in-rust/
        // argon2 docs: https://docs.rs/argon2/latest/argon2/
        use argon2::{
            password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
            Algorithm, Argon2, Params, Version,
        };
        let password = password.as_bytes();
        let salt = SaltString::generate(&mut OsRng);

        // Argon2 with OWASP params
        let hasher = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).expect("builds Argon2 params"),
        );

        // Hash password to PHC string ($argon2id$v=19$...)
        let password_hash = hasher
            .hash_password(password, &salt)
            .expect("hashes password");
        (password_hash.to_string(), salt.to_string())
    }

    pub async fn register(&self, tx: &mut PgConnection, name: &str, password: &str) -> User {
        // time zone? utc? password encryption?
        // maybe don't bother with registered_at because we should have a separate
        // 'actions' table (or equivalent) that tracks ip and registrations/logins/logouts.
        // we need a reversable encryption system too (just in case) for stuff like IP maybe.
        let (password_hash, salt) = User::encrypt_password(password);
        sqlx::query_as(concat!(
            "UPDATE users SET name = $1, password_hash = $2, salt = $3, ",
            "registered_at = now() WHERE id = $4 RETURNING *"
        ))
        .bind(name)
        .bind(password_hash)
        .bind(salt)
        .bind(self.id)
        .fetch_one(&mut *tx)
        .await
        .expect("updates user name, encrypted_password, and registered_at")
    }
}
