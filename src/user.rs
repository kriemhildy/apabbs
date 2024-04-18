#[derive(sqlx::FromRow, serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
#[sqlx(default)]
pub struct User {
    pub id: i32,
    pub name: String,
    #[sqlx(skip)]
    pub password: String,
    #[serde(skip)]
    pub token: String,
    #[serde(skip)]
    pub password_hash: String,
    #[serde(skip)]
    pub password_salt: String,
}

use argon2::password_hash::SaltString;
use sqlx::PgConnection;

impl User {
    pub async fn select(tx: &mut PgConnection, token: &str) -> Option<User> {
        sqlx::query_as("SELECT * FROM users WHERE token = $1")
            .bind(token)
            .fetch_optional(&mut *tx)
            .await
            .expect("select user by token")
    }

    pub async fn name_taken(&self, tx: &mut PgConnection) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE name = $1)")
            .bind(self.name.as_str())
            .fetch_one(&mut *tx)
            .await
            .expect("selects whether username exists")
    }

    pub fn acceptable_password(&self) -> bool {
        let lowercase_name = self.name.to_lowercase();
        let lowercase_password = self.password.to_lowercase();
        self.password.len() >= 8 && !lowercase_password.contains(lowercase_name.as_str())
    }

    fn argon2_salt_string(b64_salt: Option<&str>) -> SaltString {
        use argon2::password_hash::rand_core::OsRng;
        match b64_salt {
            Some(salt) => SaltString::from_b64(salt).expect("convert str to Argon2 SaltString"),
            None => SaltString::generate(&mut OsRng),
        }
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
        // time zone? utc? password encryption?
        // maybe don't bother with registered_at because we should have a separate
        // 'actions' table (or equivalent) that tracks ip and registrations/logins/logouts.
        // we need a reversable encryption system too (just in case) for stuff like IP maybe.
        let argon2_salt_string = User::argon2_salt_string(None);
        let password_hash = User::hash_password(self.password.as_str(), &argon2_salt_string);
        sqlx::query_as(concat!(
            "INSERT INTO users (name, password_hash, password_salt) ",
            "VALUES ($1, $2, $3) RETURNING *"
        ))
        .bind(self.name.as_str())
        .bind(password_hash)
        .bind(argon2_salt_string.as_str())
        .fetch_one(&mut *tx)
        .await
        .expect("inserts a new registered user")
    }

    pub async fn authenticate(&self, tx: &mut PgConnection) -> Option<User> {
        let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE name = $1")
            .bind(self.name.as_str())
            .fetch_optional(&mut *tx)
            .await
            .expect("selects user based on name");
        if user.is_none() {
            return None;
        }
        let user = user.expect("extract user");
        let input_password = self.password.as_str();
        let b64_salt = user.password_salt.as_str();
        let argon2_salt_string = User::argon2_salt_string(Some(b64_salt));
        let input_password_hash = User::hash_password(input_password, &argon2_salt_string);
        if user.password_hash == input_password_hash {
            Some(user)
        } else {
            None
        }
    }
}
