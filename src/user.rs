#[derive(sqlx::FromRow, serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
#[sqlx(default)]
pub struct User {
    pub id: i32,
    pub name: Option<String>,
    #[sqlx(skip)]
    pub password: String,
    #[serde(skip)]
    pub token: String,
    #[serde(skip)]
    pub password_hash: String,
    #[serde(skip)]
    pub password_salt: String,
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

    pub async fn name_taken(tx: &mut PgConnection, name: &str) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE name = $1)")
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

    fn hash_password(password: &str, input_salt: Option<&str>) -> (String, String) {
        // resources used:
        // modern rust hashing guide: https://www.lpalmieri.com/posts/password-authentication-in-rust/
        // argon2 docs: https://docs.rs/argon2/latest/argon2/
        use argon2::{
            password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
            Algorithm, Argon2, Params, Version,
        };
        let password = password.as_bytes();
        let output_salt = match input_salt {
            Some(salt) => SaltString::from_b64(salt).expect("convert str to SaltString"),
            None => SaltString::generate(&mut OsRng),
        };

        // Argon2 with OWASP params
        let hasher = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).expect("build Argon2 params"),
        );

        // Hash password to PHC string ($argon2id$v=19$...)
        let password_hash = hasher
            .hash_password(password, &output_salt)
            .expect("hashes password");
        (password_hash.to_string(), output_salt.to_string())
    }

    pub async fn register(tx: &mut PgConnection, name: &str, password: &str) -> User {
        // time zone? utc? password encryption?
        // maybe don't bother with registered_at because we should have a separate
        // 'actions' table (or equivalent) that tracks ip and registrations/logins/logouts.
        // we need a reversable encryption system too (just in case) for stuff like IP maybe.
        let (password_hash, salt) = User::hash_password(password, None);
        sqlx::query_as(concat!(
            "INSERT INTO users (name, password_hash, password_salt) ",
            "VALUES ($1, $2, $3) RETURNING *"
        ))
        .bind(name)
        .bind(password_hash)
        .bind(salt)
        .fetch_one(&mut *tx)
        .await
        .expect("inserts a new registered user")
    }

    pub async fn authenticate(&self, tx: &mut PgConnection) -> Option<User> {
        let username = self.name.clone().expect("read username");
        let user_option: Option<User> = sqlx::query_as("SELECT * FROM users WHERE name = $1")
            .bind(username.as_str())
            .fetch_optional(&mut *tx)
            .await
            .expect("selects user based on name");
        if user_option.is_none() {
            return None;
        }
        let user = user_option.expect("extract user");
        let password = self.password.as_str();
        let input_salt = user.password_salt.as_str();
        let (password_hash, _output_salt) = User::hash_password(password, Some(input_salt));
        if user.password_hash == password_hash {
            Some(user)
        } else {
            None
        }
    }
}
