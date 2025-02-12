use crate::POSTGRES_TIMESTAMP_FORMAT;
use regex::Regex;
use sqlx::PgConnection;
use uuid::Uuid;

pub struct User {
    pub account: Option<Account>,
    pub anon_token: Uuid,
}

impl User {
    pub fn admin(&self) -> bool {
        self.account.as_ref().is_some_and(|a| a.admin)
    }

    pub fn anon_hash(&self) -> String {
        sha256::digest(&self.anon_token.to_string())[..8].to_owned()
    }

    pub fn username(&self) -> Option<&str> {
        match &self.account {
            Some(account) => Some(&account.username),
            None => None,
        }
    }

    pub fn anon(&self) -> bool {
        match &self.account {
            Some(account) => account.anon,
            None => true,
        }
    }

    pub fn time_zone(&self) -> &str {
        match &self.account {
            Some(account) => &account.time_zone,
            None => "UTC",
        }
    }

    pub async fn update_anon(mut self, tx: &mut PgConnection, anon: bool) -> Self {
        self.account = match self.account {
            Some(mut account) => {
                if account.anon != anon {
                    account.anon = anon;
                    account.update_anon(tx, anon).await;
                }
                Some(account)
            }
            None => None,
        };
        self
    }
}

#[derive(sqlx::FromRow, serde::Serialize)]
pub struct Account {
    pub id: i32,
    pub username: String,
    pub token: Uuid,
    pub password_hash: String,
    pub admin: bool,
    pub anon: bool,
    pub time_zone: String,
    #[sqlx(default)]
    pub created_at_str: Option<String>,
}

impl Account {
    pub async fn select_by_token(tx: &mut PgConnection, token: &Uuid) -> Option<Self> {
        sqlx::query_as("SELECT * FROM accounts WHERE token = $1")
            .bind(token)
            .fetch_optional(&mut *tx)
            .await
            .expect("select account by token")
    }

    pub async fn select_by_username(tx: &mut PgConnection, username: &str) -> Option<Self> {
        sqlx::query_as(concat!(
            "SELECT *, to_char(created_at, $1) AS created_at_str ",
            "FROM accounts WHERE username = $2",
        ))
        .bind(POSTGRES_TIMESTAMP_FORMAT)
        .bind(username)
        .fetch_optional(&mut *tx)
        .await
        .expect("select account by username")
    }

    pub async fn update_anon(&self, tx: &mut PgConnection, anon: bool) {
        sqlx::query("UPDATE accounts SET anon = $1 WHERE id = $2")
            .bind(anon)
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("update anon bool");
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct TimeZoneUpdate {
    pub username: String,
    pub time_zone: String,
}

impl TimeZoneUpdate {
    pub async fn select_time_zones(tx: &mut PgConnection) -> Vec<String> {
        sqlx::query_scalar(concat!(
            "SELECT name FROM pg_timezone_names ",
            "WHERE name !~ '^(posix|Etc)' AND (name LIKE '%/%' OR name = 'UTC') ",
            "ORDER BY name"
        ))
        .fetch_all(&mut *tx)
        .await
        .expect("select distinct time zones")
    }

    pub async fn update(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE accounts SET time_zone = $1 WHERE username = $2")
            .bind(&self.time_zone)
            .bind(&self.username)
            .execute(&mut *tx)
            .await
            .expect("update time zone");
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub confirm_password: Option<String>,
}

impl Credentials {
    pub async fn username_exists(&self, tx: &mut PgConnection) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE username = $1)")
            .bind(&self.username)
            .fetch_one(&mut *tx)
            .await
            .expect("select whether username exists")
    }

    pub fn validate(&self) -> Vec<&str> {
        let mut errors: Vec<&str> = Vec::new();
        let pattern = Regex::new(r"^\w{4,16}$").expect("build regex pattern");
        if !pattern.is_match(&self.username) {
            errors.push("username must be 4 to 16 word characters");
        }
        if !(8..=64).contains(&self.password.len()) {
            errors.push("password must be 8 to 64 chars");
        }
        let lowercase_username = self.username.to_lowercase();
        let lowercase_password = self.password.to_lowercase();
        if lowercase_password.contains(&lowercase_username) {
            errors.push("password cannot contain username");
        }
        match &self.confirm_password {
            Some(confirm_password) => {
                if &self.password != confirm_password {
                    errors.push("passwords do not match");
                }
            }
            None => errors.push("password confirmation is required"),
        }
        errors
    }

    pub async fn register(&self, tx: &mut PgConnection, ip_hash: &str) -> Account {
        sqlx::query_as(concat!(
            "INSERT INTO accounts (username, password_hash, ip_hash) ",
            "VALUES ($1, crypt($2, gen_salt('bf', 10)), $3) RETURNING *"
        ))
        .bind(&self.username)
        .bind(&self.password)
        .bind(ip_hash)
        .fetch_one(&mut *tx)
        .await
        .expect("insert a new registered account")
    }

    pub async fn authenticate(&self, tx: &mut PgConnection) -> Option<Account> {
        sqlx::query_as(concat!(
            "SELECT * FROM accounts WHERE username = $1 ",
            "AND crypt($2, password_hash) = password_hash"
        ))
        .bind(&self.username)
        .bind(&self.password)
        .fetch_optional(&mut *tx)
        .await
        .expect("select account by username and password")
    }

    pub async fn update_password(&self, tx: &mut PgConnection) {
        sqlx::query(concat!(
            "UPDATE accounts SET password_hash = crypt($1, gen_salt('bf', 10)) ",
            "WHERE username = $2"
        ))
        .bind(&self.password)
        .bind(&self.username)
        .execute(&mut *tx)
        .await
        .expect("update password");
    }
}
