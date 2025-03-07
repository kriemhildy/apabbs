use crate::POSTGRES_TIMESTAMP_FORMAT;
use regex::Regex;
use sqlx::PgConnection;
use uuid::Uuid;

const BLOWFISH_ITERATIONS: i32 = 10;

#[derive(sqlx::Type, serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "account_role", rename_all = "snake_case")]
pub enum AccountRole {
    Novice,
    Member,
    Mod,
    Admin,
}

#[derive(serde::Serialize)]
pub struct User {
    pub account: Option<Account>,
    pub session_token: Uuid,
}

impl User {
    pub fn mod_or_admin(&self) -> bool {
        self.account
            .as_ref()
            .is_some_and(|a| [AccountRole::Admin, AccountRole::Mod].contains(&a.role))
    }

    pub fn time_zone(&self) -> &str {
        match self.account {
            Some(ref account) => &account.time_zone,
            None => "UTC",
        }
    }
}

#[derive(sqlx::FromRow, serde::Serialize)]
pub struct Account {
    pub id: i32,
    pub username: String,
    pub token: Uuid,
    pub password_hash: String,
    pub role: AccountRole,
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

    pub async fn reset_token(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE accounts SET token = gen_random_uuid() WHERE id = $1")
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("update account token");
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct TimeZoneUpdate {
    pub session_token: Uuid,
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

    pub async fn update(&self, tx: &mut PgConnection, account_id: i32) {
        sqlx::query("UPDATE accounts SET time_zone = $1 WHERE id = $2")
            .bind(&self.time_zone)
            .bind(account_id)
            .execute(&mut *tx)
            .await
            .expect("update time zone");
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Credentials {
    pub session_token: Uuid,
    pub username: String,
    pub password: String,
    pub confirm_password: Option<String>,
    pub year: Option<String>,
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
        if lowercase_password.contains("password") {
            errors.push(r#"password cannot contain "password""#);
        }
        match self.confirm_password {
            None => errors.push("password confirmation is required"),
            Some(ref confirm_password) => {
                if &self.password != confirm_password {
                    errors.push("passwords do not match");
                }
            }
        }
        errors
    }

    pub async fn register(&self, tx: &mut PgConnection, ip_hash: &str) -> Account {
        sqlx::query_as(concat!(
            "INSERT INTO accounts (username, password_hash, ip_hash) ",
            "VALUES ($1, crypt($2, gen_salt('bf', $3)), $4) RETURNING *"
        ))
        .bind(&self.username)
        .bind(&self.password)
        .bind(BLOWFISH_ITERATIONS)
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
            "UPDATE accounts SET password_hash = crypt($1, gen_salt('bf', $2)) ",
            "WHERE username = $3"
        ))
        .bind(&self.password)
        .bind(BLOWFISH_ITERATIONS)
        .bind(&self.username)
        .execute(&mut *tx)
        .await
        .expect("update password");
    }

    pub fn year_checked(&self) -> bool {
        match self.year {
            Some(ref year) => year == "on",
            None => false,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Logout {
    pub session_token: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_password_and_confirmation(credentials: &mut Credentials, password: &str) {
        credentials.password = password.to_owned();
        credentials.confirm_password = Some(password.to_owned());
    }

    #[test]
    fn validate_credentials() {
        let mut credentials = Credentials {
            session_token: Uuid::new_v4(),
            username: "username".to_owned(),
            password: "passw0rd".to_owned(),
            confirm_password: Some("passw0rd".to_owned()),
            year: None,
        };
        assert_eq!(credentials.validate().len(), 0);
        credentials.username = "bob".to_owned();
        assert_eq!(credentials.validate().len(), 1);
        credentials.username = "bob_the_magical_genius".to_owned();
        assert_eq!(credentials.validate().len(), 1);
        credentials.username = "bob cool".to_owned();
        assert_eq!(credentials.validate().len(), 1);
        credentials.username = "username".to_owned();
        set_password_and_confirmation(&mut credentials, "passw0r");
        assert_eq!(credentials.validate().len(), 1);
        set_password_and_confirmation(&mut credentials, "username1");
        assert_eq!(credentials.validate().len(), 1);
        set_password_and_confirmation(&mut credentials, "UserName1");
        assert_eq!(credentials.validate().len(), 1);
        set_password_and_confirmation(&mut credentials, "passw0rd");
        assert_eq!(credentials.validate().len(), 0);
        credentials.confirm_password = Some("pass".to_owned());
        assert_eq!(credentials.validate().len(), 1);
        credentials.confirm_password = Some("passw0rd".to_owned());
        assert_eq!(credentials.validate().len(), 0);
        set_password_and_confirmation(&mut credentials, "password1");
        assert_eq!(credentials.validate().len(), 1);
        credentials.username = "password".to_owned();
        assert_eq!(credentials.validate().len(), 2);
    }
}
