use crate::crypto;
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

    pub async fn set_session_time_zone(&self, tx: &mut PgConnection) {
        // cannot pass $1 variables to this command, but the value should be safe
        sqlx::query(&format!("SET TIME ZONE '{}'", self.time_zone()))
            .execute(&mut *tx)
            .await
            .expect("set time zone");
    }
}

#[derive(sqlx::FromRow, serde::Serialize)]
pub struct Account {
    pub id: i32,
    pub username: String,
    pub token: Uuid,
    pub password_hash: String,
    pub password_salt: String,
    pub admin: bool,
    pub anon: bool,
    pub time_zone: String,
}

impl Account {
    pub async fn select_by_token(tx: &mut PgConnection, token: &Uuid) -> Option<Self> {
        sqlx::query_as("SELECT * FROM accounts WHERE token = $1")
            .bind(token)
            .fetch_optional(&mut *tx)
            .await
            .expect("select account by token")
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
pub struct Credentials {
    pub username: String,
    pub password: String,
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
        errors
    }

    pub async fn register(&self, tx: &mut PgConnection, ip_hash: &str) -> Account {
        let phc_salt_string = crypto::generate_phc_salt_string();
        let password_hash = crypto::hash_password(&self.password, &phc_salt_string);
        let password_salt = phc_salt_string.as_str();
        sqlx::query_as(concat!(
            "INSERT INTO accounts (username, password_hash, password_salt, ip_hash) ",
            "VALUES ($1, $2, $3, $4) RETURNING *"
        ))
        .bind(&self.username)
        .bind(password_hash)
        .bind(password_salt)
        .bind(ip_hash)
        .fetch_one(&mut *tx)
        .await
        .expect("insert a new registered account")
    }

    pub async fn authenticate(&self, tx: &mut PgConnection) -> Option<Account> {
        let account: Option<Account> = sqlx::query_as("SELECT * FROM accounts WHERE username = $1")
            .bind(&self.username)
            .fetch_optional(&mut *tx)
            .await
            .expect("select account by username");
        let account = match account {
            Some(account) => account,
            None => return None,
        };
        let phc_salt_string = crypto::convert_b64_salt(&account.password_salt);
        let input_password_hash = crypto::hash_password(&self.password, &phc_salt_string);
        match account.password_hash == input_password_hash {
            true => Some(account),
            false => None,
        }
    }
}
