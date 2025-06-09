//! User authentication and account management functionality.
//!
//! This module provides utilities for user registration, authentication,
//! credentials validation, and account management. It handles both anonymous
//! and registered users through a session-based system.
//!
//! # Key Types
//!
//! - [`User`]: Anonymous or authenticated user with session tracking
//! - [`Account`]: Registered user account with credentials and preferences
//! - [`AccountRole`]: Permission levels (Novice, Member, Mod, Admin)
//! - [`Credentials`]: User registration and login information
//! - [`TimeZoneUpdate`]: User time zone preference management
//! - [`Logout`]: Session termination request handler

use crate::{POSTGRES_HTML_DATETIME, POSTGRES_RFC5322_DATETIME};
use regex::Regex;
use sqlx::PgConnection;
use uuid::Uuid;

/// The number of iterations used for Blowfish password hashing.
const BLOWFISH_ITERATIONS: i32 = 10;

/// Role-based access control for user accounts.
///
/// Defines the access level and permissions of a user within the system.
#[derive(sqlx::Type, serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug, Default)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "account_role", rename_all = "snake_case")]
pub enum AccountRole {
    /// Basic user with limited privileges
    #[default]
    Novice,
    /// Regular user with standard privileges
    Member,
    /// Moderator with elevated access for content management
    Mod,
    /// Administrator with full system access
    Admin,
}

/// Represents a user in the system, either anonymous or authenticated.
///
/// Contains the user's session token and optional account information.
#[derive(serde::Serialize)]
pub struct User {
    /// The user's account details if they are logged in
    pub account_opt: Option<Account>,
    /// Unique token for identifying the user's session
    pub session_token: Uuid,
}

impl User {
    /// Checks if the user has moderator or administrator privileges.
    ///
    /// Returns `true` if the user is a moderator or administrator.
    pub fn mod_or_admin(&self) -> bool {
        self.account_opt
            .as_ref()
            .is_some_and(|a| [AccountRole::Admin, AccountRole::Mod].contains(&a.role))
    }

    /// Checks if the user has administrator privileges.
    ///
    /// Returns `true` if the user is an administrator.
    pub fn admin(&self) -> bool {
        self.account_opt
            .as_ref()
            .is_some_and(|a| a.role == AccountRole::Admin)
    }

    /// Gets the user's preferred time zone.
    ///
    /// Returns the account's time zone if logged in, or "UTC" for anonymous users.
    pub fn time_zone(&self) -> &str {
        match self.account_opt {
            Some(ref account) => &account.time_zone,
            None => "UTC",
        }
    }
}

/// Represents a registered user account in the system.
///
/// Contains all account details including credentials and preferences.
#[derive(sqlx::FromRow, serde::Serialize, Default)]
pub struct Account {
    /// Unique identifier for the account
    pub id: i32,
    /// Unique username for the account
    pub username: String,
    /// Authentication token for session management
    pub token: Uuid,
    /// Hashed password for secure storage
    pub password_hash: String,
    /// Access level and permissions for the account
    pub role: AccountRole,
    /// The user's preferred time zone
    pub time_zone: String,
    /// Account creation timestamp in RFC5322 format
    #[sqlx(default)]
    pub created_at_rfc5322_opt: Option<String>,
    /// Account creation timestamp in HTML format
    #[sqlx(default)]
    pub created_at_html_opt: Option<String>,
}

impl Account {
    /// Retrieves an account by its authentication token.
    ///
    /// Returns the account information if found, or None if no account matches the token.
    pub async fn select_by_token(tx: &mut PgConnection, token: &Uuid) -> Option<Self> {
        sqlx::query_as("SELECT * FROM accounts WHERE token = $1")
            .bind(token)
            .fetch_optional(&mut *tx)
            .await
            .expect("select account by token")
    }

    /// Retrieves an account by username.
    ///
    /// Returns the account information with formatted timestamps if found,
    /// or None if no account matches the username.
    pub async fn select_by_username(tx: &mut PgConnection, username: &str) -> Option<Self> {
        sqlx::query_as(concat!(
            "SELECT *, to_char(created_at, $1) AS created_at_rfc5322_opt, ",
            "to_char(created_at, $2) AS created_at_html_opt ",
            "FROM accounts WHERE username = $3",
        ))
        .bind(POSTGRES_RFC5322_DATETIME)
        .bind(POSTGRES_HTML_DATETIME)
        .bind(username)
        .fetch_optional(&mut *tx)
        .await
        .expect("select account by username")
    }

    /// Generates and assigns a new authentication token for the account.
    ///
    /// This is typically used for security purposes like logging out from all devices.
    pub async fn reset_token(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE accounts SET token = gen_random_uuid() WHERE id = $1")
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("update account token");
    }
}

/// Represents a request to update a user's time zone preference.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TimeZoneUpdate {
    /// Session token for authentication
    pub session_token: Uuid,
    /// New time zone to be set for the user
    pub time_zone: String,
}

impl TimeZoneUpdate {
    /// Retrieves a list of all valid time zones from the database.
    ///
    /// Returns a sorted list of time zone names that can be used by users.
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

    /// Updates the time zone setting for a user account.
    pub async fn update(&self, tx: &mut PgConnection, account_id: i32) {
        sqlx::query("UPDATE accounts SET time_zone = $1 WHERE id = $2")
            .bind(&self.time_zone)
            .bind(account_id)
            .execute(&mut *tx)
            .await
            .expect("update time zone");
    }
}

/// Represents user credentials for registration or authentication.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Credentials {
    /// Session token for the current user session
    pub session_token: Uuid,
    /// Username for registration or login
    pub username: String,
    /// Password for registration or login
    pub password: String,
    /// Password confirmation for registration
    #[serde(rename = "confirm_password")]
    pub confirm_password_opt: Option<String>,
    /// Age verification field (typically a checkbox)
    #[serde(rename = "year")]
    pub year_opt: Option<String>,
}

impl Credentials {
    /// Checks if a username already exists in the database.
    ///
    /// Returns true if the username is already taken.
    pub async fn username_exists(&self, tx: &mut PgConnection) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE username = $1)")
            .bind(&self.username)
            .fetch_one(&mut *tx)
            .await
            .expect("select whether username exists")
    }

    /// Validates the credentials for registration.
    ///
    /// Performs various checks on username and password:
    /// - Username format (4-16 word characters)
    /// - Password length (8-64 characters)
    /// - Reserved username check ("anon")
    /// - Password containing username check
    /// - Common password check ("password")
    /// - Password confirmation match
    ///
    /// Returns a list of error messages if validation fails.
    pub fn validate(&self) -> Vec<&str> {
        let mut errors: Vec<&str> = Vec::new();

        // Validate username format
        let pattern = Regex::new(r"^\w{4,16}$").expect("build regex pattern");
        if !pattern.is_match(&self.username) {
            errors.push("username must be 4 to 16 word characters");
        }

        // Validate password length
        if !(8..=64).contains(&self.password.len()) {
            errors.push("password must be 8 to 64 chars");
        }

        let lowercase_username = self.username.to_lowercase();
        let lowercase_password = self.password.to_lowercase();

        // Check for reserved username
        if lowercase_username == "anon" {
            errors.push("username cannot be \"anon\"");
        }

        // Check password doesn't contain username
        if lowercase_password.contains(&lowercase_username) {
            errors.push("password cannot contain username");
        }

        // Check for common password patterns
        if lowercase_password.contains("password") {
            errors.push(r#"password cannot contain "password""#);
        }

        // Validate password confirmation
        match self.confirm_password_opt {
            None => errors.push("password confirmation is required"),
            Some(ref confirm_password) => {
                if &self.password != confirm_password {
                    errors.push("passwords do not match");
                }
            }
        }

        errors
    }

    /// Registers a new user account in the database.
    ///
    /// Creates a new account with the provided credentials and IP hash.
    /// Automatically hashes the password for secure storage.
    ///
    /// Returns the newly created account.
    pub async fn register(&self, tx: &mut PgConnection, ip_hash: &str) -> Account {
        sqlx::query_as(concat!(
            "INSERT INTO accounts (username, password_hash, ip_hash_opt) ",
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

    /// Authenticates a user with the provided credentials.
    ///
    /// Returns the account if authentication is successful, or None if credentials are invalid.
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

    /// Updates the password for an existing account.
    ///
    /// Hashes the new password before storing it in the database.
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

    /// Checks if the year verification checkbox was checked.
    ///
    /// Returns true if the year field is present and set to "on".
    pub fn year_checked(&self) -> bool {
        match self.year_opt {
            Some(ref year) => year == "on",
            None => false,
        }
    }
}

/// Represents a logout request.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Logout {
    /// Session token to invalidate during logout
    pub session_token: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to set both password and confirmation fields.
    fn set_password_and_confirmation(credentials: &mut Credentials, password: &str) {
        credentials.password = password.to_owned();
        credentials.confirm_password_opt = Some(password.to_owned());
    }

    /// Tests the credential validation for various username and password combinations.
    ///
    /// Verifies:
    /// - Username length and format requirements
    /// - Password length requirements
    /// - Reserved username restrictions
    /// - Password containing username check
    /// - Common password patterns check
    /// - Password confirmation matching
    #[test]
    fn validate_credentials() {
        let mut credentials = Credentials {
            session_token: Uuid::new_v4(),
            username: "username".to_owned(),
            password: "passw0rd".to_owned(),
            confirm_password_opt: Some("passw0rd".to_owned()),
            year_opt: None,
        };

        // Valid initial credentials
        assert_eq!(credentials.validate().len(), 0);

        // Test username requirements
        credentials.username = "bob".to_owned();
        assert_eq!(credentials.validate().len(), 1);

        credentials.username = "bob_the_magical_genius".to_owned();
        assert_eq!(credentials.validate().len(), 1);

        credentials.username = "bob cool".to_owned();
        assert_eq!(credentials.validate().len(), 1);

        credentials.username = "anon".to_owned();
        assert_eq!(credentials.validate().len(), 1);

        credentials.username = "anon1".to_owned();
        assert_eq!(credentials.validate().len(), 0);

        // Test password requirements
        credentials.username = "username".to_owned();
        set_password_and_confirmation(&mut credentials, "passw0r");
        assert_eq!(credentials.validate().len(), 1);

        set_password_and_confirmation(&mut credentials, "username1");
        assert_eq!(credentials.validate().len(), 1);

        set_password_and_confirmation(&mut credentials, "UserName1");
        assert_eq!(credentials.validate().len(), 1);

        set_password_and_confirmation(&mut credentials, "passw0rd");
        assert_eq!(credentials.validate().len(), 0);

        // Test password confirmation
        credentials.confirm_password_opt = Some("pass".to_owned());
        assert_eq!(credentials.validate().len(), 1);

        credentials.confirm_password_opt = Some("passw0rd".to_owned());
        assert_eq!(credentials.validate().len(), 0);

        // Test common password patterns
        set_password_and_confirmation(&mut credentials, "password1");
        assert_eq!(credentials.validate().len(), 1);

        // Test multiple validation errors
        credentials.username = "password".to_owned();
        assert_eq!(credentials.validate().len(), 2);
    }
}
