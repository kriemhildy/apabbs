//! User authentication and account management functionality.
//!
//! Utilities for user registration, authentication, credentials validation, and account management.
//! Handles both anonymous and registered users through a session-based system.

use crate::utils::{POSTGRES_HTML_DATETIME, POSTGRES_RFC5322_DATETIME};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::error::Error;
use uuid::Uuid;

/// The number of iterations used for Blowfish password hashing.
pub const BLOWFISH_ITERATIONS: i32 = 10;

/// Role-based access control for user accounts.
///
/// Defines the access level and permissions of a user within the system.
#[derive(sqlx::Type, Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
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

/// Information about the user's browser, used for feature detection.
#[derive(Serialize)]
pub struct UserAgent {
    /// True if the browser is running on macOS.
    pub mac: bool,
    /// True if the browser is based on Chromium (e.g., Chrome, Brave, Edge).
    pub chromium: bool,
}

/// Represents a user in the system, either anonymous or authenticated.
///
/// Contains the user's session token and optional account information.
#[derive(Serialize, Default)]
pub struct User {
    /// The user's account details if they are logged in
    pub account: Option<Account>,
    /// Unique token for identifying the user's session
    pub session_token: Uuid,
    /// Hash of IP address for flood and abuse protection
    pub ip_hash: String,
    /// Browser information for feature detection
    pub agent: Option<UserAgent>,
    /// Expiration time of the user's ban, if applicable
    pub ban_expires_at: Option<String>,
}

impl User {
    /// Returns true if the user is a moderator or administrator.
    pub fn mod_or_admin(&self) -> bool {
        self.account
            .as_ref()
            .is_some_and(|a| [AccountRole::Admin, AccountRole::Mod].contains(&a.role))
    }

    /// Returns true if the user is an administrator.
    pub fn admin(&self) -> bool {
        self.account
            .as_ref()
            .is_some_and(|a| a.role == AccountRole::Admin)
    }

    /// Gets the user's preferred time zone, or "UTC" for anonymous users.
    pub fn time_zone(&self) -> &str {
        match self.account {
            Some(ref account) => &account.time_zone,
            None => "UTC",
        }
    }
}

/// Represents a registered user account in the system.
///
/// Contains all account details including credentials and preferences.
#[derive(sqlx::FromRow, Serialize, Default, Clone)]
pub struct Account {
    pub id: i32,
    pub username: String,
    pub token: Uuid,
    pub password_hash: String,
    pub role: AccountRole,
    pub time_zone: String,
    #[sqlx(default)]
    pub created_at_rfc5322: Option<String>,
    #[sqlx(default)]
    pub created_at_html: Option<String>,
}

impl Account {
    /// Retrieves an account by its authentication token.
    pub async fn select_by_token(
        tx: &mut PgConnection,
        token: &Uuid,
    ) -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        sqlx::query_as("SELECT * FROM accounts WHERE token = $1")
            .bind(token)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| format!("failed to select account by token: {e}").into())
    }

    /// Retrieves an account by username, with formatted timestamps.
    pub async fn select_by_username(
        tx: &mut PgConnection,
        username: &str,
    ) -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        sqlx::query_as(concat!(
            "SELECT *, to_char(created_at, $1) AS created_at_rfc5322, ",
            "to_char(created_at, $2) AS created_at_html ",
            "FROM accounts WHERE username = $3",
        ))
        .bind(POSTGRES_RFC5322_DATETIME)
        .bind(POSTGRES_HTML_DATETIME)
        .bind(username)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("failed to select account by username: {e}").into())
    }

    /// Generates and assigns a new authentication token for the account.
    pub async fn reset_token(
        &self,
        tx: &mut PgConnection,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        sqlx::query("UPDATE accounts SET token = gen_random_uuid() WHERE id = $1")
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .map(|_| ())
            .map_err(|e| format!("failed to reset account token: {e}").into())
    }
}

/// Represents a request to update a user's time zone preference.
#[derive(Serialize, Deserialize)]
pub struct TimeZoneUpdate {
    pub session_token: Uuid,
    pub time_zone: String,
}

impl TimeZoneUpdate {
    /// Retrieves a list of all valid time zones from the database.
    pub async fn select_time_zones(
        tx: &mut PgConnection,
    ) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
        sqlx::query_scalar(concat!(
            "SELECT name FROM pg_timezone_names ",
            "WHERE name !~ '^(posix|Etc)' AND (name LIKE '%/%' OR name = 'UTC') ",
            "ORDER BY name"
        ))
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("failed to select time zones: {e}").into())
    }

    /// Updates the time zone setting for a user account.
    pub async fn update(
        &self,
        tx: &mut PgConnection,
        account_id: i32,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        sqlx::query("UPDATE accounts SET time_zone = $1 WHERE id = $2")
            .bind(&self.time_zone)
            .bind(account_id)
            .execute(&mut *tx)
            .await
            .map(|_| ())
            .map_err(|e| format!("failed to update time zone: {e}").into())
    }
}

/// Represents user credentials for registration or authentication.
#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub session_token: Uuid,
    pub username: String,
    pub password: String,
    #[serde(rename = "confirm_password")]
    pub confirm_password: Option<String>,
    #[serde(rename = "year")]
    pub year: Option<String>,
}

impl Credentials {
    /// Checks if a username already exists in the database.
    pub async fn username_exists(
        &self,
        tx: &mut PgConnection,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE username = $1)")
            .bind(&self.username)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| format!("failed to check if username exists: {e}").into())
    }

    /// Validates the credentials for registration.
    ///
    /// Performs checks on username and password format, reserved names, and confirmation.
    pub fn validate(&self) -> Vec<&str> {
        use regex::Regex;

        let mut errors: Vec<&str> = Vec::new();

        // Validate username format
        let pattern = Regex::new(r"^\w{4,16}$").expect("builds regex");
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
        if lowercase_password.contains(&lowercase_username) && !lowercase_username.is_empty() {
            errors.push("password cannot contain username");
        }

        // Check for common password patterns
        if lowercase_password.contains("password") {
            errors.push(r#"password cannot contain "password""#);
        }

        // Validate password confirmation
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

    /// Registers a new user account in the database.
    pub async fn register(
        &self,
        tx: &mut PgConnection,
        ip_hash: &str,
    ) -> Result<Account, Box<dyn Error + Send + Sync>> {
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
        .map_err(|e| format!("failed to register account: {e}").into())
    }

    /// Authenticates a user with the provided credentials.
    pub async fn authenticate(
        &self,
        tx: &mut PgConnection,
    ) -> Result<Option<Account>, Box<dyn Error + Send + Sync>> {
        sqlx::query_as(concat!(
            "SELECT * FROM accounts WHERE username = $1 ",
            "AND crypt($2, password_hash) = password_hash"
        ))
        .bind(&self.username)
        .bind(&self.password)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("failed to authenticate: {e}").into())
    }

    /// Updates the password for an existing account.
    pub async fn update_password(
        &self,
        tx: &mut PgConnection,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        sqlx::query(concat!(
            "UPDATE accounts SET password_hash = crypt($1, gen_salt('bf', $2)) ",
            "WHERE username = $3"
        ))
        .bind(&self.password)
        .bind(BLOWFISH_ITERATIONS)
        .bind(&self.username)
        .execute(&mut *tx)
        .await
        .map(|_| ())
        .map_err(|e| format!("failed to update password: {e}").into())
    }

    /// Returns true if the year verification checkbox was checked.
    pub fn year_checked(&self) -> bool {
        matches!(self.year.as_deref(), Some("on"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to set both password and confirmation fields.
    fn set_password_and_confirmation(credentials: &mut Credentials, password: &str) {
        credentials.password = password.to_string();
        credentials.confirm_password = Some(password.to_string());
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
            username: "username".to_string(),
            password: "passw0rd".to_string(),
            confirm_password: Some("passw0rd".to_string()),
            year: None,
        };

        // Valid initial credentials
        assert_eq!(credentials.validate().len(), 0);

        // Test username requirements
        credentials.username = "bob".to_string();
        assert_eq!(credentials.validate().len(), 1);

        credentials.username = "bob_the_magical_genius".to_string();
        assert_eq!(credentials.validate().len(), 1);

        credentials.username = "bob cool".to_string();
        assert_eq!(credentials.validate().len(), 1);

        credentials.username = "anon".to_string();
        assert_eq!(credentials.validate().len(), 1);

        credentials.username = "anon1".to_string();
        assert_eq!(credentials.validate().len(), 0);

        // Test password requirements
        credentials.username = "username".to_string();
        set_password_and_confirmation(&mut credentials, "passw0r");
        assert_eq!(credentials.validate().len(), 1);

        set_password_and_confirmation(&mut credentials, "username1");
        assert_eq!(credentials.validate().len(), 1);

        set_password_and_confirmation(&mut credentials, "UserName1");
        assert_eq!(credentials.validate().len(), 1);

        set_password_and_confirmation(&mut credentials, "passw0rd");
        assert_eq!(credentials.validate().len(), 0);

        // Test password confirmation
        credentials.confirm_password = Some("pass".to_string());
        assert_eq!(credentials.validate().len(), 1);

        credentials.confirm_password = Some("passw0rd".to_string());
        assert_eq!(credentials.validate().len(), 0);

        // Test common password patterns
        set_password_and_confirmation(&mut credentials, "password1");
        assert_eq!(credentials.validate().len(), 1);

        // Test multiple validation errors
        credentials.username = "password".to_string();
        assert_eq!(credentials.validate().len(), 2);
    }

    /// Tests the User helper methods for permission checking
    #[tokio::test]
    async fn user_permission_checks() {
        // Define a constant for the New York time zone
        const NEW_YORK: &str = "America/New_York";

        // Test anonymous user
        let anon_user = User::default();

        assert!(!anon_user.mod_or_admin());
        assert!(!anon_user.admin());
        assert_eq!(anon_user.time_zone(), "UTC");

        // Test novice user
        let novice_user = User {
            account: Some(Account {
                role: AccountRole::Novice,
                time_zone: NEW_YORK.to_string(),
                ..Account::default()
            }),
            ..User::default()
        };

        assert!(!novice_user.mod_or_admin());
        assert!(!novice_user.admin());
        assert_eq!(novice_user.time_zone(), NEW_YORK);

        // Test mod user
        let mod_user = User {
            account: Some(Account {
                role: AccountRole::Mod,
                ..Account::default()
            }),
            ..User::default()
        };

        assert!(mod_user.mod_or_admin());
        assert!(!mod_user.admin());

        // Test admin user
        let admin_user = User {
            account: Some(Account {
                role: AccountRole::Admin,
                ..novice_user.account.as_ref().unwrap().clone()
            }),
            ..User::default()
        };

        assert!(admin_user.mod_or_admin());
        assert!(admin_user.admin());
    }

    /// Tests the year_checked method of Credentials
    #[tokio::test]
    async fn year_checkbox_validation() {
        let mut credentials = Credentials {
            session_token: Uuid::new_v4(),
            username: "username".to_string(),
            password: "password123".to_string(),
            confirm_password: Some("password123".to_string()),
            year: None,
        };

        // Test default state (unchecked)
        assert!(!credentials.year_checked());

        // Test with year checked
        credentials.year = Some("on".to_string());
        assert!(credentials.year_checked());

        // Test with incorrect value
        credentials.year = Some("yes".to_string());
        assert!(!credentials.year_checked());
    }
}
