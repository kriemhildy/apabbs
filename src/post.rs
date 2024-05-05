use crate::user::{Account, User};
use sqlx::PgConnection;

fn convert_to_html(input: &str) -> String {
    input
        .trim()
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br>\n")
}

#[derive(sqlx::Type, serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "post_status", rename_all = "snake_case")]
pub enum PostStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(sqlx::FromRow, serde::Serialize, Clone, Debug)]
pub struct Post {
    pub id: i32,
    pub body: String,
    pub account_id: Option<i32>,
    pub username: Option<String>, // cache
    pub anon_uuid: Option<String>,
    pub anon_hash: Option<String>, // cache
    pub status: PostStatus,
}

impl Post {
    async fn select_latest_as_anon(tx: &mut PgConnection, anon_uuid: &str) -> Vec<Self> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE (status = 'approved' OR anon_uuid = $1) ",
            "AND hidden = false ORDER BY id DESC LIMIT 100"
        ))
        .bind(anon_uuid)
        .fetch_all(&mut *tx)
        .await
        .expect("select latest posts as anon")
    }

    async fn select_latest_as_account(tx: &mut PgConnection, account: &Account) -> Vec<Self> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE (status = 'approved' OR account_id = $1) ",
            "AND hidden = false ORDER BY id DESC LIMIT 100"
        ))
        .bind(account.id)
        .fetch_all(&mut *tx)
        .await
        .expect("select latest posts as account")
    }

    async fn select_latest_as_admin(tx: &mut PgConnection, account: &Account) -> Vec<Self> {
        sqlx::query_as(concat!(
            "SELECT * FROM posts WHERE (status <> 'rejected' OR account_id = $1) ",
            "AND hidden = false ORDER BY id DESC LIMIT 100"
        ))
        .bind(account.id)
        .fetch_all(&mut *tx)
        .await
        .expect("select latest posts as admin")
    }

    pub async fn select_latest(tx: &mut PgConnection, user: &User) -> Vec<Self> {
        match &user.account {
            Some(account) => match account.admin {
                true => Post::select_latest_as_admin(tx, &account).await,
                false => Post::select_latest_as_account(tx, &account).await,
            },
            None => Post::select_latest_as_anon(tx, &user.anon_uuid).await,
        }
    }

    pub async fn select(tx: &mut PgConnection, id: i32) -> Option<Self> {
        sqlx::query_as("SELECT * FROM posts WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .expect("select post by id")
    }

    pub fn authored_by(&self, user: &User) -> bool {
        match &user.account {
            Some(account) => self.account_id.is_some_and(|id| id == account.id),
            None => self
                .anon_uuid
                .as_ref()
                .is_some_and(|uuid| uuid == &user.anon_uuid),
        }
    }
}

#[derive(serde::Deserialize)]
pub struct PostSubmission {
    pub body: String,
}

impl PostSubmission {
    async fn insert_as_account(
        &self,
        tx: &mut PgConnection,
        account: &Account,
        ip_hash: &str,
    ) -> Post {
        sqlx::query_as(concat!(
            "INSERT INTO posts (body, account_id, username, ip_hash) ",
            "VALUES ($1, $2, $3, $4) RETURNING *",
        ))
        .bind(convert_to_html(&self.body))
        .bind(account.id)
        .bind(&account.username)
        .bind(ip_hash)
        .fetch_one(&mut *tx)
        .await
        .expect("insert new post as account")
    }

    async fn insert_as_anon(
        &self,
        tx: &mut PgConnection,
        anon_uuid: &str,
        anon_hash: &str,
        ip_hash: &str,
    ) -> Post {
        sqlx::query_as(concat!(
            "INSERT INTO posts (body, anon_uuid, anon_hash, ip_hash) ",
            "VALUES ($1, $2, $3, $4) RETURNING *",
        ))
        .bind(convert_to_html(&self.body))
        .bind(anon_uuid)
        .bind(anon_hash)
        .bind(ip_hash)
        .fetch_one(&mut *tx)
        .await
        .expect("insert new post as anon")
    }

    pub async fn insert(&self, tx: &mut PgConnection, user: User, ip_hash: &str) -> Post {
        match user.account {
            Some(account) => self.insert_as_account(tx, &account, &ip_hash).await,
            None => {
                self.insert_as_anon(tx, &user.anon_uuid, &user.anon_hash(), &ip_hash)
                    .await
            }
        }
    }
}

#[derive(serde::Deserialize)]
pub struct PostReview {
    pub id: i32,
    pub status: String,
}

impl PostReview {
    pub async fn update_status(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE posts SET status = $1::post_status WHERE id = $2")
            .bind(&self.status)
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("update post status");
    }
}

#[derive(serde::Deserialize)]
pub struct PostHiding {
    pub id: i32,
}

impl PostHiding {
    pub async fn hide_post(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE posts SET hidden = true WHERE id = $1")
            .bind(self.id)
            .execute(&mut *tx)
            .await
            .expect("set hidden flag to true");
    }
}

#[derive(Clone, Debug)]
pub struct PostMessage {
    pub post: Post,
    pub html: String,
}
