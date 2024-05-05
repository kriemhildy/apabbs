use crate::user::User;
use sqlx::{PgConnection, Postgres, QueryBuilder};

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
    pub async fn select_latest(tx: &mut PgConnection, user: &User) -> Vec<Self> {
        let mut query_builder: QueryBuilder<Postgres> =
            QueryBuilder::new("SELECT * FROM posts WHERE (");
        match &user.account {
            Some(account) => {
                match account.admin {
                    true => query_builder.push("status <> 'rejected' "),
                    false => query_builder.push("status = 'approved' "),
                };
                query_builder.push("OR account_id = ");
                query_builder.push_bind(account.id);
            }
            None => {
                query_builder.push("status = 'approved' OR anon_uuid = ");
                query_builder.push_bind(&user.anon_uuid);
            }
        }
        query_builder.push(") AND hidden = false ORDER BY id DESC LIMIT 100");
        query_builder
            .build_query_as()
            .fetch_all(&mut *tx)
            .await
            .expect("select latest posts")
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
    pub async fn insert(&self, tx: &mut PgConnection, user: User, ip_hash: &str) -> Post {
        let mut query_builder: QueryBuilder<Postgres> = QueryBuilder::new("INSERT INTO posts (");
        query_builder.push(match &user.account {
            Some(_account) => "account_id, username",
            None => "anon_uuid, anon_hash",
        });
        query_builder.push(", body, ip_hash) VALUES (");
        let mut separated = query_builder.separated(", ");
        match user.account {
            Some(account) => {
                separated.push_bind(account.id);
                separated.push_bind(account.username);
            }
            None => {
                separated.push_bind(&user.anon_uuid);
                separated.push_bind(user.anon_hash());
            }
        }
        query_builder.push(", $3, $4) RETURNING *");
        query_builder
            .build_query_as()
            .bind(&self.body_as_html())
            .bind(ip_hash)
            .fetch_one(&mut *tx)
            .await
            .expect("insert new post")
    }

    fn body_as_html(&self) -> String {
        self.body
            .trim()
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br>\n")
    }
}

#[derive(serde::Deserialize)]
pub struct PostReview {
    pub id: i32,
    pub status: PostStatus,
}

impl PostReview {
    pub async fn update_status(&self, tx: &mut PgConnection) {
        sqlx::query("UPDATE posts SET status = $1 WHERE id = $2")
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
