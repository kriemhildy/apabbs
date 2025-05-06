pub mod ban;
pub mod post;
pub mod user;

use sqlx::PgPool;

pub const BEGIN: &'static str = "begin transaction";
pub const COMMIT: &'static str = "commit transaction";
const POSTGRES_RFC5322_DATETIME: &'static str = "Dy, DD Mon YYYY HH24:MI:SS TZHTZM";
const POSTGRES_HTML_DATETIME: &'static str = r#"YYYY-MM-DD"T"HH24:MI:SS.FF3TZH:TZM""#;

pub async fn db() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("read DATABASE_URL env");
    PgPool::connect(&url).await.expect("connect postgres")
}

pub fn per_page() -> usize {
    match std::env::var("PER_PAGE") {
        Ok(per_page) => per_page.parse().expect("parse PER_PAGE env"),
        Err(_) => 1000,
    }
}

pub fn dev() -> bool {
    std::env::var("DEV").is_ok_and(|v| v == "1")
}

pub fn host() -> String {
    std::env::var("HOST").expect("read HOST env")
}

pub fn secret_key() -> String {
    std::env::var("SECRET_KEY").expect("read SECRET_KEY env")
}
