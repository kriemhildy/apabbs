mod ban;
mod jobs;
mod post;
mod router;
mod user;

use minijinja::Environment;
use post::Post;
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast::Sender;

const BEGIN: &'static str = "begin transaction";
const COMMIT: &'static str = "commit transaction";
const POSTGRES_RFC5322_DATETIME: &'static str = "Dy, DD Mon YYYY HH24:MI:SS TZHTZM";
const POSTGRES_HTML_DATETIME: &'static str = r#"YYYY-MM-DD"T"HH24:MI:SS.FF3TZH:TZM""#;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    jinja: Arc<RwLock<Environment<'static>>>,
    sender: Arc<Sender<Post>>,
}

async fn db() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("read DATABASE_URL env");
    PgPool::connect(&url).await.expect("connect postgres")
}

fn dev() -> bool {
    std::env::var("DEV").is_ok_and(|v| v == "1")
}

fn per_page() -> usize {
    match std::env::var("PER_PAGE") {
        Ok(per_page) => per_page.parse().expect("parse PER_PAGE env"),
        Err(_) => 1000,
    }
}

fn site_name() -> String {
    format!(
        "{}{}",
        if dev() { "[dev] " } else { "" },
        std::env::var("SITE_NAME").expect("read SITE_NAME env")
    )
}

fn secret_key() -> String {
    std::env::var("SECRET_KEY").expect("read SECRET_KEY env")
}

async fn app_state() -> AppState {
    let db = db().await;
    let jinja = {
        use regex::Regex;
        let mut env = Environment::new();
        env.set_loader(minijinja::path_loader("templates"));
        env.set_keep_trailing_newline(true);
        env.set_lstrip_blocks(true);
        env.set_trim_blocks(true);
        fn remove_youtube_thumbnail_links(body: &str) -> String {
            let re = Regex::new(r#"<a href="/post/\w+"><img src="/youtube/(.*?)</a></div>"#)
                .expect("regex builds");
            re.replace_all(body, r#"<img src="/youtube/$1</div>"#)
                .to_string()
        }
        env.add_filter(
            "remove_youtube_thumbnail_links",
            remove_youtube_thumbnail_links,
        );
        fn byte_slice(body: &str, end: usize) -> String {
            body[..end].to_owned()
        }
        env.add_filter("byte_slice", byte_slice);
        Arc::new(RwLock::new(env))
    };
    let sender = Arc::new(tokio::sync::broadcast::channel(100).0);
    AppState { db, jinja, sender }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    if secret_key().len() < 16 {
        panic!("SECRET_KEY env must be at least 16 chars");
    }
    jobs::init().await;
    let state = app_state().await;
    let router = router::router(state, true);
    let port = match std::env::var("PORT") {
        Ok(port) => port.parse().expect("parse PORT env"),
        Err(_) => 7878,
    };
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect(&format!("listen on port {port}"));
    println!("APABBS listening on port {port}");
    axum::serve(listener, router).await.expect("serve axum")
}
