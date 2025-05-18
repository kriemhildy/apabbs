mod cron;
mod router;

use apabbs::post::Post;
use minijinja::Environment;
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast::Sender;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    jinja: Arc<RwLock<Environment<'static>>>,
    sender: Arc<Sender<Post>>,
}

async fn app_state() -> AppState {
    let db = apabbs::db().await;
    let jinja = {
        use regex::Regex;
        let mut env = Environment::new();
        env.set_loader(minijinja::path_loader("templates"));
        env.set_keep_trailing_newline(true);
        env.set_lstrip_blocks(true);
        env.set_trim_blocks(true);
        fn remove_youtube_thumbnail_links(body: &str) -> String {
            let re = Regex::new(concat!(
                r#"<a href="/p/\w{8,}"><img src="/youtube/([\w\-]{11})/(\w{4,}).jpg" "#,
                r#"alt="Post \w{8,}" width="(\d+)" height="(\d+)"></a>"#
            ))
            .expect("regex builds");
            re.replace_all(
                body,
                concat!(
                    r#"<img src="/youtube/$1/$2.jpg" alt="YouTube thumbnail $1" "#,
                    r#"width="$3" height="$4">"#,
                ),
            )
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
    if let Err(error) = dotenv::dotenv() {
        eprintln!("Error loading .env file: {}", error);
        std::process::exit(1);
    }
    if apabbs::secret_key().len() < 16 {
        panic!("SECRET_KEY env must be at least 16 chars");
    }
    cron::init().await;
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
