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

mod init {
    use crate::{AppState, Arc, Environment, PgPool, Post, RwLock, Sender, jobs};
    use tower_http::{
        classify::{ServerErrorsAsFailures, SharedClassifier},
        trace::TraceLayer,
    };

    pub async fn db() -> PgPool {
        let url = std::env::var("DATABASE_URL").expect("read DATABASE_URL env");
        PgPool::connect(&url).await.expect("connect postgres")
    }

    pub async fn cron_jobs() {
        use tokio_cron_scheduler::JobScheduler;
        let sched = JobScheduler::new().await.expect("make new job scheduler");
        let job = jobs::scrub_ips();
        sched.add(job).await.expect("add job to scheduler");
        sched.start().await.expect("start scheduler");
    }

    pub fn jinja() -> Arc<RwLock<Environment<'static>>> {
        let mut env = Environment::new();
        env.set_loader(minijinja::path_loader("templates"));
        env.set_keep_trailing_newline(true);
        env.set_lstrip_blocks(true);
        env.set_trim_blocks(true);
        fn remove_youtube_thumbnail_links(body: &str, key: &str) -> String {
            body.replace(
                &format!(r#"<a href="/{key}"><img src="/youtube/"#),
                r#"<img src="/youtube/"#,
            )
            .replace(r#"</a></div>"#, "</div>")
        }
        env.add_filter(
            "remove_youtube_thumbnail_links",
            remove_youtube_thumbnail_links,
        );
        Arc::new(RwLock::new(env))
    }

    pub fn sender() -> Arc<Sender<Post>> {
        Arc::new(tokio::sync::broadcast::channel(100).0)
    }

    pub fn trace_layer() -> TraceLayer<SharedClassifier<ServerErrorsAsFailures>> {
        use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse};
        use tracing::Level;
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .try_init()
            .ok();
        TraceLayer::new_for_http()
            .make_span_with(DefaultMakeSpan::new().level(Level::DEBUG))
            .on_response(DefaultOnResponse::new().level(Level::DEBUG))
    }

    pub fn port() -> u16 {
        match std::env::var("PORT") {
            Ok(port) => port.parse().expect("parse PORT env"),
            Err(_) => 7878,
        }
    }

    pub fn dev() -> bool {
        std::env::var("DEV").is_ok_and(|v| v == "1")
    }

    pub fn per_page() -> usize {
        match std::env::var("PER_PAGE") {
            Ok(per_page) => per_page.parse().expect("parse PER_PAGE env"),
            Err(_) => 1000,
        }
    }

    pub fn site_name() -> String {
        format!(
            "{}{}",
            if dev() { "[dev] " } else { "" },
            std::env::var("SITE_NAME").expect("read SITE_NAME env")
        )
    }

    pub fn secret_key() -> String {
        std::env::var("SECRET_KEY").expect("read SECRET_KEY env")
    }

    pub async fn app_state() -> AppState {
        let (db, _) = tokio::join!(db(), cron_jobs());
        let jinja = jinja();
        let sender = sender();
        AppState { db, jinja, sender }
    }

    pub fn validate_secret_key() {
        if secret_key().len() < 16 {
            panic!("SECRET_KEY env must be at least 16 chars");
        }
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    init::validate_secret_key();
    let state = init::app_state().await;
    let router = router::router(state, true);
    let port = init::port();
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect(&format!("listen on port {port}"));
    println!("APABBS listening on port {port}");
    axum::serve(listener, router).await.expect("serve axum")
}
