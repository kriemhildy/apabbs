mod ban;
mod crypto;
mod jobs;
mod post;
mod router;
mod user;

use minijinja::Environment;
use post::PostMessage;
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast::Sender;

const BEGIN: &'static str = "begin transaction";
const COMMIT: &'static str = "commit transaction";

#[derive(Clone)]
struct AppState {
    db: PgPool,
    jinja: Arc<RwLock<Environment<'static>>>,
    sender: Arc<Sender<PostMessage>>,
}

mod init {
    use crate::{jobs, AppState, Arc, Environment, PgPool, PostMessage, RwLock, Sender};
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
        env.add_filter("repeat", str::repeat);
        Arc::new(RwLock::new(env))
    }

    pub fn sender() -> Arc<Sender<PostMessage>> {
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

    pub async fn app_state() -> AppState {
        let (db, _) = tokio::join!(db(), cron_jobs());
        let jinja = jinja();
        let sender = sender();
        AppState { db, jinja, sender }
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let state = init::app_state().await;
    let router = router::router(state, true);
    let port = init::port();
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect(&format!("listen on port {port}"));
    println!("app listening on port {port}");
    axum::serve(listener, router).await.expect("serve axum")
}
