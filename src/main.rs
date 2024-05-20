mod ban;
mod crypto;
mod jobs;
mod post;
mod router;
mod user;

use minijinja::Environment;
use post::PostMessage;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast::Sender;
use tower_http::{
    classify::{ServerErrorsAsFailures, SharedClassifier},
    trace::TraceLayer,
};

const BEGIN: &'static str = "begin transaction";
const COMMIT: &'static str = "commit transaction";

#[derive(Clone)]
struct AppState {
    db: sqlx::PgPool,
    jinja: Arc<RwLock<Environment<'static>>>,
    sender: Arc<Sender<PostMessage>>,
}

async fn init_db() -> sqlx::PgPool {
    let url = std::env::var("DATABASE_URL").expect("read DATABASE_URL env");
    sqlx::PgPool::connect(&url).await.expect("connect postgres")
}

async fn init_cron_jobs() {
    use tokio_cron_scheduler::JobScheduler;
    let sched = JobScheduler::new().await.expect("make new job scheduler");
    let job = jobs::scrub_ips();
    sched.add(job).await.expect("add job to scheduler");
    sched.start().await.expect("start scheduler");
}

fn init_jinja() -> Arc<RwLock<Environment<'static>>> {
    let mut env = Environment::new();
    env.set_loader(minijinja::path_loader("templates"));
    env.set_keep_trailing_newline(true);
    env.set_lstrip_blocks(true);
    env.set_trim_blocks(true);
    env.add_filter("repeat", str::repeat);
    Arc::new(RwLock::new(env))
}

fn init_sender() -> Arc<Sender<PostMessage>> {
    Arc::new(tokio::sync::broadcast::channel(100).0)
}

fn trace_layer() -> TraceLayer<SharedClassifier<ServerErrorsAsFailures>> {
    use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse};
    use tracing::Level;
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();
    TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::DEBUG))
        .on_response(DefaultOnResponse::new().level(Level::DEBUG))
}

fn port() -> u16 {
    match std::env::var("PORT") {
        Ok(port) => port.parse().expect("parse PORT env"),
        Err(_) => 7878,
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let state = {
        let (db, _) = tokio::join!(init_db(), init_cron_jobs());
        let jinja = init_jinja();
        let sender = init_sender();
        AppState { db, jinja, sender }
    };
    let router = router::router(state);
    let port = port();
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect(&format!("listen on port {port}"));
    println!("app listening on port {port}");
    axum::serve(listener, router).await.expect("serve axum")
}
