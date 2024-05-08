// schizo.land
// main.rs
// author: Kriemhild Gretchen

pub mod ban;
pub mod crypto;
pub mod post;
pub mod user;

pub const BEGIN: &'static str = "begin transaction";
pub const COMMIT: &'static str = "commit transaction";

pub use post::PostMessage;
pub use tokio::sync::broadcast::Sender;

mod jobs;
mod routes;

use std::sync::{Arc, RwLock};
use tower_http::{
    classify::{ServerErrorsAsFailures, SharedClassifier},
    trace::TraceLayer,
};

#[derive(Clone)]
pub struct AppState {
    db: sqlx::PgPool,
    jinja: Arc<RwLock<minijinja::Environment<'static>>>,
    sender: Arc<Sender<PostMessage>>,
}

pub fn dev() -> bool {
    std::env::var("DEV").is_ok_and(|v| v == "1")
}

pub fn render(
    lock: Arc<RwLock<minijinja::Environment<'_>>>,
    name: &str,
    ctx: minijinja::value::Value,
) -> String {
    if dev() {
        let mut env = lock.write().expect("write jinja env");
        env.clear_templates();
    }
    let env = lock.read().expect("read jinja env");
    let tmpl = env.get_template(name).expect("get jinja template");
    tmpl.render(ctx).expect("render template")
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

fn init_jinja() -> Arc<RwLock<minijinja::Environment<'static>>> {
    let mut env = minijinja::Environment::new();
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

fn router(state: AppState) -> axum::Router {
    use axum::routing::{get, post};
    use routes::*;
    axum::Router::new()
        .route("/", get(index))
        .route("/submit-post", post(submit_post))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/new-hash", post(new_hash))
        .route("/hide-rejected-post", post(hide_rejected_post))
        .route("/web-socket", get(web_socket))
        .route("/admin/update-post-status", post(update_post_status))
        .layer(trace_layer())
        .with_state(state)
}

fn port() -> u16 {
    match std::env::var("PORT") {
        Ok(port) => port.parse().expect("parse PORT env"),
        Err(_) => 7878
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
    let router = router(state);
    let port = port();
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect(&format!("listen on port {port}"));
    println!("app listening on port {port}");
    axum::serve(listener, router).await.expect("serve axum")
}
