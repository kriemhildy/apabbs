mod router;
mod jobs;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    if apabbs::secret_key().len() < 16 {
        panic!("SECRET_KEY env must be at least 16 chars");
    }
    jobs::init().await;
    let state = apabbs::app_state().await;
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
