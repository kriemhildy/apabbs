//! Application entry point and server initialization.
//!
//! Sets up the web server, configures template rendering,
//! initializes background tasks, and manages application state.

#[tokio::main]
pub async fn main() {
    // Load environment variables from .env file (fail fast if missing)
    if let Err(error) = dotenv::dotenv() {
        eprintln!("Failed to load .env file: {error}");
        std::process::exit(1);
    }

    // Initialize global tracing subscriber for logging and diagnostics
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Ensure critical configuration is present
    if apabbs::secret_key().len() < 16 {
        eprintln!("SECRET_KEY environment variable must be at least 16 characters");
        std::process::exit(1);
    }

    // Start background tasks and scheduled jobs
    apabbs::cron::init().await;

    // Build application state (DB, templates, broadcast channel)
    let state = apabbs::app_state().await;

    // Build router with all routes and middleware
    let router = apabbs::router::router(state, true);

    // Get server port from environment or use default
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7878);

    // Bind to network address
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap_or_else(|_| panic!("Failed to bind to 0.0.0.0:{port}"));

    tracing::info!("Server listening on port {port}");

    // Start HTTP server
    axum::serve(listener, router).await.expect("server starts");
}
