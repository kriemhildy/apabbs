//! Application entry point and server initialization.
//!
//! Sets up the web server, configures template rendering,
//! initializes background tasks, and manages application state.

fn main() {
    // Initialize global tracing subscriber for logging and diagnostics
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Load environment variables from .env file (fail fast if missing)
    if let Err(error) = dotenv::dotenv() {
        tracing::error!("Failed to load .env file: {error}");
        std::process::exit(1);
    }

    // Ensure critical configuration is present
    if apabbs::secret_key().len() < 16 {
        tracing::error!("SECRET_KEY environment variable must be at least 16 characters");
        std::process::exit(1);
    }

    // Initialize Sentry for error tracking if enabled
    #[cfg(feature = "sentry")]
    let _sentry_guard = {
        if let Ok(sentry_dsn) = std::env::var("SENTRY_DSN") {
            let guard = sentry::init((
                sentry_dsn,
                sentry::ClientOptions {
                    release: sentry::release_name!(),
                    // Capture user IPs and potentially sensitive headers when using HTTP server integrations
                    // see https://docs.sentry.io/platforms/rust/data-management/data-collected for more info
                    send_default_pii: true,
                    ..Default::default()
                },
            ));
            tracing::info!("Sentry error tracking initialized");
            Some(guard)
        } else {
            tracing::warn!("SENTRY_DSN not set, Sentry error tracking disabled");
            None
        }
    };

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            // Start background tasks and scheduled jobs
            apabbs::cron::init().await;

            // Build application state (DB, templates, broadcast channel)
            let state = apabbs::init_app_state().await;

            // Build router with all routes and middleware
            let router = apabbs::router::init_router(state, true);

            // Get server port from environment or use default
            let port = std::env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(7878);

            // Bind to network address
            let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
                .await
                .unwrap_or_else(|_| panic!("Failed to bind to 0.0.0.0:{port}"));

            // Start HTTP server
            axum::serve(listener, router)
                .await
                .expect("Start Axum server");

            tracing::info!("Server listening on port {port}");
        });
}
