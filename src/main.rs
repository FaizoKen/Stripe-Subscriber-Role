use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::middleware;
use axum::routing::{delete, get, post};
use axum::Router;
use sqlx::PgPool;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;
use tower_governor::GovernorLayer;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::TraceLayer;

mod config;
mod db;
mod error;
mod models;
mod routes;
mod schema;
mod services;
mod tasks;

use services::rolelogic::RoleLogicClient;
use services::security_headers;
use tasks::shutdown::Shutdown;

pub struct AppState {
    pub pool: PgPool,
    pub config: config::AppConfig,
    pub rl_client: RoleLogicClient,
    pub http: reqwest::Client,
    /// Origins permitted to issue cookie-authenticated state-changing requests.
    /// Source of truth for both the `CorsLayer` allowlist and the per-handler
    /// `csrf::verify_origin` check.
    pub allowed_origins: Vec<String>,
    /// Flips to `true` when graceful shutdown starts. `/ready` reads it so load
    /// balancers can drain replicas before they stop accepting.
    pub draining: AtomicBool,
    /// Per-replica wake signal driven by `tasks::job_listener` on every
    /// `NOTIFY jobs_pending`. Workers `select!` on this so a job inserted by any
    /// replica wakes every worker within ~ms.
    pub jobs_notify: Arc<tokio::sync::Notify>,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "stripe_subscriber_role=info,tower_http=warn".into()),
        )
        .init();

    // `migrate` subcommand: apply migrations and exit (for blue-green deploys).
    let migrate_only = std::env::args().nth(1).as_deref() == Some("migrate");

    let app_config = config::AppConfig::from_env();
    let listen_addr = app_config.listen_addr.clone();

    let pool = db::create_pool(&app_config.database_url, &app_config.db_pool).await;
    db::run_migrations(&pool).await;
    tracing::info!("Database connected and migrations applied");

    if migrate_only {
        tracing::info!("`migrate` subcommand done; exiting without starting the server");
        return;
    }

    let rl_client = RoleLogicClient::new(app_config.rolelogic_api_url.clone());
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to build HTTP client");

    let mut allowed_origins = vec![config::derive_origin(&app_config.base_url)];
    if let Some(dash) = app_config.rl_dashboard_origin.as_deref() {
        allowed_origins.push(dash.to_string());
    }

    let worker_concurrency = app_config.worker_concurrency.max(1);

    let state = Arc::new(AppState {
        pool,
        config: app_config,
        rl_client,
        http,
        allowed_origins,
        draining: AtomicBool::new(false),
        jobs_notify: Arc::new(tokio::sync::Notify::new()),
    });

    let shutdown = Shutdown::new();

    let listener_handle = tokio::spawn(tasks::job_listener::run(
        state.pool.clone(),
        Arc::clone(&state.jobs_notify),
        shutdown.subscribe(),
    ));

    let mut worker_handles: Vec<tokio::task::JoinHandle<()>> =
        Vec::with_capacity(worker_concurrency as usize);
    for i in 0..worker_concurrency {
        worker_handles.push(tokio::spawn(tasks::job_worker::run(
            Arc::clone(&state),
            shutdown.subscribe(),
            format!("job-worker-{i}"),
        )));
    }
    tracing::info!(workers = worker_concurrency, "Job workers started");

    // Periodic reconcile (6h) — re-imports each connected Stripe account and is
    // the webhook-loss safety net.
    let reconcile_handle = tokio::spawn(tasks::reconcile::run(
        Arc::clone(&state),
        shutdown.subscribe(),
    ));

    let plugin_routes = Router::new()
        // RoleLogic plugin contract
        .route("/register", post(routes::plugin::register))
        .route("/config", get(routes::plugin::get_config))
        .route("/config", post(routes::plugin::post_config))
        .route("/config", delete(routes::plugin::delete_config))
        // Admin — Stripe account CRUD
        .route(
            "/admin/{guild_id}/accounts",
            get(routes::admin::account_list),
        )
        .route(
            "/admin/{guild_id}/accounts/connect",
            post(routes::admin::account_connect),
        )
        .route(
            "/admin/{guild_id}/accounts/{account_ref}",
            delete(routes::admin::account_disconnect),
        )
        .route(
            "/admin/{guild_id}/accounts/{account_ref}/webhook-secret",
            post(routes::admin::account_set_webhook_secret),
        )
        .route(
            "/admin/{guild_id}/accounts/{account_ref}/catalog",
            get(routes::admin::account_catalog),
        )
        // Admin — iframe role-config (deep-linked from RoleLogic dashboard)
        .route(
            "/admin/{guild_id}/role/{role_id}",
            get(routes::admin::role_config_page),
        )
        .route(
            "/admin/{guild_id}/role/{role_id}/data",
            get(routes::admin::role_config_data),
        )
        .route(
            "/admin/{guild_id}/role/{role_id}/save",
            post(routes::admin::role_config_save),
        )
        .route(
            "/admin/{guild_id}/role/{role_id}/preview",
            get(routes::admin::role_config_preview).post(routes::admin::role_config_preview_edit),
        )
        // Stripe webhook ingestor (per-account URL)
        .route(
            "/webhooks/stripe/{account_ref}",
            post(routes::webhooks::stripe_webhook),
        )
        // Member status page
        .route("/verify", get(routes::verify::verify_page))
        .route("/verify/status", get(routes::verify::verify_status))
        .route("/verify/login", post(routes::verify::verify_login))
        .route("/verify/refresh", post(routes::verify::verify_refresh))
        // Health & static
        .route("/favicon.ico", get(routes::health::favicon))
        .route("/health", get(routes::health::health))
        .route("/ready", get(routes::health::ready));

    // -------- Middleware stack (outermost declared last) --------

    let cors_origins: Vec<HeaderValue> = state
        .allowed_origins
        .iter()
        .map(|o| {
            HeaderValue::from_str(o)
                .expect("allowed origin contains characters not valid in a HeaderValue")
        })
        .collect();
    let cors_layer = CorsLayer::new()
        .allow_origin(cors_origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_credentials(true)
        .max_age(Duration::from_secs(600));

    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(5)
            .burst_size(20)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("Failed to build governor config"),
    );
    let governor_limiter = governor_config.limiter().clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.tick().await;
        loop {
            interval.tick().await;
            governor_limiter.retain_recent();
        }
    });

    let sensitive_request_headers = SetSensitiveRequestHeadersLayer::new([
        header::AUTHORIZATION,
        header::COOKIE,
        HeaderName::from_static("x-internal-key"),
        HeaderName::from_static("stripe-signature"),
    ]);

    let request_id_header = HeaderName::from_static("x-request-id");

    let app = Router::new()
        .nest("/stripe-subscriber-role", plugin_routes)
        .layer(DefaultBodyLimit::max(256 * 1024))
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(TraceLayer::new_for_http())
        .layer(sensitive_request_headers)
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .layer(cors_layer)
        .layer(GovernorLayer {
            config: governor_config,
        })
        .layer(middleware::from_fn(security_headers::baseline))
        .layer(CompressionLayer::new().br(true).gzip(true))
        .with_state(Arc::clone(&state));

    tracing::info!("Server starting on {listen_addr}");

    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .expect("Failed to bind listener");

    let shutdown_for_signal = shutdown.clone();
    let state_for_signal = Arc::clone(&state);
    tokio::spawn(async move {
        tasks::shutdown::wait_for_signal().await;
        state_for_signal.draining.store(true, Ordering::SeqCst);
        tracing::info!("Shutdown signal received; draining HTTP");
        shutdown_for_signal.trigger();
    });

    let mut server_shutdown = shutdown.subscribe();
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        server_shutdown.wait().await;
    })
    .await
    {
        tracing::error!("Server error: {e}");
    }

    tracing::info!("HTTP drained; waiting for workers to finish in-flight jobs");
    for h in worker_handles {
        if let Err(e) = h.await {
            tracing::error!("Worker join failed: {e}");
        }
    }
    if let Err(e) = listener_handle.await {
        tracing::error!("Job listener join failed: {e}");
    }
    if let Err(e) = reconcile_handle.await {
        tracing::error!("reconcile join failed: {e}");
    }

    tracing::info!("Server stopped");
}
