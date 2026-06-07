use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};

use crate::AppState;

pub async fn favicon() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/x-icon"),
            (header::CACHE_CONTROL, "public, max-age=2592000, immutable"),
        ],
        include_bytes!("../../favicon.ico").as_slice(),
    )
}

/// Probes an external dependency with a short timeout. Any HTTP response (even
/// 401, since we hit Stripe unauthenticated) counts as "up" — we're checking
/// reachability, not authorization.
async fn check_service(http: &reqwest::Client, name: &str, url: &str) -> Value {
    let start = std::time::Instant::now();
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(3), http.get(url).send()).await;
    let latency = start.elapsed().as_millis() as u64;
    let is_up = matches!(result, Ok(Ok(_)));
    json!({
        "name": name,
        "status": if is_up { "up" } else { "down" },
        "latency_ms": latency
    })
}

/// Liveness — process is up. Returns 503 if the DB is unreachable so an
/// orchestrator restarts a stuck pod. Stripe being down only downgrades the
/// body status to "degraded"; it never flips the HTTP status.
pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let db_fut = async {
        let start = std::time::Instant::now();
        let ok = sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&state.pool)
            .await
            .is_ok();
        (ok, start.elapsed().as_millis() as u64)
    };
    let stripe_url = format!("{}/v1", state.config.stripe_api_base);
    let stripe_fut = check_service(&state.http, "Stripe API", &stripe_url);

    let ((db_ok, db_latency), stripe_check) = tokio::join!(db_fut, stripe_fut);

    let http_status = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let stripe_down = stripe_check["status"] == "down";
    let body_status = match (db_ok, stripe_down) {
        (true, false) => "healthy",
        (false, _) => "unhealthy",
        (true, true) => "degraded",
    };

    let body = Json(json!({
        "status": body_status,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "checks": {
            "database": {
                "status": if db_ok { "up" } else { "down" },
                "latency_ms": db_latency
            }
        },
        "services": [stripe_check]
    }));
    (http_status, body)
}

/// Readiness — flips to 503 the moment shutdown begins so the load balancer can
/// drain this replica before the HTTP server stops accepting connections.
pub async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.draining.load(Ordering::SeqCst) {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "draining" })),
        )
    } else {
        (StatusCode::OK, Json(json!({ "status": "ready" })))
    }
}
