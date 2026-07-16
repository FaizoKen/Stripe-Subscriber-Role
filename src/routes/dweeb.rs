//! DWEEB link-plugin setup probe.
//!
//! DWEEB (the Discord Webhook Embed Builder, <https://dweeb.faizo.net>) lists
//! this plugin as a **link plugin**: a Link button that sends members to our
//! verify page. Its editor probes this endpoint to show a live
//! "Ready / Needs setup" state for the connected server instead of a
//! permanent "set it up first" warning.
//!
//! Public and CORS-open on purpose: it returns only whether the guild has
//! any registration here — the same fact anyone could observe by loading the
//! public verify page with that guild id — never any configuration content.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::AppState;

const PLUGIN_SLUG: &str = "stripe-subscriber-role";

/// Shape check for a Discord snowflake id coming from an untrusted query.
fn is_snowflake(s: &str) -> bool {
    (15..=25).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

#[derive(Deserialize)]
pub struct StatusQuery {
    #[serde(default)]
    pub guild: Option<String>,
}

/// JSON response with the CORS + cache headers the probe needs. The wildcard
/// is safe: the endpoint is public, credential-less, and boolean-only.
fn probe_json(status: StatusCode, cache_control: &'static str, body: Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::CACHE_CONTROL, cache_control),
        ],
        body.to_string(),
    )
        .into_response()
}

/// `GET /dweeb/status?guild=<id>` — is this guild set up on this plugin?
///
/// "Configured" means at least one role link is registered for the guild,
/// i.e. the member-facing URL a DWEEB Link button carries will actually do
/// something when clicked.
pub async fn status(State(state): State<Arc<AppState>>, Query(q): Query<StatusQuery>) -> Response {
    let Some(guild) = q.guild.as_deref().filter(|g| is_snowflake(g)) else {
        return probe_json(
            StatusCode::BAD_REQUEST,
            "no-store",
            json!({ "error": "guild must be a Discord server id" }),
        );
    };

    let role_count: i64 =
        match sqlx::query_scalar("SELECT COUNT(*) FROM role_links WHERE guild_id = $1")
            .bind(guild)
            .fetch_one(&state.pool)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                tracing::error!("dweeb status probe query failed: {e}");
                return probe_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "no-store",
                    json!({ "error": "temporarily unavailable" }),
                );
            }
        };

    probe_json(
        StatusCode::OK,
        // Short shared cache: the editor re-probes cheaply, and a
        // just-finished setup shows up within a minute.
        "public, max-age=60",
        json!({
            "schema_version": 1,
            "plugin": PLUGIN_SLUG,
            "guild_id": guild,
            "configured": role_count > 0,
            "role_count": role_count,
        }),
    )
}
