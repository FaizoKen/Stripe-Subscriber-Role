//! Member-facing status page.
//!
//! Linking is automatic — a member's Discord ID rides along in their Stripe
//! subscription/customer metadata (`discord_user_id`) — so there's no account
//! to connect here. This page just lets a member confirm the plugin can see
//! their subscription and trigger an immediate re-check of their roles.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::services::auth::read_session;
use crate::services::csrf;
use crate::AppState;

const VERIFY_PAGE: &str = include_str!("../../templates/verify.html");

pub async fn verify_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let html = VERIFY_PAGE.replace("{{BASE_URL}}", &state.config.base_url);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

#[derive(sqlx::FromRow)]
struct MembershipRow {
    display_name: String,
    livemode: bool,
    has_active_subscription: bool,
    subscription_status: Option<String>,
    is_trialing: bool,
    is_past_due: bool,
    cancels_at_period_end: bool,
    plan_amount_cents: i64,
    currency: Option<String>,
    billing_interval: Option<String>,
    total_mrr_cents: i64,
    current_period_end: Option<chrono::DateTime<chrono::Utc>>,
    trial_end: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(serde::Deserialize)]
pub struct GuildQuery {
    #[serde(default)]
    guild: Option<String>,
}

/// A `?guild=` worth filtering on: a snowflake, nothing else.
fn guild_of(q: &GuildQuery) -> Option<&str> {
    q.guild
        .as_deref()
        .filter(|g| (15..=25).contains(&g.len()) && g.bytes().all(|b| b.is_ascii_digit()))
}

/// The member's subscriptions as the plugin sees them. Opened from a
/// server's link (`?guild=`, what the settings page hands out), only that
/// server's Stripe accounts are listed; without one, every account the
/// member is a customer of.
pub async fn verify_status(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(q): Query<GuildQuery>,
) -> Result<Json<Value>, AppError> {
    let discord = read_session(&jar, &state.config.session_secret).ok();
    let guild = guild_of(&q);

    let memberships: Vec<Value> = match &discord {
        Some((did, _)) => {
            let rows = sqlx::query_as::<_, MembershipRow>(
                "SELECT a.display_name, a.livemode, mf.has_active_subscription, \
                        mf.subscription_status, mf.is_trialing, mf.is_past_due, \
                        mf.cancels_at_period_end, mf.plan_amount_cents, mf.currency, \
                        mf.billing_interval, mf.total_mrr_cents, mf.current_period_end, \
                        mf.trial_end \
                 FROM stripe_member_facts mf \
                 JOIN stripe_accounts a ON a.id = mf.account_ref \
                 WHERE mf.discord_id = $1 AND ($2::text IS NULL OR a.guild_id = $2) \
                 ORDER BY mf.has_active_subscription DESC, a.display_name",
            )
            .bind(did)
            .bind(guild)
            .fetch_all(&state.pool)
            .await?;
            rows.into_iter()
                .map(|r| {
                    json!({
                        "account": r.display_name,
                        "livemode": r.livemode,
                        "has_active_subscription": r.has_active_subscription,
                        "status": r.subscription_status,
                        "is_trialing": r.is_trialing,
                        "is_past_due": r.is_past_due,
                        "cancels_at_period_end": r.cancels_at_period_end,
                        "plan_amount_cents": r.plan_amount_cents,
                        "currency": r.currency,
                        "billing_interval": r.billing_interval,
                        "total_mrr_cents": r.total_mrr_cents,
                        "current_period_end": r.current_period_end,
                        "trial_end": r.trial_end,
                    })
                })
                .collect()
        }
        None => vec![],
    };

    Ok(Json(json!({
        "signed_in_discord": discord.is_some(),
        "discord_username": discord.as_ref().map(|(_, n)| n.clone()),
        "memberships": memberships,
    })))
}

/// Re-evaluate the signed-in member's roles against current facts.
pub async fn verify_refresh(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    let (discord_id, _) = read_session(&jar, &state.config.session_secret)?;
    crate::services::jobs::enqueue_player_sync(&state.pool, &discord_id).await?;
    Ok(Json(json!({ "refreshed": true })))
}

/// Sign in with Discord through the Auth Gateway, then come back to this
/// page — to the same server's view when it was opened from a server's link.
pub async fn verify_login(
    State(state): State<Arc<AppState>>,
    Query(q): Query<GuildQuery>,
) -> impl IntoResponse {
    let path = path_only(&state.config.base_url);
    let return_to = match guild_of(&q) {
        Some(g) => format!("{path}/verify?guild={g}"),
        None => format!("{path}/verify"),
    };
    let url = format!(
        "{}/auth/login?return_to={}",
        state.config.auth_gateway_url,
        urlencoding::encode(&return_to)
    );
    Redirect::to(&url)
}

fn path_only(base_url: &str) -> String {
    if let Some(scheme_end) = base_url.find("://") {
        let after_scheme = scheme_end + 3;
        if let Some(slash) = base_url[after_scheme..].find('/') {
            return base_url[after_scheme + slash..]
                .trim_end_matches('/')
                .to_string();
        }
    }
    String::new()
}
