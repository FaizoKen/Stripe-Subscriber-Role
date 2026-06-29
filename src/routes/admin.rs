//! Admin routes: Stripe account connect/list/disconnect, the iframe
//! role-config page, the rule-tree save/preview handlers, and the product/price
//! catalog used by the rule-builder picker.
//!
//! Dual-mode auth (Convention 45): iframe entry via `?rl_token=` JWT → minted
//! `ifs:` Bearer for XHRs; direct nav via `rl_session` cookie + Auth-Gateway
//! manager check.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::AppError;
use crate::models::condition::{ConditionOperator, ConditionTarget, TargetKind};
use crate::models::rule::{RuleTree, MAX_CONDITIONS_PER_GROUP, MAX_GROUPS};
use crate::services::auth::{extract_bearer, require_guild_admin, require_manager};
use crate::services::rule_sql::{self, Bind};
use crate::services::rule_validator::{self, RuleTreeBody};
use crate::services::security_headers::admin_iframe_csp;
use crate::services::stripe::StripeClient;
use crate::services::{auth_gateway, crypto, csrf, jobs, rl_token};
use crate::tasks::reconcile::decrypt_key;
use crate::AppState;

const ROLE_CONFIG_TEMPLATE: &str = include_str!("../../templates/role_config.html");

/// Stripe events the admin should subscribe their webhook endpoint to.
const WEBHOOK_EVENTS: &[&str] = &[
    "checkout.session.completed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "customer.updated",
    "customer.deleted",
    "charge.succeeded",
    "invoice.payment_failed",
];

// ---------------------------------------------------------------------------
// Account rows
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
pub struct AccountRow {
    pub id: i64,
    pub stripe_account_id: String,
    pub display_name: String,
    pub country: Option<String>,
    pub livemode: bool,
    pub discord_metadata_key: String,
    pub webhook_configured: bool,
    pub last_synced_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_backfill_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn account_json(state: &AppState, a: &AccountRow) -> Value {
    json!({
        "id": a.id,
        "stripe_account_id": a.stripe_account_id,
        "display_name": a.display_name,
        "country": a.country,
        "livemode": a.livemode,
        "discord_metadata_key": a.discord_metadata_key,
        "webhook_configured": a.webhook_configured,
        "webhook_url": format!("{}/webhooks/stripe/{}", state.config.base_url, a.id),
        "last_synced_at": a.last_synced_at,
        "last_backfill_at": a.last_backfill_at,
    })
}

const ACCOUNT_SELECT: &str = "SELECT id, stripe_account_id, display_name, country, livemode, \
    discord_metadata_key, (webhook_secret_enc IS NOT NULL) AS webhook_configured, \
    last_synced_at, last_backfill_at FROM stripe_accounts";

async fn load_accounts(state: &AppState, guild_id: &str) -> Result<Vec<AccountRow>, AppError> {
    let rows = sqlx::query_as::<_, AccountRow>(&format!(
        "{ACCOUNT_SELECT} WHERE guild_id = $1 ORDER BY created_at DESC"
    ))
    .bind(guild_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// POST /admin/{guild_id}/accounts/connect
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ConnectBody {
    pub api_key: String,
    #[serde(default)]
    pub webhook_secret: Option<String>,
    #[serde(default)]
    pub discord_metadata_key: Option<String>,
}

pub async fn account_connect(
    State(state): State<Arc<AppState>>,
    Path(guild_id): Path<String>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<ConnectBody>,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    let discord_id = require_guild_admin(&state, &jar, &headers, &guild_id).await?;

    let api_key = body.api_key.trim().to_string();
    if api_key.is_empty() {
        return Err(AppError::BadRequest("Paste your Stripe API key.".into()));
    }
    if !(api_key.starts_with("rk_") || api_key.starts_with("sk_")) {
        return Err(AppError::BadRequest(
            "That doesn't look like a Stripe secret/restricted key (expected rk_… or sk_…).".into(),
        ));
    }

    let metadata_key = body
        .discord_metadata_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("discord_user_id")
        .to_string();

    let client = StripeClient::new(state.config.stripe_api_base.clone());
    let info = client.validate_and_describe(&api_key).await?;

    let key_enc = crypto::encrypt(&state.config.session_secret, api_key.as_bytes());
    let secret_enc = body
        .webhook_secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| crypto::encrypt(&state.config.session_secret, s.as_bytes()));

    let account_ref: i64 = sqlx::query_scalar(
        "INSERT INTO stripe_accounts ( \
            guild_id, stripe_account_id, display_name, country, livemode, \
            api_key_enc, webhook_secret_enc, discord_metadata_key, connected_by_discord_id \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT (guild_id, stripe_account_id) DO UPDATE SET \
            display_name = EXCLUDED.display_name, \
            country = EXCLUDED.country, \
            livemode = EXCLUDED.livemode, \
            api_key_enc = EXCLUDED.api_key_enc, \
            webhook_secret_enc = COALESCE(EXCLUDED.webhook_secret_enc, stripe_accounts.webhook_secret_enc), \
            discord_metadata_key = EXCLUDED.discord_metadata_key, \
            updated_at = now() \
         RETURNING id",
    )
    .bind(&guild_id)
    .bind(&info.account_id)
    .bind(&info.display_name)
    .bind(&info.country)
    .bind(info.livemode)
    .bind(&key_enc)
    .bind(&secret_enc)
    .bind(&metadata_key)
    .bind(&discord_id)
    .fetch_one(&state.pool)
    .await?;

    // Kick off the initial import in the background.
    jobs::enqueue_account_backfill(&state.pool, account_ref).await?;

    tracing::info!(guild_id, account_ref, account = %info.account_id, "Stripe account connected");

    let row = sqlx::query_as::<_, AccountRow>(&format!("{ACCOUNT_SELECT} WHERE id = $1"))
        .bind(account_ref)
        .fetch_one(&state.pool)
        .await?;

    Ok(Json(json!({
        "account": account_json(&state, &row),
        "webhook_events": WEBHOOK_EVENTS,
    })))
}

// ---------------------------------------------------------------------------
// GET /admin/{guild_id}/accounts
// ---------------------------------------------------------------------------

pub async fn account_list(
    State(state): State<Arc<AppState>>,
    Path(guild_id): Path<String>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    require_guild_admin(&state, &jar, &headers, &guild_id).await?;
    let rows = load_accounts(&state, &guild_id).await?;
    let accounts: Vec<Value> = rows.iter().map(|a| account_json(&state, a)).collect();
    Ok(Json(json!({ "accounts": accounts })))
}

// ---------------------------------------------------------------------------
// DELETE /admin/{guild_id}/accounts/{account_ref}
// ---------------------------------------------------------------------------

pub async fn account_disconnect(
    State(state): State<Arc<AppState>>,
    Path((guild_id, account_ref)): Path<(String, i64)>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_guild_admin(&state, &jar, &headers, &guild_id).await?;

    let mut tx = state.pool.begin().await?;
    // Unbind any role links pointing at this account so a later save doesn't
    // reference a deleted account.
    sqlx::query(
        "UPDATE role_links SET stripe_account_ref = NULL, updated_at = now() \
         WHERE guild_id = $1 AND stripe_account_ref = $2",
    )
    .bind(&guild_id)
    .bind(account_ref)
    .execute(&mut *tx)
    .await?;

    // CASCADE drops the account's customers/subscriptions/member_facts.
    let result = sqlx::query("DELETE FROM stripe_accounts WHERE id = $1 AND guild_id = $2")
        .bind(account_ref)
        .bind(&guild_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(json!({ "removed": result.rows_affected() > 0 })))
}

// ---------------------------------------------------------------------------
// POST /admin/{guild_id}/accounts/{account_ref}/webhook-secret
// Adds/updates the Stripe webhook signing secret for one account. This is a
// separate (post-connect) step because the webhook URL is per-account, so the
// admin can only obtain the secret after the account exists.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct WebhookSecretBody {
    pub webhook_secret: String,
}

pub async fn account_set_webhook_secret(
    State(state): State<Arc<AppState>>,
    Path((guild_id, account_ref)): Path<(String, i64)>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<WebhookSecretBody>,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_guild_admin(&state, &jar, &headers, &guild_id).await?;

    let secret = body.webhook_secret.trim().to_string();
    if secret.is_empty() {
        return Err(AppError::BadRequest(
            "Paste the webhook signing secret (whsec_…).".into(),
        ));
    }
    if !secret.starts_with("whsec_") {
        return Err(AppError::BadRequest(
            "That doesn't look like a Stripe signing secret (expected whsec_…).".into(),
        ));
    }

    let enc = crypto::encrypt(&state.config.session_secret, secret.as_bytes());
    let result = sqlx::query(
        "UPDATE stripe_accounts SET webhook_secret_enc = $1, updated_at = now() \
         WHERE id = $2 AND guild_id = $3",
    )
    .bind(&enc)
    .bind(account_ref)
    .bind(&guild_id)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(
            "That Stripe account isn't connected to this server.".into(),
        ));
    }

    Ok(Json(json!({ "success": true, "webhook_configured": true })))
}

// ---------------------------------------------------------------------------
// GET /admin/{guild_id}/accounts/{account_ref}/catalog
// Products + prices for the rule-builder picker.
// ---------------------------------------------------------------------------

pub async fn account_catalog(
    State(state): State<Arc<AppState>>,
    Path((guild_id, account_ref)): Path<(String, i64)>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    require_guild_admin(&state, &jar, &headers, &guild_id).await?;

    let enc = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT api_key_enc FROM stripe_accounts WHERE id = $1 AND guild_id = $2",
    )
    .bind(account_ref)
    .bind(&guild_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("That Stripe account isn't connected here.".into()))?;

    let key = decrypt_key(&state, &enc)?;
    let client = StripeClient::new(state.config.stripe_api_base.clone());

    let products = client.list_products(&key).await.unwrap_or_default();
    let prices = client.list_prices(&key).await.unwrap_or_default();

    let products: Vec<Value> = products
        .into_iter()
        .map(|p| json!({ "id": p.id, "name": p.name }))
        .collect();
    let prices: Vec<Value> = prices
        .into_iter()
        .map(|p| {
            json!({
                "id": p.id,
                "product_id": p.product_id,
                "nickname": p.nickname,
                "unit_amount_cents": p.unit_amount_cents,
                "currency": p.currency,
                "interval": p.interval,
            })
        })
        .collect();

    Ok(Json(json!({ "products": products, "prices": prices })))
}

// ---------------------------------------------------------------------------
// Iframe role-config page (dual-mode)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RoleConfigPageQuery {
    #[serde(default)]
    rl_token: Option<String>,
}

pub async fn role_config_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
    Query(query): Query<RoleConfigPageQuery>,
) -> Response {
    let has_rl_token = query
        .rl_token
        .as_deref()
        .map(|t| !t.is_empty())
        .unwrap_or(false);

    // `read_only` is true when a developer is impersonating the user.
    let (iframe_session, read_only) = match query.rl_token.as_deref() {
        Some(token) if !token.is_empty() => {
            match verify_iframe_entry(&state, &guild_id, &role_id, token).await {
                Ok((t, ro)) => (Some(t), ro),
                Err(resp) => return resp,
            }
        }
        _ => (None, false),
    };

    if iframe_session.is_none() {
        if let Err(e) = require_manager(&state, &jar, &guild_id).await {
            if !has_rl_token && looks_embedded(&headers) {
                tracing::warn!(
                    guild_id,
                    role_id,
                    base_url = %state.config.base_url,
                    "role_config_page reached inside an iframe with no rl_token — \
                     verify BASE_URL matches the plugin URL registered in RoleLogic."
                );
                return render_iframe_no_token(&state);
            }
            return render_signin_page(&state, &e.to_string());
        }
    }

    let body = ROLE_CONFIG_TEMPLATE
        .replace("__BASE_URL__", &state.config.base_url)
        .replace("__GUILD_ID__", &guild_id)
        .replace("__ROLE_ID__", &role_id)
        .replace("__IFRAME_TOKEN__", iframe_session.as_deref().unwrap_or(""))
        .replace("__READ_ONLY__", if read_only { "1" } else { "0" });

    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
            (
                header::CACHE_CONTROL,
                "private, max-age=300, must-revalidate".to_string(),
            ),
        ],
        body,
    )
        .into_response()
}

async fn verify_iframe_entry(
    state: &AppState,
    guild_id: &str,
    role_id: &str,
    rl_token_str: &str,
) -> Result<(String, bool), Response> {
    let api_token: Option<String> =
        sqlx::query_scalar("SELECT api_token FROM role_links WHERE guild_id = $1 AND role_id = $2")
            .bind(guild_id)
            .bind(role_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| render_inline_error(state, &format!("Database error: {e}")))?;

    let Some(api_token) = api_token else {
        return Err(render_inline_error(
            state,
            "This role link isn't registered with this plugin yet.",
        ));
    };

    let verified =
        rl_token::verify(rl_token_str, &api_token, &state.config.base_url).map_err(|e| {
            let msg = match e {
                rl_token::RlTokenError::Expired => {
                    "Your session expired. Reopen the plugin in the RoleLogic dashboard."
                }
                rl_token::RlTokenError::BadSignature | rl_token::RlTokenError::Malformed => {
                    "Invalid auth token."
                }
                rl_token::RlTokenError::WrongAudience => "Token is for a different plugin.",
                rl_token::RlTokenError::WrongIssuer => "Token was not issued by RoleLogic.",
            };
            render_inline_error(state, msg)
        })?;

    if verified.guild_id != guild_id || verified.role_id != role_id {
        return Err(render_inline_error(
            state,
            "Token does not match this role link.",
        ));
    }

    if verified.read_only {
        tracing::info!(
            guild_id,
            role_id,
            target = %verified.discord_id,
            actor = verified.actor_id.as_deref().unwrap_or("?"),
            "Role config opened read-only (developer impersonation)"
        );
    }

    // Carry the read-only flag into the minted iframe-session so every XHR is
    // gated; return it too so the page renders in read-only mode.
    let token = rl_token::mint_iframe_session(
        &verified.discord_id,
        guild_id,
        role_id,
        verified.read_only,
        &state.config.session_secret,
    );
    Ok((token, verified.read_only))
}

fn render_inline_error(state: &AppState, message: &str) -> Response {
    let base_url = &state.config.base_url;
    let msg = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cannot load configuration</title>
<link rel="icon" href="{base_url}/favicon.ico">
<style>body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e8eaed;padding:32px 24px;line-height:1.5}}
h1{{color:#fca5a5;font-size:18px;margin-bottom:10px}}p{{color:#9aa3b2}}</style>
</head><body><h1>Cannot load configuration</h1><p>{msg}</p>
<p style="margin-top:14px;color:#7a8497">If you opened this from the RoleLogic dashboard, close and reopen the role's plugin tab.</p>
</body></html>"##
    );
    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::FORBIDDEN,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
        ],
        body,
    )
        .into_response()
}

fn looks_embedded(headers: &HeaderMap) -> bool {
    let h = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase()
    };
    let dest = h("sec-fetch-dest");
    dest == "iframe" || dest == "frame" || h("sec-fetch-site") == "cross-site"
}

fn render_iframe_no_token(state: &AppState) -> Response {
    let base_url = &state.config.base_url;
    let body = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Configuration unavailable</title>
<link rel="icon" href="{base_url}/favicon.ico">
<style>body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e8eaed;padding:32px 24px;line-height:1.55;max-width:560px}}
h1{{color:#fbbf24;font-size:18px;margin:0 0 10px}}p{{color:#9aa3b2;margin:8px 0}}
code{{background:#0b0d12;padding:2px 6px;border-radius:4px;font-size:12px}}</style>
</head><body>
<h1>RoleLogic didn't pass an authentication token</h1>
<p>This plugin page must be opened from inside the RoleLogic dashboard, which
attaches a one-time token. None arrived with this request.</p>
<p><strong>If you're the server admin:</strong> close this tab and reopen the
role's plugin tab from RoleLogic. If it keeps happening, the plugin is
mis-registered — its <code>BASE_URL</code> must exactly match the URL
configured for this plugin in RoleLogic: HTTPS, no trailing slash, and
including the <code>/stripe-subscriber-role</code> path prefix.</p>
<p style="color:#7a8497;font-size:12px;margin-top:16px">Configured BASE_URL:
<code>{base_url}</code></p>
</body></html>"##
    );
    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
        ],
        body,
    )
        .into_response()
}

fn render_signin_page(state: &AppState, reason: &str) -> Response {
    let base_url = &state.config.base_url;
    let reason = reason
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — Stripe Subscriber Role</title>
<link rel="icon" href="{base_url}/favicon.ico">
<style>body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e8eaed;padding:48px 24px;max-width:520px;margin:0 auto;line-height:1.55}}
h1{{font-size:22px;margin:0 0 12px}}p{{color:#9aa3b2}}
a.btn{{display:inline-block;margin-top:18px;background:#635bff;color:#fff;padding:12px 22px;border-radius:8px;text-decoration:none;font-weight:600}}
.actions{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:18px}}
.actions a.btn{{margin-top:0}}
form.logout-form{{margin:0}}
button.logout{{background:none;color:#8a93a4;border:1px solid #2a2f3a;
  padding:10px 16px;border-radius:8px;font-size:13px;font-weight:600;
  cursor:pointer;font-family:inherit}}
button.logout:hover{{color:#fca5a5;border-color:#5c2630}}</style>
</head><body>
<h1>Sign in to continue</h1>
<p>You need <strong>Manage Server</strong> on this guild to edit its
Stripe-Subscriber-Role configuration.</p>
<p style="color:#7a8497;font-size:12px">{reason}</p>
<div class="actions">
  <a class="btn" id="login">Sign in with Discord</a>
  <form class="logout-form" method="POST" action="/auth/logout">
    <button type="submit" class="logout">Sign out &amp; try another account</button>
  </form>
</div>
<script>
const ORIGIN=new URL("{base_url}").origin;
const RET=encodeURIComponent(location.pathname);
document.getElementById('login').href=ORIGIN+'/auth/login?return_to='+RET;
document.querySelectorAll('form.logout-form').forEach(f=>{{
  f.action=ORIGIN+'/auth/logout?return_to='+RET;
}});
</script>
</body></html>"##
    );
    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
        ],
        body,
    )
        .into_response()
}

/// Dual gate: `Authorization: Bearer ifs:…` (iframe) OR cookie+manager (direct
/// nav). Returns the caller's discord_id (Convention 45).
/// Outcome of an access check for the role-config endpoints: who is calling and
/// whether the session is read-only (a developer impersonating the user).
struct RoleConfigAccess {
    #[allow(dead_code)]
    discord_id: String,
    read_only: bool,
}

async fn require_role_config_access(
    state: &Arc<AppState>,
    jar: &CookieJar,
    headers: &HeaderMap,
    guild_id: &str,
    role_id: &str,
) -> Result<RoleConfigAccess, AppError> {
    if let Some(bearer) = extract_bearer(headers) {
        let s = rl_token::verify_iframe_session(&bearer, &state.config.session_secret).ok_or_else(
            || {
                AppError::UnauthorizedWith(
                    "Your session expired. Reopen the plugin in the RoleLogic dashboard.".into(),
                )
            },
        )?;
        if s.guild_id != guild_id || s.role_id != role_id {
            return Err(AppError::Forbidden(
                "Token does not grant access to this role link.".into(),
            ));
        }
        return Ok(RoleConfigAccess {
            discord_id: s.discord_id,
            read_only: s.read_only,
        });
    }
    let discord_id = require_manager(state, jar, guild_id).await?;
    Ok(RoleConfigAccess {
        discord_id,
        read_only: false,
    })
}

// ---------------------------------------------------------------------------
// GET /admin/{guild_id}/role/{role_id}/data
// ---------------------------------------------------------------------------

pub async fn role_config_data(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;

    let link = sqlx::query_as::<_, (Option<i64>, Value, i32)>(
        "SELECT stripe_account_ref, rule_tree, rule_tree_version \
         FROM role_links WHERE guild_id = $1 AND role_id = $2",
    )
    .bind(&guild_id)
    .bind(&role_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| {
        AppError::NotFound("This role link doesn't exist. Has it been added in RoleLogic?".into())
    })?;
    let (stripe_account_ref, rule_tree, rule_tree_version) = link;
    let tree: RuleTree = serde_json::from_value(rule_tree).unwrap_or_default();

    let accounts_rows = load_accounts(&state, &guild_id).await?;
    let accounts: Vec<Value> = accounts_rows
        .iter()
        .map(|a| account_json(&state, a))
        .collect();

    Ok(Json(json!({
        "guild_id": guild_id,
        "role_id": role_id,
        "config": {
            "stripe_account_ref": stripe_account_ref,
            "grant_on_any_relation": tree.grant_on_any_relation,
            "groups": tree.groups,
        },
        "rule_tree_version": rule_tree_version,
        "accounts": accounts,
        "targets": target_catalog(),
        "operators": operator_catalog(),
        "limits": {
            "max_groups": MAX_GROUPS,
            "max_conditions_per_group": MAX_CONDITIONS_PER_GROUP,
        },
        "webhook_events": WEBHOOK_EVENTS,
        "verify_url": format!("{}/verify?guild={}", state.config.base_url, guild_id),
    })))
}

// ---------------------------------------------------------------------------
// POST /admin/{guild_id}/role/{role_id}/save  (optimistic-locked)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RoleConfigSaveBody {
    pub rule_tree_version: i32,
    #[serde(flatten)]
    pub tree: RuleTreeBody,
}

pub async fn role_config_save(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
    Json(body): Json<RoleConfigSaveBody>,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    let access = require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;
    // Read-only sessions (a developer impersonating the user) may view but not
    // write — the server-side half of the read-only contract.
    if access.read_only {
        return Err(AppError::Forbidden(
            "This configuration is read-only while impersonating a user.".into(),
        ));
    }

    let expected_version = body.rule_tree_version;

    // If an account is chosen, it must be one connected to THIS guild.
    if let Some(acct) = body.tree.stripe_account_ref {
        let ok: Option<i64> =
            sqlx::query_scalar("SELECT id FROM stripe_accounts WHERE id = $1 AND guild_id = $2")
                .bind(acct)
                .bind(&guild_id)
                .fetch_optional(&state.pool)
                .await?;
        if ok.is_none() {
            return Err(AppError::BadRequest(
                "Selected Stripe account isn't connected to this server.".into(),
            ));
        }
    }

    let parsed = rule_validator::parse_rule_tree(body.tree)?;

    // A rule needs a Stripe account to evaluate against; without one it would
    // grant the role to nobody. Reject so the dashboard surfaces why.
    if parsed.stripe_account_ref.is_none()
        && (parsed.rule_tree.grant_on_any_relation || !parsed.rule_tree.groups.is_empty())
    {
        return Err(AppError::BadRequest(
            "Connect a Stripe account and pick it for this rule before saving — \
             without one it would grant the role to nobody."
                .into(),
        ));
    }

    let tree_json = serde_json::to_value(&parsed.rule_tree)
        .map_err(|e| AppError::Internal(format!("serialize rule_tree: {e}")))?;

    let result = sqlx::query(
        "UPDATE role_links \
         SET stripe_account_ref = $1, rule_tree = $2, \
             rule_tree_version = rule_tree_version + 1, updated_at = now() \
         WHERE guild_id = $3 AND role_id = $4 AND rule_tree_version = $5",
    )
    .bind(parsed.stripe_account_ref)
    .bind(&tree_json)
    .bind(&guild_id)
    .bind(&role_id)
    .bind(expected_version)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        let exists: Option<i32> = sqlx::query_scalar(
            "SELECT rule_tree_version FROM role_links WHERE guild_id=$1 AND role_id=$2",
        )
        .bind(&guild_id)
        .bind(&role_id)
        .fetch_optional(&state.pool)
        .await?;
        return match exists {
            None => Err(AppError::NotFound(
                "This role link doesn't exist. Has it been added in RoleLogic?".into(),
            )),
            Some(_) => Err(AppError::StaleVersion),
        };
    }

    let new_version: i32 = sqlx::query_scalar(
        "SELECT rule_tree_version FROM role_links WHERE guild_id=$1 AND role_id=$2",
    )
    .bind(&guild_id)
    .bind(&role_id)
    .fetch_one(&state.pool)
    .await?;

    if let Err(e) = jobs::enqueue_config_sync(&state.pool, &guild_id, &role_id).await {
        tracing::warn!(
            guild_id,
            role_id,
            "enqueue config_sync after save failed: {e}"
        );
    }

    tracing::info!(
        guild_id,
        role_id,
        groups = parsed.rule_tree.groups.len(),
        grant_on_any = parsed.rule_tree.grant_on_any_relation,
        "Role rule_tree updated"
    );

    Ok(Json(
        json!({ "success": true, "rule_tree_version": new_version }),
    ))
}

// ---------------------------------------------------------------------------
// Preview (GET = saved tree, POST = proposed tree)
// ---------------------------------------------------------------------------

pub async fn role_config_preview(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;

    let link = sqlx::query_as::<_, (Option<i64>, Value)>(
        "SELECT stripe_account_ref, rule_tree FROM role_links WHERE guild_id=$1 AND role_id=$2",
    )
    .bind(&guild_id)
    .bind(&role_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Role link not found.".into()))?;
    let (account_ref, raw_tree) = link;
    let tree: RuleTree = serde_json::from_value(raw_tree).unwrap_or_default();

    preview_count_for(&state, &guild_id, account_ref, &tree).await
}

pub async fn role_config_preview_edit(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
    Json(body): Json<RuleTreeBody>,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;

    if let Some(acct) = body.stripe_account_ref {
        let ok: Option<i64> =
            sqlx::query_scalar("SELECT id FROM stripe_accounts WHERE id = $1 AND guild_id = $2")
                .bind(acct)
                .bind(&guild_id)
                .fetch_optional(&state.pool)
                .await?;
        if ok.is_none() {
            return Err(AppError::BadRequest(
                "Selected Stripe account isn't connected to this server.".into(),
            ));
        }
    }

    let parsed = rule_validator::parse_rule_tree(body)?;
    preview_count_for(
        &state,
        &guild_id,
        parsed.stripe_account_ref,
        &parsed.rule_tree,
    )
    .await
}

async fn preview_count_for(
    state: &Arc<AppState>,
    guild_id: &str,
    account_ref: Option<i64>,
    tree: &RuleTree,
) -> Result<Json<Value>, AppError> {
    let nobody = account_ref.is_none() || (!tree.grant_on_any_relation && tree.groups.is_empty());
    if nobody {
        return Ok(Json(
            json!({ "matching": 0, "linked": 0, "available": true }),
        ));
    }
    let account_ref = account_ref.expect("account bound checked above");

    // Mirror the sync engine's universe: everyone linked to this account minus
    // opt-outs (NOT gated on the gateway member list — see `sync_for_role_link`).
    let optout_ids = match auth_gateway::fetch_guild_optout_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        guild_id,
    )
    .await
    {
        Ok(v) => v,
        Err(_) => {
            return Ok(Json(json!({
                "available": false,
                "reason": "Opt-out list temporarily unavailable; preview will work once the Auth Gateway responds."
            })))
        }
    };

    let linked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM stripe_member_facts \
         WHERE account_ref = $1 AND discord_id <> ALL($2::text[])",
    )
    .bind(account_ref)
    .bind(&optout_ids)
    .fetch_one(&state.pool)
    .await?;

    if tree.grant_on_any_relation {
        return Ok(Json(json!({
            "available": true,
            "matching": linked,
            "linked": linked,
        })));
    }

    let (rule_where, binds) = rule_sql::build_rule_where(tree, 2);
    let query = format!(
        "SELECT count(*) FROM stripe_member_facts mf \
         WHERE mf.account_ref = $1 AND mf.discord_id <> ALL($2::text[]) AND ({rule_where})"
    );
    let mut q = sqlx::query_scalar::<_, i64>(&query)
        .bind(account_ref)
        .bind(&optout_ids);
    for b in &binds {
        q = match b {
            Bind::Bool(v) => q.bind(*v),
            Bind::Int(v) => q.bind(*v),
            Bind::Text(v) => q.bind(v.clone()),
            Bind::TextArray(v) => q.bind(v.clone()),
        };
    }
    let matching: i64 = q.fetch_one(&state.pool).await?;

    Ok(Json(json!({
        "available": true,
        "matching": matching,
        "linked": linked,
    })))
}

// ---------------------------------------------------------------------------
// Catalogs consumed by the rule-builder front-end
// ---------------------------------------------------------------------------

fn kind_str(k: TargetKind) -> &'static str {
    match k {
        TargetKind::Bool => "bool",
        TargetKind::Int => "int",
        TargetKind::String => "string",
        TargetKind::StringList => "string_list",
    }
}

#[derive(Serialize)]
struct TargetEntry {
    key: &'static str,
    label: &'static str,
    kind: &'static str,
    group: &'static str,
    is_money: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    picker: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    choices: Option<Vec<&'static str>>,
    help: &'static str,
}

fn target_catalog() -> Vec<Value> {
    use ConditionTarget::*;
    let status_choices = vec![
        "active",
        "trialing",
        "past_due",
        "canceled",
        "unpaid",
        "incomplete",
        "incomplete_expired",
        "paused",
    ];
    let interval_choices = vec!["day", "week", "month", "year"];

    let entry = |t: ConditionTarget,
                 label: &'static str,
                 group: &'static str,
                 picker: Option<&'static str>,
                 choices: Option<Vec<&'static str>>,
                 help: &'static str| {
        serde_json::to_value(TargetEntry {
            key: t.as_str(),
            label,
            kind: kind_str(t.kind()),
            group,
            is_money: t.is_money(),
            picker,
            choices,
            help,
        })
        .expect("TargetEntry serializes")
    };

    vec![
        // --- subscription ---
        entry(
            HasActiveSubscription,
            "Has an active subscription",
            "subscription",
            None,
            None,
            "True if they have any active or trialing subscription.",
        ),
        entry(
            SubscriptionStatus,
            "Subscription status",
            "subscription",
            None,
            Some(status_choices),
            "The most favorable status across their subscriptions.",
        ),
        entry(
            IsTrialing,
            "Is on a free trial",
            "subscription",
            None,
            None,
            "True while any subscription is in its trial period.",
        ),
        entry(
            IsPastDue,
            "Subscription is past due",
            "subscription",
            None,
            None,
            "A payment failed and the subscription is past due.",
        ),
        entry(
            CancelsAtPeriodEnd,
            "Set to cancel at period end",
            "subscription",
            None,
            None,
            "They cancelled but still have paid access until the period ends.",
        ),
        entry(
            ActiveSubscriptionCount,
            "Number of active subscriptions",
            "subscription",
            None,
            None,
            "How many active/trialing subscriptions they hold.",
        ),
        entry(
            SubscribedToProduct,
            "Subscribed to product",
            "subscription",
            Some("product"),
            None,
            "Active subscription to a specific product (pick by name).",
        ),
        entry(
            SubscribedToPrice,
            "Subscribed to price / plan",
            "subscription",
            Some("price"),
            None,
            "Active subscription to a specific price (pick by name).",
        ),
        entry(
            PlanAmount,
            "Plan price (per period)",
            "subscription",
            None,
            None,
            "Per-period charge of their highest active plan.",
        ),
        entry(
            BillingInterval,
            "Billing interval",
            "subscription",
            None,
            Some(interval_choices),
            "Billing interval of their primary active plan.",
        ),
        entry(
            SubscriptionAgeDays,
            "Days subscribed",
            "subscription",
            None,
            None,
            "Days since their current subscription started.",
        ),
        entry(
            DaysUntilRenewal,
            "Days until renewal",
            "subscription",
            None,
            None,
            "Days until the next renewal of their active plan.",
        ),
        entry(
            TotalMrr,
            "Monthly recurring value (MRR)",
            "subscription",
            None,
            None,
            "Normalized monthly value of all active subscriptions.",
        ),
        // --- customer ---
        entry(
            IsCustomer,
            "Is a customer",
            "customer",
            None,
            None,
            "True if they have any Stripe customer record.",
        ),
        entry(
            CustomerAgeDays,
            "Customer age (days)",
            "customer",
            None,
            None,
            "Days since they first became a customer.",
        ),
        entry(
            IsDelinquent,
            "Has an overdue balance",
            "customer",
            None,
            None,
            "Stripe marks the customer as delinquent (unpaid).",
        ),
        entry(
            LifetimeSpend,
            "Lifetime spend",
            "customer",
            None,
            None,
            "Total of their successful payments.",
        ),
        entry(
            SuccessfulPayments,
            "Successful payments",
            "customer",
            None,
            None,
            "Count of their successful charges.",
        ),
        entry(
            CountryCode,
            "Country code",
            "customer",
            None,
            None,
            "Customer billing country, e.g. US.",
        ),
        entry(
            Currency,
            "Currency",
            "customer",
            None,
            None,
            "Customer currency, e.g. usd.",
        ),
        entry(
            EmailDomain,
            "Email domain",
            "customer",
            None,
            None,
            "Domain of the customer email, e.g. acme.com.",
        ),
    ]
}

fn operator_catalog() -> Vec<Value> {
    use ConditionOperator::*;
    let all = [
        (Eq, "equals"),
        (Neq, "not equals"),
        (Gt, "greater than"),
        (Gte, "at least"),
        (Lt, "less than"),
        (Lte, "at most"),
        (Between, "between"),
        (Contains, "contains"),
        (Regex, "matches regex"),
        (In, "is one of"),
        (NotIn, "is not one of"),
    ];
    all.iter()
        .map(|(op, label)| {
            json!({
                "key": op.as_str(),
                "label": label,
                "valid_for": {
                    "bool": op.valid_for(TargetKind::Bool),
                    "int": op.valid_for(TargetKind::Int),
                    "string": op.valid_for(TargetKind::String),
                    "string_list": op.valid_for(TargetKind::StringList),
                },
                "needs_value_end": matches!(op, Between),
                "value_is_list": matches!(op, In | NotIn),
            })
        })
        .collect()
}
