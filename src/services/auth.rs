//! Admin-permission helpers used by routes that mix cookie-auth (direct nav)
//! and iframe-Bearer auth (RoleLogic iframe).
//!
//! Direct-nav routes call `require_manager()` which reads `rl_session`,
//! verifies it locally, then queries the Auth Gateway for guild manage-server
//! permission. Iframe-Bearer routes verify the `ifs:` token via
//! [services::rl_token::verify_iframe_session] before reaching this module.

use std::sync::Arc;

use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;

use crate::error::AppError;
use crate::services::rl_token;
use crate::services::session::verify_session;
use crate::AppState;

#[derive(Debug, Deserialize)]
struct GuildPermissionResp {
    #[serde(default)]
    is_member: bool,
    #[serde(default)]
    is_manager: bool,
}

/// Classify a non-success Auth Gateway HTTP response.
///
/// Only a genuine `401 Unauthorized` means the caller's session is actually
/// bad (cookie rejected by the gateway despite passing local verification —
/// e.g. a `SESSION_SECRET` mismatch). That stays `UnauthorizedWith` so
/// user-facing pages show a "sign in" prompt.
///
/// EVERY other non-success status — 502/503/504 from a gateway
/// restart/deploy, a Cloudflare Tunnel blip, gateway overload — is a
/// *transient server problem*, NOT the user being logged out. Mapping those
/// to `Internal` (HTTP 500) is what stops the users page from falsely
/// telling a signed-in member to re-authenticate on every gateway hiccup
/// (the "sometimes the users page doesn't work" symptom). Mirrors
/// `Genshin-Player-Role/src/routes/players.rs::auth_gateway_get` and
/// BLUEPRINT §16.5.
fn classify_gateway_status(status: reqwest::StatusCode, body: &str, gateway_url: &str) -> AppError {
    if status == reqwest::StatusCode::UNAUTHORIZED {
        AppError::UnauthorizedWith(format!(
            "The Auth Gateway rejected your session ({status}). Please sign in again."
        ))
    } else {
        AppError::Internal(format!(
            "Auth Gateway at {gateway_url} returned {status}: {body}"
        ))
    }
}

/// Pull `rl_session` cookie value via CookieJar (Convention 35) and verify it.
pub fn read_session(jar: &CookieJar, secret: &str) -> Result<(String, String), AppError> {
    let cookie = jar.get("rl_session").ok_or_else(|| {
        AppError::UnauthorizedWith("Not signed in. Log in with Discord to continue.".into())
    })?;
    verify_session(cookie.value(), secret)
        .ok_or_else(|| AppError::UnauthorizedWith("Session expired or invalid.".into()))
}

/// Verify the caller has manage-server on `guild_id`. Returns the caller's
/// discord_id on success.
pub async fn require_manager(
    state: &Arc<AppState>,
    jar: &CookieJar,
    guild_id: &str,
) -> Result<String, AppError> {
    let (discord_id, _) = read_session(jar, &state.config.session_secret)?;

    // Forward the cookie value to the Auth Gateway. Convention 31:
    // re-encode through Cookie::encoded() so the gateway's `parse_encoded`
    // doesn't double-decode names containing percent-escapes.
    let cookie_val = jar
        .get("rl_session")
        .map(|c| {
            Cookie::build(("rl_session", c.value().to_string()))
                .build()
                .encoded()
                .to_string()
        })
        .unwrap_or_default();

    let url = format!(
        "{}/auth/guild_permission?guild_id={guild_id}",
        state.config.auth_gateway_url
    );
    let resp = state
        .http
        .get(&url)
        .header("Cookie", cookie_val)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway permission request: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(classify_gateway_status(
            status,
            &body,
            &state.config.auth_gateway_url,
        ));
    }
    let parsed: GuildPermissionResp = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway response not JSON: {e}")))?;
    if !parsed.is_member {
        return Err(AppError::Forbidden(
            "You're not a member of this server.".into(),
        ));
    }
    if !parsed.is_manager {
        return Err(AppError::Forbidden(
            "You need Manage Server to do this.".into(),
        ));
    }
    Ok(discord_id)
}

/// Extract an `Authorization: Bearer ifs:…` token if present. Used by
/// dual-mode admin XHRs (Convention 42/45).
pub fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<String> {
    let val = headers.get("authorization")?.to_str().ok()?;
    val.strip_prefix("Bearer ").map(String::from)
}

/// Guild-scoped dual gate for admin actions that aren't tied to a single
/// role link (broadcaster connect/list/disconnect, per-guild settings).
///
/// Accepts EITHER an iframe-session `Bearer ifs:…` bound to this guild, OR
/// the `rl_session` cookie + Auth-Gateway manager check (direct nav). The
/// iframe-session is only minted after a valid RoleLogic `rl_token` for a
/// role link in this guild, so guild-scoped trust is appropriate here
/// (Convention 45). Returns the caller's discord_id.
pub async fn require_guild_admin(
    state: &Arc<AppState>,
    jar: &CookieJar,
    headers: &axum::http::HeaderMap,
    guild_id: &str,
) -> Result<String, AppError> {
    if let Some(bearer) = extract_bearer(headers) {
        let s = rl_token::verify_iframe_session(&bearer, &state.config.session_secret).ok_or_else(
            || {
                AppError::UnauthorizedWith(
                    "Your session expired. Reopen the plugin in the RoleLogic dashboard.".into(),
                )
            },
        )?;
        if s.guild_id != guild_id {
            return Err(AppError::Forbidden(
                "Token does not grant access to this server.".into(),
            ));
        }
        return Ok(s.discord_id);
    }
    require_manager(state, jar, guild_id).await
}
