//! Server-to-server client for the centralized Auth Gateway's
//! `/auth/internal/*` endpoints.
//!
//! Background sync workers don't have a logged-in user cookie, so they call
//! these internal endpoints (header-authed via `X-Internal-Key`) instead of
//! the user-cookie-authed `/auth/guild_permission` and `/auth/guild_members`.
//!
//! All errors are bubbled up — callers (sync workers) should log and skip
//! the affected user/role-link this cycle (Convention 40), NEVER catch and
//! return an empty list, which would clear the role from every member on
//! every transient gateway hiccup.

use serde::Deserialize;

use crate::error::AppError;

/// Plugin slug sent to the Auth Gateway. Must match the URL prefix this
/// plugin is mounted under (`/stripe-subscriber-role`) and the entry in the
/// gateway's plugin registry. The gateway uses this to scope the user's
/// per-(plugin × server) opt-outs when filtering guild lists.
const PLUGIN_SLUG: &str = "stripe-subscriber-role";

#[derive(Debug, Deserialize)]
struct UserGuildIdsResponse {
    guild_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GuildOptoutIdsResponse {
    discord_ids: Vec<String>,
}

pub async fn fetch_user_guild_ids(
    http: &reqwest::Client,
    base: &str,
    key: &str,
    discord_id: &str,
) -> Result<Vec<String>, AppError> {
    let url = format!("{base}/auth/internal/user_guild_ids");
    let resp = http
        .get(&url)
        .header("X-Internal-Key", key)
        // `plugin` scopes the response to this plugin's opt-out preferences
        // so guilds where the user disabled this plugin are excluded.
        .query(&[("discord_id", discord_id), ("plugin", PLUGIN_SLUG)])
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway request failed: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "auth_gateway user_guild_ids returned {status}: {body}"
        )));
    }

    let parsed: UserGuildIdsResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway response not JSON: {e}")))?;
    Ok(parsed.guild_ids)
}

/// Discord IDs that have opted OUT of this guild for this plugin (or guild-wide).
///
/// Plugins whose candidate set comes from their own linked data — rather than
/// the gateway's member list — subtract these so the centralized opt-out
/// system is still honored for members the gateway has never seen log in.
///
/// Errors bubble up (Convention 40): the caller must retry, NEVER treat a
/// gateway hiccup as "nobody opted out" — doing so would re-grant a role the
/// member explicitly stripped.
pub async fn fetch_guild_optout_ids(
    http: &reqwest::Client,
    base: &str,
    key: &str,
    guild_id: &str,
) -> Result<Vec<String>, AppError> {
    let url = format!("{base}/auth/internal/guild_optout_ids");
    let resp = http
        .get(&url)
        .header("X-Internal-Key", key)
        .query(&[("guild_id", guild_id), ("plugin", PLUGIN_SLUG)])
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway request failed: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "auth_gateway guild_optout_ids returned {status}: {body}"
        )));
    }

    let parsed: GuildOptoutIdsResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway response not JSON: {e}")))?;
    Ok(parsed.discord_ids)
}
