//! RoleLogic GET/POST /config helpers. Iframe UI mode (Section 1b of the
//! plugin blueprint) — `GET /config` returns an embed URL pointing at the
//! plugin's own role-config page; all real editing happens there.
//!
//! POST /config is a no-op kept for contract compliance: iframe-mode plugins
//! never receive it in practice, but we still verify the token so a stale call
//! can't ping silently.

use serde_json::{json, Value};

/// Build the iframe-mode response returned by GET /config. RoleLogic appends
/// `?rl_token=<jwt>` to `embed_url` before rendering the iframe; the admin page
/// verifies that token locally (Section 1b.3) to authenticate the admin.
pub fn build_iframe_config(base_url: &str, guild_id: &str, role_id: &str) -> Value {
    let embed_url = format!("{base_url}/admin/{guild_id}/role/{role_id}");
    json!({
        "version": 1,
        "ui_mode": "iframe",
        "name": "Stripe Subscriber Role",
        "description": "Grant Discord roles from Stripe — active subscribers, specific plans, trials, lifetime spend, and more, with rich condition logic.",
        "embed_url": embed_url,
    })
}

/// POST /config is unreachable in iframe mode; the contract still expects 200.
pub fn accept_empty_config() -> Value {
    json!({ "success": true })
}
