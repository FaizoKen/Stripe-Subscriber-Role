//! Verify the short-lived JWT RoleLogic appends as `?rl_token=…` when the
//! dashboard embeds our role-config page in an iframe.
//!
//! Format: HS256 JWT signed with this role link's raw API token (the same
//! `rl_…` token we stored on `POST /register`). Plugin-side verification is
//! local — no callback to RoleLogic.
//!
//! Claims: `iss=rolelogic`, `aud=plugin_url`, `sub=discord_id`, `guild_id`,
//! `role_id`, `iat`, `exp` (issued for 5 min).

use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const ALLOWED_SKEW_SECS: i64 = 60;

#[derive(Debug)]
pub enum RlTokenError {
    Malformed,
    BadSignature,
    Expired,
    WrongAudience,
    WrongIssuer,
}

#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    guild_id: String,
    role_id: String,
    exp: i64,
}

pub struct Verified {
    pub discord_id: String,
    pub guild_id: String,
    pub role_id: String,
}

/// Verify the JWT and return the admin's identity bound to (guild_id, role_id).
///
/// `role_link_token` is the raw `rl_…` API token RoleLogic gave us at
/// `POST /register` (HS256 secret). `expected_aud` is our own `BASE_URL`
/// (what RoleLogic stores as `plugin_url`).
pub fn verify(
    token: &str,
    role_link_token: &str,
    expected_aud: &str,
) -> Result<Verified, RlTokenError> {
    let mut parts = token.splitn(3, '.');
    let header_b64 = parts.next().ok_or(RlTokenError::Malformed)?;
    let payload_b64 = parts.next().ok_or(RlTokenError::Malformed)?;
    let sig_b64 = parts.next().ok_or(RlTokenError::Malformed)?;
    if parts.next().is_some() {
        return Err(RlTokenError::Malformed);
    }

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_bytes = b64
        .decode(header_b64)
        .map_err(|_| RlTokenError::Malformed)?;
    let payload_bytes = b64
        .decode(payload_b64)
        .map_err(|_| RlTokenError::Malformed)?;
    let sig_bytes = b64.decode(sig_b64).map_err(|_| RlTokenError::Malformed)?;

    let header: Header =
        serde_json::from_slice(&header_bytes).map_err(|_| RlTokenError::Malformed)?;
    if header.alg != "HS256" {
        return Err(RlTokenError::BadSignature);
    }
    if let Some(typ) = header.typ.as_deref() {
        if !typ.eq_ignore_ascii_case("JWT") {
            return Err(RlTokenError::Malformed);
        }
    }

    let signed_input = format!("{header_b64}.{payload_b64}");
    let mut mac = HmacSha256::new_from_slice(role_link_token.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(signed_input.as_bytes());
    mac.verify_slice(&sig_bytes)
        .map_err(|_| RlTokenError::BadSignature)?;

    let claims: Claims =
        serde_json::from_slice(&payload_bytes).map_err(|_| RlTokenError::Malformed)?;
    if claims.iss != "rolelogic" {
        return Err(RlTokenError::WrongIssuer);
    }
    if !aud_matches(&claims.aud, expected_aud) {
        return Err(RlTokenError::WrongAudience);
    }
    let now = chrono::Utc::now().timestamp();
    if now > claims.exp + ALLOWED_SKEW_SECS {
        return Err(RlTokenError::Expired);
    }

    Ok(Verified {
        discord_id: claims.sub,
        guild_id: claims.guild_id,
        role_id: claims.role_id,
    })
}

fn aud_matches(claim_aud: &str, expected: &str) -> bool {
    claim_aud.trim_end_matches('/') == expected.trim_end_matches('/')
}

// -------------------------------------------------------------------------
// Iframe-session token: minted after a successful `rl_token` verification,
// embedded in the rendered role-config page, and sent as `Authorization:
// Bearer …` on every subsequent XHR from the iframe.
//
// Bound to (discord_id, guild_id, role_id) so leakage of one token cannot
// be used to edit a different role link. Signed with `session_secret`.
//
// Format: `ifs:{discord_id}:{guild_id}:{role_id}:{exp}:{hmac_hex}` — the
// `ifs:` prefix disambiguates from the cookie session token in
// [services::session].
// -------------------------------------------------------------------------

const IFRAME_PREFIX: &str = "ifs:";
const IFRAME_TTL_SECS: i64 = 60 * 60; // 1 hour edit window per token

pub fn mint_iframe_session(
    discord_id: &str,
    guild_id: &str,
    role_id: &str,
    session_secret: &str,
) -> String {
    let exp = chrono::Utc::now().timestamp() + IFRAME_TTL_SECS;
    let payload = format!("{discord_id}:{guild_id}:{role_id}:{exp}");
    let mut mac =
        HmacSha256::new_from_slice(session_secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("{IFRAME_PREFIX}{payload}:{sig}")
}

pub struct IframeSession {
    pub discord_id: String,
    pub guild_id: String,
    pub role_id: String,
}

pub fn verify_iframe_session(token: &str, session_secret: &str) -> Option<IframeSession> {
    let rest = token.strip_prefix(IFRAME_PREFIX)?;
    let parts: Vec<&str> = rest.splitn(5, ':').collect();
    if parts.len() != 5 {
        return None;
    }
    let discord_id = parts[0];
    let guild_id = parts[1];
    let role_id = parts[2];
    let exp_str = parts[3];
    let sig = parts[4];

    let exp: i64 = exp_str.parse().ok()?;
    if chrono::Utc::now().timestamp() > exp {
        return None;
    }

    let payload = format!("{discord_id}:{guild_id}:{role_id}:{exp_str}");
    let mut mac =
        HmacSha256::new_from_slice(session_secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    if !constant_time_eq(sig.as_bytes(), expected.as_bytes()) {
        return None;
    }

    Some(IframeSession {
        discord_id: discord_id.to_string(),
        guild_id: guild_id.to_string(),
        role_id: role_id.to_string(),
    })
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;

    const ROLE_TOKEN: &str = "rl_test_token_must_match_what_role_logic_signed_with";
    const PLUGIN_AUD: &str = "https://plugin.example/kick-channel-role";
    const SESSION_SECRET: &str = "session-secret-not-for-prod";

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn mint_jwt(
        role_token: &str,
        aud: &str,
        sub: &str,
        guild_id: &str,
        role_id: &str,
        exp: i64,
    ) -> String {
        let header = json!({ "alg": "HS256", "typ": "JWT" });
        let payload = json!({
            "iss": "rolelogic",
            "aud": aud,
            "sub": sub,
            "guild_id": guild_id,
            "role_id": role_id,
            "iat": chrono::Utc::now().timestamp(),
            "exp": exp,
        });
        let h = b64(serde_json::to_vec(&header).unwrap().as_slice());
        let p = b64(serde_json::to_vec(&payload).unwrap().as_slice());
        let signing_input = format!("{h}.{p}");
        let mut mac = HmacSha256::new_from_slice(role_token.as_bytes()).unwrap();
        mac.update(signing_input.as_bytes());
        let sig = b64(mac.finalize().into_bytes().as_slice());
        format!("{signing_input}.{sig}")
    }

    fn far_future() -> i64 {
        chrono::Utc::now().timestamp() + 3600
    }

    #[test]
    fn cteq_equal_and_unequal() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn jwt_round_trip() {
        let token = mint_jwt(ROLE_TOKEN, PLUGIN_AUD, "user1", "g1", "r1", far_future());
        let verified = verify(&token, ROLE_TOKEN, PLUGIN_AUD).expect("valid JWT");
        assert_eq!(verified.discord_id, "user1");
        assert_eq!(verified.guild_id, "g1");
        assert_eq!(verified.role_id, "r1");
    }

    #[test]
    fn jwt_audience_trailing_slash_tolerated() {
        let token = mint_jwt(
            ROLE_TOKEN,
            &format!("{PLUGIN_AUD}/"),
            "u",
            "g",
            "r",
            far_future(),
        );
        assert!(verify(&token, ROLE_TOKEN, PLUGIN_AUD).is_ok());
        let token2 = mint_jwt(ROLE_TOKEN, PLUGIN_AUD, "u", "g", "r", far_future());
        assert!(verify(&token2, ROLE_TOKEN, &format!("{PLUGIN_AUD}/")).is_ok());
    }

    #[test]
    fn jwt_rejects_wrong_aud() {
        let token = mint_jwt(
            ROLE_TOKEN,
            "https://other-plugin.example",
            "u",
            "g",
            "r",
            far_future(),
        );
        assert!(matches!(
            verify(&token, ROLE_TOKEN, PLUGIN_AUD),
            Err(RlTokenError::WrongAudience)
        ));
    }

    #[test]
    fn jwt_rejects_wrong_issuer() {
        let header = b64(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = b64(serde_json::to_vec(&json!({
            "iss": "attacker",
            "aud": PLUGIN_AUD,
            "sub": "u",
            "guild_id": "g",
            "role_id": "r",
            "exp": far_future(),
        }))
        .unwrap()
        .as_slice());
        let input = format!("{header}.{payload}");
        let mut mac = HmacSha256::new_from_slice(ROLE_TOKEN.as_bytes()).unwrap();
        mac.update(input.as_bytes());
        let sig = b64(mac.finalize().into_bytes().as_slice());
        let token = format!("{input}.{sig}");
        assert!(matches!(
            verify(&token, ROLE_TOKEN, PLUGIN_AUD),
            Err(RlTokenError::WrongIssuer)
        ));
    }

    #[test]
    fn jwt_rejects_bad_signature() {
        let token = mint_jwt(ROLE_TOKEN, PLUGIN_AUD, "u", "g", "r", far_future());
        assert!(matches!(
            verify(&token, "different-role-token", PLUGIN_AUD),
            Err(RlTokenError::BadSignature)
        ));
    }

    #[test]
    fn jwt_rejects_expired() {
        let token = mint_jwt(
            ROLE_TOKEN,
            PLUGIN_AUD,
            "u",
            "g",
            "r",
            chrono::Utc::now().timestamp() - 300,
        );
        assert!(matches!(
            verify(&token, ROLE_TOKEN, PLUGIN_AUD),
            Err(RlTokenError::Expired)
        ));
    }

    #[test]
    fn jwt_rejects_non_hs256_alg() {
        let header = b64(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = b64(br#"{"iss":"rolelogic","aud":"x","sub":"u","guild_id":"g","role_id":"r","exp":99999999999}"#);
        let token = format!("{header}.{payload}.");
        assert!(matches!(
            verify(&token, ROLE_TOKEN, PLUGIN_AUD),
            Err(RlTokenError::BadSignature) | Err(RlTokenError::Malformed)
        ));
    }

    #[test]
    fn jwt_rejects_malformed() {
        assert!(matches!(
            verify("not-a-jwt", ROLE_TOKEN, PLUGIN_AUD),
            Err(RlTokenError::Malformed)
        ));
        assert!(matches!(
            verify("only.two", ROLE_TOKEN, PLUGIN_AUD),
            Err(RlTokenError::Malformed)
        ));
        assert!(matches!(
            verify("a.b.c.d", ROLE_TOKEN, PLUGIN_AUD),
            Err(RlTokenError::Malformed)
        ));
    }

    #[test]
    fn iframe_session_round_trip() {
        let token = mint_iframe_session("user1", "g1", "r1", SESSION_SECRET);
        let s = verify_iframe_session(&token, SESSION_SECRET).expect("valid iframe token");
        assert_eq!(s.discord_id, "user1");
        assert_eq!(s.guild_id, "g1");
        assert_eq!(s.role_id, "r1");
    }

    #[test]
    fn iframe_session_rejects_wrong_secret() {
        let token = mint_iframe_session("u", "g", "r", SESSION_SECRET);
        assert!(verify_iframe_session(&token, "wrong-secret").is_none());
    }

    #[test]
    fn iframe_session_rejects_pivot() {
        let token = mint_iframe_session("alice", "g1", "r1", SESSION_SECRET);
        let rest = token.strip_prefix("ifs:").unwrap();
        let parts: Vec<&str> = rest.splitn(5, ':').collect();
        let forged = format!("ifs:{}:{}:r2:{}:{}", parts[0], parts[1], parts[3], parts[4]);
        assert!(verify_iframe_session(&forged, SESSION_SECRET).is_none());
    }

    #[test]
    fn iframe_session_rejects_missing_prefix() {
        let token = mint_iframe_session("u", "g", "r", SESSION_SECRET);
        let no_prefix = token.strip_prefix("ifs:").unwrap();
        assert!(verify_iframe_session(no_prefix, SESSION_SECRET).is_none());
    }
}
