use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::services::rl_token::constant_time_eq;

type HmacSha256 = Hmac<Sha256>;

/// Build a valid session cookie value. Production sessions are minted by the
/// Auth Gateway; this helper exists for tests (and for any future plugin-side
/// minting flow). Kept `cfg(test)` to avoid drift from the gateway's format.
#[cfg(test)]
pub(crate) fn mint_session(
    discord_id: &str,
    display_name: &str,
    expires_unix: i64,
    secret: &str,
) -> String {
    let encoded_name = urlencoding::encode(display_name);
    let payload = format!("{discord_id}:{encoded_name}:{expires_unix}");
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("{payload}:{sig}")
}

/// Verify and extract (discord_id, display_name) from a signed session cookie.
///
/// Cookie format: `discord_id:url_encoded_name:expires_unix:hex_hmac_sig`.
/// The HMAC is taken over the first three fields with `secret` as the key.
pub fn verify_session(cookie_value: &str, secret: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = cookie_value.splitn(4, ':').collect();
    if parts.len() != 4 {
        return None;
    }

    let discord_id = parts[0];
    let encoded_name = parts[1];
    let expires_str = parts[2];
    let sig = parts[3];

    let expires: i64 = expires_str.parse().ok()?;
    if chrono::Utc::now().timestamp() > expires {
        return None;
    }

    let payload = format!("{discord_id}:{encoded_name}:{expires_str}");
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());

    let expected_sig = hex::encode(mac.finalize().into_bytes());
    if !constant_time_eq(sig.as_bytes(), expected_sig.as_bytes()) {
        return None;
    }

    let display_name = urlencoding::decode(encoded_name).ok()?.into_owned();
    Some((discord_id.to_string(), display_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-do-not-use-in-production";

    fn far_future() -> i64 {
        chrono::Utc::now().timestamp() + 3600
    }

    fn far_past() -> i64 {
        chrono::Utc::now().timestamp() - 3600
    }

    #[test]
    fn verify_round_trip() {
        let cookie = mint_session("123", "Alice", far_future(), SECRET);
        let (id, name) = verify_session(&cookie, SECRET).expect("valid cookie should verify");
        assert_eq!(id, "123");
        assert_eq!(name, "Alice");
    }

    #[test]
    fn verify_unicode_display_name() {
        let cookie = mint_session("123", "Aliçe 🦀", far_future(), SECRET);
        let (_, name) = verify_session(&cookie, SECRET).expect("unicode name should round-trip");
        assert_eq!(name, "Aliçe 🦀");
    }

    #[test]
    fn verify_rejects_expired() {
        let cookie = mint_session("123", "Alice", far_past(), SECRET);
        assert!(verify_session(&cookie, SECRET).is_none());
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let cookie = mint_session("123", "Alice", far_future(), SECRET);
        let mut tampered = cookie.clone();
        let last = tampered.pop().unwrap();
        let new_last = if last == '0' { '1' } else { '0' };
        tampered.push(new_last);
        assert!(verify_session(&tampered, SECRET).is_none());
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let cookie = mint_session("123", "Alice", far_future(), SECRET);
        assert!(verify_session(&cookie, "different-secret").is_none());
    }

    #[test]
    fn verify_rejects_id_swap() {
        let cookie = mint_session("alice", "Alice", far_future(), SECRET);
        let parts: Vec<&str> = cookie.splitn(4, ':').collect();
        let forged = format!("eve:{}:{}:{}", parts[1], parts[2], parts[3]);
        assert!(verify_session(&forged, SECRET).is_none());
    }

    #[test]
    fn verify_rejects_malformed() {
        assert!(verify_session("", SECRET).is_none());
        assert!(verify_session("only-one-part", SECRET).is_none());
        assert!(verify_session("a:b:c", SECRET).is_none());
        assert!(verify_session("a:b:not-a-number:c", SECRET).is_none());
    }
}
