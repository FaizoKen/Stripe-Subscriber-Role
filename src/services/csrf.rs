//! Origin-based CSRF defense for cookie-authenticated state-changing routes.
//!
//! The browser-side `CorsLayer` allowlist already prevents cross-origin XHR
//! with credentials from non-allowlisted sites, but it relies on the browser
//! honoring CORS. This server-side check is a second wall: it inspects the
//! `Origin` header on every state-changing admin request and rejects the
//! request if the origin isn't on our allowlist. A browser will always set
//! `Origin` on POST/PUT/DELETE from a real page; non-browser callers (curl,
//! server-to-server) won't, which is exactly what we want to reject on admin
//! write paths.
//!
//! Routes that authenticate via `Authorization: Bearer ifs:…` (the iframe
//! session) do NOT need Origin checks — the token's HMAC binding to
//! `(discord_id, guild_id, role_id)` is itself the CSRF defense, and a real
//! attacker can't make a victim's browser attach an `Authorization` header
//! the way it auto-attaches cookies.

use axum::http::HeaderMap;

use crate::error::AppError;

/// Verify the request's `Origin` matches one of the allowed origins.
/// Returns an error if the header is missing or the value doesn't match.
pub fn verify_origin(headers: &HeaderMap, allowed_origins: &[String]) -> Result<(), AppError> {
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            AppError::Forbidden("State-changing requests must include an Origin header.".into())
        })?;

    let origin_norm = origin.trim_end_matches('/');
    for allowed in allowed_origins {
        if origin_norm == allowed.trim_end_matches('/') {
            return Ok(());
        }
    }
    Err(AppError::Forbidden(format!(
        "Origin '{origin}' is not allowed for state-changing requests."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_origin(origin: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("origin", HeaderValue::from_str(origin).unwrap());
        h
    }

    fn allowed() -> Vec<String> {
        vec![
            "https://app.rolelogic.com".into(),
            "https://plugin.example.com".into(),
        ]
    }

    #[test]
    fn accepts_exact_match() {
        let h = headers_with_origin("https://app.rolelogic.com");
        assert!(verify_origin(&h, &allowed()).is_ok());
    }

    #[test]
    fn accepts_trailing_slash() {
        let h = headers_with_origin("https://app.rolelogic.com/");
        assert!(verify_origin(&h, &allowed()).is_ok());
    }

    #[test]
    fn rejects_missing_origin_header() {
        let h = HeaderMap::new();
        match verify_origin(&h, &allowed()) {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[test]
    fn rejects_attacker_origin() {
        let h = headers_with_origin("https://evil.example");
        assert!(verify_origin(&h, &allowed()).is_err());
    }

    #[test]
    fn rejects_subdomain_of_allowed() {
        let h = headers_with_origin("https://attacker.rolelogic.com");
        assert!(verify_origin(&h, &allowed()).is_err());
    }

    #[test]
    fn rejects_path_in_origin_value() {
        let h = headers_with_origin("https://app.rolelogic.com/anything");
        assert!(verify_origin(&h, &allowed()).is_err());
    }

    #[test]
    fn rejects_scheme_downgrade() {
        let h = headers_with_origin("http://app.rolelogic.com");
        assert!(verify_origin(&h, &allowed()).is_err());
    }
}
