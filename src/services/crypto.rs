//! At-rest encryption for sensitive secrets (Kick OAuth access/refresh tokens).
//!
//! Threat model: an attacker who exfiltrates the database (a dump, a stolen
//! backup, a SQL-injection that reads BYTEA columns) cannot impersonate the
//! broadcaster against Kick without also stealing `SESSION_SECRET` from the
//! plugin's environment. This is a meaningful defense-in-depth boundary;
//! it does NOT protect against an attacker with full host access.
//!
//! Construction:
//!   * KEK = HKDF-SHA256(SESSION_SECRET, salt=fixed, info="stripe-subscriber-role/v1/kek")
//!   * Each ciphertext = nonce(12B) || AES-256-GCM(KEK, nonce, plaintext, aad=tag-context)
//!   * Stored as a single BYTEA so column shape doesn't leak structure.
//!
//! The nonce is random per-encryption (12 bytes is GCM-standard) and stored
//! inline — never reused with the same key. Rotating SESSION_SECRET means
//! every encrypted token must be re-encrypted; surface a `migrate_kek`
//! binary if/when that becomes necessary.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

const NONCE_BYTES: usize = 12;
const HKDF_INFO: &[u8] = b"stripe-subscriber-role/v1/kek";
const HKDF_SALT: &[u8] = b"stripe-subscriber-role/v1/salt";
const AAD: &[u8] = b"stripe-subscriber-role/v1/oauth-token";

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("ciphertext too short")]
    TooShort,
    #[error("decrypt failed")]
    DecryptFailed,
}

fn derive_kek(session_secret: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), session_secret.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(HKDF_INFO, &mut out)
        .expect("HKDF expand never fails for 32-byte output");
    out
}

pub fn encrypt(session_secret: &str, plaintext: &[u8]) -> Vec<u8> {
    let kek = derive_kek(session_secret);
    let cipher = Aes256Gcm::new_from_slice(&kek).expect("AES-256-GCM accepts 32-byte key");
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .expect("AES-256-GCM encrypt cannot fail with valid inputs");

    let mut out = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

pub fn decrypt(session_secret: &str, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < NONCE_BYTES + 16 {
        // 16 is the GCM tag length. Below that there's no way for it to be a
        // valid ciphertext + tag.
        return Err(CryptoError::TooShort);
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_BYTES);
    let kek = derive_kek(session_secret);
    let cipher = Aes256Gcm::new_from_slice(&kek).expect("AES-256-GCM accepts 32-byte key");
    cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload { msg: ct, aad: AAD },
        )
        .map_err(|_| CryptoError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "session-secret-not-for-prod";

    #[test]
    fn round_trip_short() {
        let pt = b"hello";
        let ct = encrypt(SECRET, pt);
        let decrypted = decrypt(SECRET, &ct).unwrap();
        assert_eq!(&decrypted, pt);
    }

    #[test]
    fn round_trip_real_token_size() {
        let pt = b"kck_access_token_kf83hf83hf83hf8hf8h83hf83hf83hf83hf83hf83hf83hf83hf83hf";
        let ct = encrypt(SECRET, pt);
        assert_ne!(&ct, pt);
        let decrypted = decrypt(SECRET, &ct).unwrap();
        assert_eq!(decrypted.as_slice(), pt);
    }

    #[test]
    fn nonce_is_unique() {
        let pt = b"same-plaintext";
        let a = encrypt(SECRET, pt);
        let b = encrypt(SECRET, pt);
        assert_ne!(a, b, "fresh nonce must change ciphertext");
    }

    #[test]
    fn wrong_secret_fails() {
        let ct = encrypt(SECRET, b"x");
        assert!(decrypt("wrong-secret", &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut ct = encrypt(SECRET, b"x");
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(decrypt(SECRET, &ct).is_err());
    }

    #[test]
    fn too_short_blob_errors() {
        assert!(matches!(
            decrypt(SECRET, b"abc"),
            Err(CryptoError::TooShort)
        ));
    }
}
