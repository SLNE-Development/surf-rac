//! Random secrets, hashing and password verification.

use std::sync::LazyLock;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Returns `bytes` cryptographically random bytes encoded as unpadded base64url.
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Returns the SHA-256 digest of `s`.
pub fn sha256(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}

/// Hashes `password` with argon2id and a random salt, in PHC string format.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

/// Returns true when `password` matches the PHC `hash`; false for a malformed hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

/// A valid hash of a random password, used to spend equal time on unknown usernames.
static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| hash_password(&random_token(16)).expect("hashing a dummy password"));

/// Verifies `password` against a throwaway hash and always returns false.
///
/// Makes a login for a missing or disabled account cost as much as a real one.
pub fn verify_dummy(password: &str) -> bool {
    let _ = verify_password(password, &DUMMY_HASH);
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_token_length_and_charset() {
        let t = random_token(32);
        assert_eq!(t.len(), 43);
        assert!(t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_ne!(random_token(32), t);
    }

    #[test]
    fn sha256_is_stable() {
        assert_eq!(sha256("abc").len(), 32);
        assert_eq!(sha256("abc"), sha256("abc"));
        assert_ne!(sha256("abc"), sha256("abd"));
    }

    #[test]
    fn password_round_trip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong", &h));
        assert!(!verify_password("x", "not a hash"));
    }
}
