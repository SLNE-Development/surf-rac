//! Device keys, per-session key derivation and sealing of data messages.
//!
//! Each device owns an X25519 key pair. Host and viewer derive the same
//! 32-byte session key from their key pair, the peer's public key, the
//! session ID and both device IDs. Data is sealed with ChaCha20-Poly1305
//! under a random 96-bit nonce, bound to its topic and session.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use surf_rac_protocol::DeviceId;
use x25519_dalek::StaticSecret;

/// HKDF info prefix of session keys.
const KDF_INFO: &[u8] = b"surf-rac session v1";

/// Length of the nonce prefixed to sealed data.
const NONCE_LEN: usize = 12;

/// Why a key or sealed message was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// A public key is not base64 of 32 bytes.
    #[error("public key must be base64 of 32 bytes")]
    InvalidKey,
    /// The peer's public key yields no shared secret.
    #[error("peer public key is a low-order point")]
    LowOrderPoint,
    /// Sealed data failed authentication or is too short.
    #[error("data could not be decrypted")]
    Decrypt,
}

/// A device's X25519 key pair.
pub struct DeviceKeys {
    /// The private scalar.
    secret: StaticSecret,
}

impl DeviceKeys {
    /// Generates a new random key pair.
    pub fn generate() -> Self {
        Self {
            secret: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// Restores a key pair from its 32 private-key bytes.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    /// Returns the 32 private-key bytes, for the application to store.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Returns the public half of the key pair.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(&self.secret).to_bytes())
    }
}

impl fmt::Debug for DeviceKeys {
    /// Writes the public key only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceKeys")
            .field("public", &self.public_key())
            .finish_non_exhaustive()
    }
}

/// An X25519 public key; serialized as standard base64.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Wraps 32 raw key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the key as standard base64.
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }

    /// Parses standard base64 of exactly 32 bytes.
    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        STANDARD
            .decode(s)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .map(Self)
            .ok_or(CryptoError::InvalidKey)
    }

    /// Returns a short human-comparable fingerprint: the first 16 bytes of the
    /// key's SHA-256 as hex in groups of four, separated by `:`.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.0);
        let hex = hex::encode(&digest[..16]);
        hex.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).expect("hex is ASCII"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl fmt::Debug for PublicKey {
    /// Writes the key's fingerprint.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.fingerprint())
    }
}

impl Serialize for PublicKey {
    /// Serializes the key as standard base64.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    /// Deserializes the key from standard base64 of 32 bytes.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        PublicKey::from_base64(&s).map_err(serde::de::Error::custom)
    }
}

/// A 32-byte symmetric key: a pairwise session key or a media key.
#[derive(Clone)]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    /// Generates a random key.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wraps 32 raw key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SessionKey {
    /// Writes a placeholder instead of the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey(..)")
    }
}

/// Derives the pairwise session key of `host` and `viewer` for `session_id`.
///
/// Both sides get the same key: each passes its own key pair and the other's
/// public key. Fails with [`CryptoError::LowOrderPoint`] when the peer key
/// yields an all-zero shared secret.
pub fn derive_session_key(
    own: &DeviceKeys,
    peer: &PublicKey,
    session_id: &str,
    host: DeviceId,
    viewer: DeviceId,
) -> Result<SessionKey, CryptoError> {
    let shared = own
        .secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(peer.0));
    if !shared.was_contributory() {
        return Err(CryptoError::LowOrderPoint);
    }
    let mut info = KDF_INFO.to_vec();
    info.extend_from_slice(host.to_string().as_bytes());
    info.extend_from_slice(viewer.to_string().as_bytes());
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared.as_bytes())
        .expand(&info, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Ok(SessionKey(key))
}

/// Encrypts `plaintext` for `topic` in `session_id`; returns nonce followed by ciphertext.
pub fn seal(key: &SessionKey, topic: &str, session_id: &str, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let aad = aad(topic, session_id);
    let ciphertext = cipher(key)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("ChaCha20-Poly1305 encryption cannot fail for in-memory data");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypts data produced by [`seal`] with the same key, topic and session.
pub fn open(
    key: &SessionKey,
    topic: &str,
    session_id: &str,
    sealed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < NONCE_LEN {
        return Err(CryptoError::Decrypt);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let aad = aad(topic, session_id);
    cipher(key)
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

/// Returns the AEAD cipher keyed with `key`.
fn cipher(key: &SessionKey) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(Key::from_slice(&key.0))
}

/// Returns the associated data binding a sealed message to `topic` and `session_id`.
fn aad(topic: &str, session_id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(topic.len() + 1 + session_id.len());
    out.extend_from_slice(topic.as_bytes());
    out.push(0);
    out.extend_from_slice(session_id.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (DeviceId, DeviceId) {
        (DeviceId::new(123_456_789).unwrap(), DeviceId::new(223_456_789).unwrap())
    }

    #[test]
    fn both_sides_derive_same_key() {
        let (h, v) = (DeviceKeys::generate(), DeviceKeys::generate());
        let (hid, vid) = ids();
        let a = derive_session_key(&h, &v.public_key(), "s1", hid, vid).unwrap();
        let b = derive_session_key(&v, &h.public_key(), "s1", hid, vid).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        let c = derive_session_key(&h, &v.public_key(), "s2", hid, vid).unwrap();
        assert_ne!(a.as_bytes(), c.as_bytes());
        let d = derive_session_key(&h, &v.public_key(), "s1", vid, hid).unwrap();
        assert_ne!(a.as_bytes(), d.as_bytes());
    }

    #[test]
    fn derive_rejects_low_order_point() {
        let h = DeviceKeys::generate();
        let zero = PublicKey::from_bytes([0; 32]);
        let (hid, vid) = ids();
        assert_eq!(
            derive_session_key(&h, &zero, "s", hid, vid).unwrap_err(),
            CryptoError::LowOrderPoint
        );
    }

    #[test]
    fn secret_bytes_restore_same_key_pair() {
        let k = DeviceKeys::generate();
        let back = DeviceKeys::from_secret_bytes(k.secret_bytes());
        assert_eq!(back.public_key(), k.public_key());
        assert_ne!(DeviceKeys::generate().public_key(), k.public_key());
    }

    #[test]
    fn seal_open_round_trip_and_tamper() {
        let k = SessionKey::random();
        let mut s = seal(&k, "surf-rac/input", "s1", b"hello");
        assert_eq!(open(&k, "surf-rac/input", "s1", &s).unwrap(), b"hello");
        assert!(open(&k, "surf-rac/clipboard", "s1", &s).is_err());
        assert!(open(&k, "surf-rac/input", "s2", &s).is_err());
        assert!(open(&SessionKey::random(), "surf-rac/input", "s1", &s).is_err());
        let last = s.len() - 1;
        s[last] ^= 1;
        assert_eq!(open(&k, "surf-rac/input", "s1", &s), Err(CryptoError::Decrypt));
        assert_eq!(open(&k, "surf-rac/input", "s1", &[0u8; 5]), Err(CryptoError::Decrypt));
    }

    #[test]
    fn nonces_differ() {
        let k = SessionKey::random();
        assert_ne!(seal(&k, "t", "s", b"x")[..12], seal(&k, "t", "s", b"x")[..12]);
    }

    #[test]
    fn public_key_base64_requires_32_bytes() {
        assert_eq!(PublicKey::from_base64("AAAA"), Err(CryptoError::InvalidKey));
        assert_eq!(PublicKey::from_base64("not base64!"), Err(CryptoError::InvalidKey));
        let k = DeviceKeys::generate().public_key();
        assert_eq!(PublicKey::from_base64(&k.to_base64()).unwrap(), k);
    }

    #[test]
    fn fingerprint_format() {
        let fp = PublicKey::from_bytes([1; 32]).fingerprint();
        assert_eq!(fp.len(), 39);
        assert_eq!(fp.split(':').count(), 8);
        assert_ne!(fp, PublicKey::from_bytes([2; 32]).fingerprint());
    }

    #[test]
    fn debug_hides_secrets() {
        let k = SessionKey::from_bytes([0xAB; 32]);
        assert_eq!(format!("{k:?}"), "SessionKey(..)");
        let d = DeviceKeys::from_secret_bytes([0xCD; 32]);
        assert!(!format!("{d:?}").contains("205"));
    }
}
