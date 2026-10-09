//! Identity keys, per-session keys, session key derivation and sealing of data messages.
//!
//! Each installation owns one Ed25519 [`IdentityKey`]. It signs the server's
//! connect challenge and the per-session X25519 key of every session.
//!
//! For each session, host and viewer each create a fresh [`Ephemeral`] X25519
//! key pair and sign its public half together with their [`Role`] and the
//! session ID. The peer verifies that signature against the sender's identity
//! key. Both sides then agree on a shared secret and derive the same 32-byte
//! [`SessionKey`] from it, both per-session public keys, both device IDs, the
//! session ID and the host nonce. The unattended password is sealed to the
//! host's per-session key. Data is sealed with ChaCha20-Poly1305 under a random
//! 96-bit nonce, bound to its topic and session.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use surf_rac_protocol::{CHALLENGE_DOMAIN, DeviceId, SESSION_DOMAIN};
use x25519_dalek::StaticSecret;

/// HKDF info prefix of session keys.
const KDF_INFO: &[u8] = b"surf-rac session v1";

/// HKDF info prefix of keys that seal an unattended password.
const PASSWORD_KDF_INFO: &[u8] = b"surf-rac-password-v1";

/// Topic the sealed password is bound to.
const PASSWORD_TOPIC: &str = "password";

/// Length of the nonce prefixed to sealed data.
const NONCE_LEN: usize = 12;

/// Why a key, signature or sealed message was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// A public key is not base64 of 32 bytes, or not a valid curve point.
    #[error("public key must be base64 of a valid 32-byte key")]
    InvalidKey,
    /// A signature is not base64 of 64 bytes.
    #[error("signature must be base64 of 64 bytes")]
    InvalidSignature,
    /// A signature does not verify for the message and key.
    #[error("signature does not verify")]
    BadSignature,
    /// The peer's public key yields no shared secret.
    #[error("peer public key is a low-order point")]
    LowOrderPoint,
    /// Sealed data failed authentication or is too short.
    #[error("data could not be decrypted")]
    Decrypt,
}

/// Which side of a session signed a per-session key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The device that asked for the session.
    Viewer,
    /// The device whose screen is shared.
    Host,
}

impl Role {
    /// Returns the role's tag as it appears in a signed per-session key.
    fn tag(self) -> &'static [u8] {
        match self {
            Role::Viewer => b"viewer",
            Role::Host => b"host",
        }
    }
}

/// An installation's Ed25519 identity key pair.
pub struct IdentityKey {
    /// The signing key.
    signing: SigningKey,
}

impl IdentityKey {
    /// Generates a new random identity key.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Restores an identity key from its 32 secret-key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&bytes),
        }
    }

    /// Returns the 32 secret-key bytes, for the application to store.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Returns the public half of the identity key.
    pub fn public(&self) -> IdentityPublic {
        IdentityPublic(self.signing.verifying_key())
    }

    /// Signs the server's connect challenge `nonce`.
    ///
    /// The signed message is [`CHALLENGE_DOMAIN`] followed by the nonce.
    pub fn sign_challenge(&self, nonce: &[u8; 32]) -> [u8; 64] {
        self.signing.sign(&challenge_message(nonce)).to_bytes()
    }

    /// Signs a device registration of this key with `fingerprint_hash` and `name`.
    ///
    /// The signed message is [`surf_rac_protocol::register_message`] of the
    /// public key, the fingerprint hash and the name.
    pub fn sign_registration(&self, fingerprint_hash: &str, name: &str) -> [u8; 64] {
        let public = self.signing.verifying_key().to_bytes();
        self.signing
            .sign(&surf_rac_protocol::register_message(
                &public,
                fingerprint_hash,
                name,
            ))
            .to_bytes()
    }

    /// Signs the per-session public `key` this device uses as `role` in `session_id`.
    ///
    /// The signed message is [`SESSION_DOMAIN`], the role tag (`viewer` or
    /// `host`), the session ID and the 32 key bytes.
    pub fn sign_session(&self, role: Role, session_id: &str, key: &EphemeralPublic) -> [u8; 64] {
        self.signing
            .sign(&session_message(role, session_id, key))
            .to_bytes()
    }
}

impl fmt::Debug for IdentityKey {
    /// Writes the public key's fingerprint only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKey")
            .field("public", &self.public())
            .finish_non_exhaustive()
    }
}

/// An installation's Ed25519 identity public key; serialized as standard base64.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IdentityPublic(VerifyingKey);

impl IdentityPublic {
    /// Parses standard base64 of a valid 32-byte Ed25519 public key.
    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        let bytes = decode_array::<32>(s).ok_or(CryptoError::InvalidKey)?;
        VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }

    /// Returns the key as standard base64.
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0.as_bytes())
    }

    /// Returns the raw key bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Checks that `signature` signs the connect challenge `nonce` with this key.
    ///
    /// Fails with [`CryptoError::BadSignature`] otherwise.
    pub fn verify_challenge(
        &self,
        nonce: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), CryptoError> {
        self.verify(&challenge_message(nonce), signature)
    }

    /// Checks that `signature` signs `key` as the per-session key of `role` in `session_id`.
    ///
    /// Fails with [`CryptoError::BadSignature`] when the signature was made by
    /// another identity key or over another role, session ID or key.
    pub fn verify_session(
        &self,
        role: Role,
        session_id: &str,
        key: &EphemeralPublic,
        signature: &[u8; 64],
    ) -> Result<(), CryptoError> {
        self.verify(&session_message(role, session_id, key), signature)
    }

    /// Returns a short human-comparable fingerprint: the first 16 bytes of the
    /// key's SHA-256 as hex in groups of four, separated by `:`.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.0.as_bytes());
        let hex = hex::encode(&digest[..16]);
        hex.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).expect("hex is ASCII"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Checks a strict Ed25519 signature over `msg`.
    fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> Result<(), CryptoError> {
        self.0
            .verify_strict(msg, &Signature::from_bytes(signature))
            .map_err(|_| CryptoError::BadSignature)
    }
}

impl fmt::Debug for IdentityPublic {
    /// Writes the key's fingerprint.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityPublic({})", self.fingerprint())
    }
}

impl Serialize for IdentityPublic {
    /// Serializes the key as standard base64.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for IdentityPublic {
    /// Deserializes the key from standard base64 of a valid 32-byte key.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        IdentityPublic::from_base64(&s).map_err(serde::de::Error::custom)
    }
}

/// Returns a signature as standard base64.
pub fn signature_to_base64(signature: &[u8; 64]) -> String {
    STANDARD.encode(signature)
}

/// Parses standard base64 of exactly 64 signature bytes.
pub fn signature_from_base64(s: &str) -> Result<[u8; 64], CryptoError> {
    decode_array::<64>(s).ok_or(CryptoError::InvalidSignature)
}

/// A per-session X25519 key pair; one is created for every session on each side.
pub struct Ephemeral {
    /// The private scalar.
    secret: StaticSecret,
}

impl Ephemeral {
    /// Generates a new random key pair.
    pub fn generate() -> Self {
        Self {
            secret: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// Returns the public half of the key pair.
    pub fn public(&self) -> EphemeralPublic {
        EphemeralPublic(x25519_dalek::PublicKey::from(&self.secret).to_bytes())
    }

    /// Computes the X25519 shared secret with the peer's per-session key `peer`.
    ///
    /// Fails with [`CryptoError::LowOrderPoint`] when `peer` yields an
    /// all-zero shared secret.
    pub fn agree(&self, peer: &EphemeralPublic) -> Result<[u8; 32], CryptoError> {
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer.0));
        if !shared.was_contributory() {
            return Err(CryptoError::LowOrderPoint);
        }
        Ok(shared.to_bytes())
    }
}

impl fmt::Debug for Ephemeral {
    /// Writes the public key only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ephemeral")
            .field("public", &self.public())
            .finish_non_exhaustive()
    }
}

/// A per-session X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EphemeralPublic([u8; 32]);

impl EphemeralPublic {
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
        decode_array::<32>(s)
            .map(Self)
            .ok_or(CryptoError::InvalidKey)
    }
}

impl fmt::Debug for EphemeralPublic {
    /// Writes the key as base64.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EphemeralPublic({})", self.to_base64())
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
/// `shared` is the result of [`Ephemeral::agree`] between the two per-session
/// keys; both sides pass the same viewer and host per-session public keys and
/// the `host_nonce` the host chose for the session, so both get the same key.
/// A fresh nonce makes every accepted session use a new key, even for a
/// repeated request.
///
/// HKDF-SHA256 with salt `session_id || host_nonce` and info
/// `"surf-rac session v1" || host || viewer || host_key || viewer_key`, with
/// the device IDs as decimal text.
pub fn derive_session_key(
    shared: &[u8; 32],
    viewer_key: &EphemeralPublic,
    host_key: &EphemeralPublic,
    session_id: &str,
    host_nonce: &[u8; 32],
    host: DeviceId,
    viewer: DeviceId,
) -> SessionKey {
    let mut info = KDF_INFO.to_vec();
    info.extend_from_slice(host.to_string().as_bytes());
    info.extend_from_slice(viewer.to_string().as_bytes());
    info.extend_from_slice(host_key.as_bytes());
    info.extend_from_slice(viewer_key.as_bytes());
    let mut salt = session_id.as_bytes().to_vec();
    salt.extend_from_slice(host_nonce);
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(&info, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    SessionKey(key)
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

/// Derives the key that seals the unattended password of `session_id`.
///
/// HKDF-SHA256 without salt over the X25519 shared secret of `own` and `peer`,
/// with info `"surf-rac-password-v1" || session_id || viewer || host` and the
/// device IDs as decimal text. Viewer and host get the same key: each passes
/// its own per-session key pair and the other's per-session public key. Fails
/// with [`CryptoError::LowOrderPoint`] when `peer` yields an all-zero shared
/// secret.
fn password_key(
    own: &Ephemeral,
    peer: &EphemeralPublic,
    session_id: &str,
    viewer: DeviceId,
    host: DeviceId,
) -> Result<SessionKey, CryptoError> {
    let shared = own.agree(peer)?;
    let mut info = PASSWORD_KDF_INFO.to_vec();
    info.extend_from_slice(session_id.as_bytes());
    info.extend_from_slice(viewer.to_string().as_bytes());
    info.extend_from_slice(host.to_string().as_bytes());
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, &shared)
        .expand(&info, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Ok(SessionKey(key))
}

/// Seals `password` so that only the owner of the host per-session key
/// `host_key` can read it in `session_id`.
///
/// `own` is the viewer's per-session key pair. Returns standard base64 of the
/// 12-byte nonce followed by the ChaCha20-Poly1305 ciphertext. Fails with
/// [`CryptoError::LowOrderPoint`] when `host_key` yields no shared secret.
pub fn seal_password(
    own: &Ephemeral,
    host_key: &EphemeralPublic,
    session_id: &str,
    viewer: DeviceId,
    host: DeviceId,
    password: &str,
) -> Result<String, CryptoError> {
    let key = password_key(own, host_key, session_id, viewer, host)?;
    Ok(STANDARD.encode(seal(&key, PASSWORD_TOPIC, session_id, password.as_bytes())))
}

/// Opens a password sealed with [`seal_password`] for this host.
///
/// `own` is the host's per-session key pair and `viewer_key` the viewer's
/// per-session public key. Fails with [`CryptoError::Decrypt`] when the text is
/// not base64, was sealed for another key, session or device pair, was
/// altered, or is not UTF-8.
pub fn open_password(
    own: &Ephemeral,
    viewer_key: &EphemeralPublic,
    session_id: &str,
    viewer: DeviceId,
    host: DeviceId,
    sealed: &str,
) -> Result<String, CryptoError> {
    let key = password_key(own, viewer_key, session_id, viewer, host)?;
    let bytes = STANDARD.decode(sealed).map_err(|_| CryptoError::Decrypt)?;
    let plain = open(&key, PASSWORD_TOPIC, session_id, &bytes)?;
    String::from_utf8(plain).map_err(|_| CryptoError::Decrypt)
}

/// Returns 32 random bytes for use as a host nonce.
pub fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Returns the message signed for the connect challenge `nonce`.
fn challenge_message(nonce: &[u8; 32]) -> Vec<u8> {
    let mut msg = CHALLENGE_DOMAIN.to_vec();
    msg.extend_from_slice(nonce);
    msg
}

/// Returns the message signed for `key` as the per-session key of `role` in `session_id`.
fn session_message(role: Role, session_id: &str, key: &EphemeralPublic) -> Vec<u8> {
    let mut msg = SESSION_DOMAIN.to_vec();
    msg.extend_from_slice(role.tag());
    msg.extend_from_slice(session_id.as_bytes());
    msg.extend_from_slice(key.as_bytes());
    msg
}

/// Decodes standard base64 of exactly `N` bytes.
fn decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    STANDARD
        .decode(s)
        .ok()
        .and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
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
        (
            DeviceId::new(123_456_789).unwrap(),
            DeviceId::new(223_456_789).unwrap(),
        )
    }

    /// Signs `msg` with `id` directly through ed25519-dalek.
    fn reference_sign(id: &IdentityKey, msg: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        ed25519_dalek::SigningKey::from_bytes(&id.to_bytes())
            .sign(msg)
            .to_bytes()
    }

    #[test]
    fn registration_signature_covers_the_register_message() {
        let id = IdentityKey::generate();
        let fingerprint = "ab".repeat(32);
        let msg =
            surf_rac_protocol::register_message(&id.public().to_bytes(), &fingerprint, "laptop");
        assert_eq!(
            id.sign_registration(&fingerprint, "laptop"),
            reference_sign(&id, &msg)
        );
        assert_ne!(
            id.sign_registration(&fingerprint, "desktop"),
            reference_sign(&id, &msg)
        );
    }

    #[test]
    fn challenge_signature_verifies() {
        let id = IdentityKey::generate();
        let sig = id.sign_challenge(&[7; 32]);
        assert_eq!(id.public().verify_challenge(&[7; 32], &sig), Ok(()));
    }

    #[test]
    fn challenge_signature_rejects_other_nonce_and_other_key() {
        let id = IdentityKey::generate();
        let sig = id.sign_challenge(&[7; 32]);
        assert_eq!(
            id.public().verify_challenge(&[8; 32], &sig),
            Err(CryptoError::BadSignature)
        );
        assert_eq!(
            IdentityKey::generate()
                .public()
                .verify_challenge(&[7; 32], &sig),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn challenge_signature_covers_domain_tag_and_nonce() {
        let id = IdentityKey::generate();
        let mut msg = b"surf-rac/challenge/v1".to_vec();
        msg.extend_from_slice(&[7; 32]);
        assert_eq!(id.sign_challenge(&[7; 32]), reference_sign(&id, &msg));
    }

    #[test]
    fn session_signature_binds_role_session_and_key() {
        let id = IdentityKey::generate();
        let key = Ephemeral::generate().public();
        let sig = id.sign_session(Role::Viewer, "s1", &key);
        let public = id.public();
        assert_eq!(
            public.verify_session(Role::Viewer, "s1", &key, &sig),
            Ok(())
        );
        assert_eq!(
            public.verify_session(Role::Host, "s1", &key, &sig),
            Err(CryptoError::BadSignature)
        );
        assert_eq!(
            public.verify_session(Role::Viewer, "s2", &key, &sig),
            Err(CryptoError::BadSignature)
        );
        let other = Ephemeral::generate().public();
        assert_eq!(
            public.verify_session(Role::Viewer, "s1", &other, &sig),
            Err(CryptoError::BadSignature)
        );
        assert_eq!(
            IdentityKey::generate()
                .public()
                .verify_session(Role::Viewer, "s1", &key, &sig),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn session_signature_covers_domain_role_session_and_key() {
        let id = IdentityKey::generate();
        let key = EphemeralPublic::from_bytes([3; 32]);
        for (role, tag) in [(Role::Host, &b"host"[..]), (Role::Viewer, &b"viewer"[..])] {
            let mut msg = b"surf-rac/session/v1".to_vec();
            msg.extend_from_slice(tag);
            msg.extend_from_slice(b"s1");
            msg.extend_from_slice(&[3; 32]);
            assert_eq!(id.sign_session(role, "s1", &key), reference_sign(&id, &msg));
        }
    }

    #[test]
    fn identity_key_bytes_restore_same_key() {
        let id = IdentityKey::generate();
        let back = IdentityKey::from_bytes(id.to_bytes());
        assert_eq!(back.public(), id.public());
        assert_ne!(IdentityKey::generate().public(), id.public());
    }

    #[test]
    fn identity_public_base64_round_trip_and_validation() {
        let public = IdentityKey::generate().public();
        assert_eq!(IdentityPublic::from_base64(&public.to_base64()), Ok(public));
        assert_eq!(
            IdentityPublic::from_base64("AAAA"),
            Err(CryptoError::InvalidKey)
        );
        assert_eq!(
            IdentityPublic::from_base64("not base64!"),
            Err(CryptoError::InvalidKey)
        );
    }

    #[test]
    fn signature_base64_round_trip_and_validation() {
        let sig = IdentityKey::generate().sign_challenge(&[1; 32]);
        assert_eq!(signature_from_base64(&signature_to_base64(&sig)), Ok(sig));
        assert_eq!(
            signature_from_base64("AAAA"),
            Err(CryptoError::InvalidSignature)
        );
        assert_eq!(
            signature_from_base64("not base64!"),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn fingerprint_is_grouped_hex_of_key_digest() {
        let a = IdentityKey::from_bytes([1; 32]).public();
        let fp = a.fingerprint();
        assert_eq!(fp.len(), 39);
        assert_eq!(fp.split(':').count(), 8);
        let digest = Sha256::digest(a.to_bytes());
        assert_eq!(fp.replace(':', ""), hex::encode(&digest[..16]));
        assert_ne!(fp, IdentityKey::from_bytes([2; 32]).public().fingerprint());
    }

    #[test]
    fn identity_public_serde_is_base64() {
        let public = IdentityKey::generate().public();
        let json = serde_json::to_string(&public).unwrap();
        assert_eq!(json, format!("\"{}\"", public.to_base64()));
        assert_eq!(
            serde_json::from_str::<IdentityPublic>(&json).unwrap(),
            public
        );
        assert!(serde_json::from_str::<IdentityPublic>("\"AAAA\"").is_err());
    }

    #[test]
    fn ephemeral_public_base64_requires_32_bytes() {
        let key = Ephemeral::generate().public();
        assert_eq!(EphemeralPublic::from_base64(&key.to_base64()), Ok(key));
        assert_eq!(
            EphemeralPublic::from_base64("AAAA"),
            Err(CryptoError::InvalidKey)
        );
        assert_eq!(
            EphemeralPublic::from_base64("not base64!"),
            Err(CryptoError::InvalidKey)
        );
    }

    #[test]
    fn agree_gives_both_sides_the_same_secret() {
        let (a, b) = (Ephemeral::generate(), Ephemeral::generate());
        assert_eq!(a.agree(&b.public()).unwrap(), b.agree(&a.public()).unwrap());
        assert_ne!(Ephemeral::generate().public(), a.public());
    }

    #[test]
    fn agree_rejects_low_order_point() {
        let a = Ephemeral::generate();
        assert_eq!(
            a.agree(&EphemeralPublic::from_bytes([0; 32])),
            Err(CryptoError::LowOrderPoint)
        );
    }

    /// Keys and IDs of one test session.
    struct Fixture {
        /// The host's per-session key.
        host: Ephemeral,
        /// The viewer's per-session key.
        viewer: Ephemeral,
        /// The host's device ID.
        host_id: DeviceId,
        /// The viewer's device ID.
        viewer_id: DeviceId,
    }

    impl Fixture {
        /// Returns fresh per-session keys for the test host and viewer.
        fn new() -> Self {
            let (host_id, viewer_id) = ids();
            Self {
                host: Ephemeral::generate(),
                viewer: Ephemeral::generate(),
                host_id,
                viewer_id,
            }
        }

        /// Derives the host's session key with the given inputs.
        fn host_key(
            &self,
            sid: &str,
            nonce: &[u8; 32],
            host: DeviceId,
            viewer: DeviceId,
        ) -> SessionKey {
            let shared = self.host.agree(&self.viewer.public()).unwrap();
            derive_session_key(
                &shared,
                &self.viewer.public(),
                &self.host.public(),
                sid,
                nonce,
                host,
                viewer,
            )
        }
    }

    #[test]
    fn both_sides_derive_same_session_key_from_ephemerals() {
        let f = Fixture::new();
        let (hid, vid) = (f.host_id, f.viewer_id);
        let host_side = f.host_key("s1", &[9; 32], hid, vid);
        let shared = f.viewer.agree(&f.host.public()).unwrap();
        let viewer_side = derive_session_key(
            &shared,
            &f.viewer.public(),
            &f.host.public(),
            "s1",
            &[9; 32],
            hid,
            vid,
        );
        assert_eq!(host_side.as_bytes(), viewer_side.as_bytes());
        assert_ne!(
            host_side.as_bytes(),
            f.host_key("s2", &[9; 32], hid, vid).as_bytes()
        );
        assert_ne!(
            host_side.as_bytes(),
            f.host_key("s1", &[8; 32], hid, vid).as_bytes()
        );
        assert_ne!(
            host_side.as_bytes(),
            f.host_key("s1", &[9; 32], vid, hid).as_bytes()
        );
        let swapped_keys = derive_session_key(
            &shared,
            &f.host.public(),
            &f.viewer.public(),
            "s1",
            &[9; 32],
            hid,
            vid,
        );
        assert_ne!(host_side.as_bytes(), swapped_keys.as_bytes());
    }

    #[test]
    fn session_key_uses_documented_hkdf_layout() {
        let (hid, vid) = ids();
        let viewer_key = EphemeralPublic::from_bytes([1; 32]);
        let host_key = EphemeralPublic::from_bytes([2; 32]);
        let key = derive_session_key(&[5; 32], &viewer_key, &host_key, "s1", &[9; 32], hid, vid);
        let mut salt = b"s1".to_vec();
        salt.extend_from_slice(&[9; 32]);
        let mut info = b"surf-rac session v1".to_vec();
        info.extend_from_slice(hid.to_string().as_bytes());
        info.extend_from_slice(vid.to_string().as_bytes());
        info.extend_from_slice(&[2; 32]);
        info.extend_from_slice(&[1; 32]);
        let mut expected = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&salt), &[5; 32])
            .expand(&info, &mut expected)
            .unwrap();
        assert_eq!(key.as_bytes(), &expected);
    }

    #[test]
    fn replayed_request_gets_fresh_key() {
        let f = Fixture::new();
        let first = f.host_key("s1", &[1; 32], f.host_id, f.viewer_id);
        let replay = f.host_key("s1", &[2; 32], f.host_id, f.viewer_id);
        let recorded = seal(&first, "surf-rac/input", "s1", b"keystroke");
        assert_eq!(
            open(&replay, "surf-rac/input", "s1", &recorded),
            Err(CryptoError::Decrypt)
        );
    }

    #[test]
    fn password_sealed_to_host_ephemeral_opens_with_it() {
        let (host, viewer) = (Ephemeral::generate(), Ephemeral::generate());
        let (hid, vid) = ids();
        let sealed = seal_password(&viewer, &host.public(), "s1", vid, hid, "hunter22").unwrap();
        let opened = open_password(&host, &viewer.public(), "s1", vid, hid, &sealed).unwrap();
        assert_eq!(opened, "hunter22");
    }

    #[test]
    fn password_opens_only_with_the_host_ephemeral() {
        let (host, viewer, other) = (
            Ephemeral::generate(),
            Ephemeral::generate(),
            Ephemeral::generate(),
        );
        let (hid, vid) = ids();
        let sealed = seal_password(&viewer, &host.public(), "s1", vid, hid, "pw").unwrap();
        assert_eq!(
            open_password(&other, &viewer.public(), "s1", vid, hid, &sealed),
            Err(CryptoError::Decrypt)
        );
        assert_eq!(
            open_password(&host, &other.public(), "s1", vid, hid, &sealed),
            Err(CryptoError::Decrypt)
        );
    }

    #[test]
    fn password_is_bound_to_session_and_devices() {
        let (host, viewer) = (Ephemeral::generate(), Ephemeral::generate());
        let (hid, vid) = ids();
        let third = DeviceId::new(323_456_789).unwrap();
        let sealed = seal_password(&viewer, &host.public(), "s1", vid, hid, "pw").unwrap();
        let open = |sid: &str, v: DeviceId, h: DeviceId| {
            open_password(&host, &viewer.public(), sid, v, h, &sealed)
        };
        assert_eq!(open("s2", vid, hid), Err(CryptoError::Decrypt));
        assert_eq!(open("s1", hid, vid), Err(CryptoError::Decrypt));
        assert_eq!(open("s1", third, hid), Err(CryptoError::Decrypt));
        assert_eq!(open("s1", vid, third), Err(CryptoError::Decrypt));
        assert_eq!(open("s1", vid, hid).as_deref(), Ok("pw"));
    }

    #[test]
    fn password_key_uses_documented_hkdf_layout() {
        let (host, viewer) = (Ephemeral::generate(), Ephemeral::generate());
        let (hid, vid) = ids();
        let sealed = seal_password(&viewer, &host.public(), "s1", vid, hid, "pw").unwrap();
        let shared = viewer.agree(&host.public()).unwrap();
        let mut info = b"surf-rac-password-v1".to_vec();
        info.extend_from_slice(b"s1");
        info.extend_from_slice(vid.to_string().as_bytes());
        info.extend_from_slice(hid.to_string().as_bytes());
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(None, &shared)
            .expand(&info, &mut key)
            .unwrap();
        let bytes = STANDARD.decode(&sealed).unwrap();
        assert_eq!(bytes.len(), NONCE_LEN + "pw".len() + 16);
        let plain = open(&SessionKey::from_bytes(key), PASSWORD_TOPIC, "s1", &bytes).unwrap();
        assert_eq!(plain, b"pw");
    }

    #[test]
    fn password_seal_rejects_low_order_host_key() {
        let viewer = Ephemeral::generate();
        let (hid, vid) = ids();
        let zero = EphemeralPublic::from_bytes([0; 32]);
        assert_eq!(
            seal_password(&viewer, &zero, "s1", vid, hid, "pw"),
            Err(CryptoError::LowOrderPoint)
        );
    }

    #[test]
    fn tampered_or_garbage_password_fails() {
        let (host, viewer) = (Ephemeral::generate(), Ephemeral::generate());
        let (hid, vid) = ids();
        let sealed = seal_password(&viewer, &host.public(), "s1", vid, hid, "pw").unwrap();
        let mut bytes = STANDARD.decode(&sealed).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let tampered = STANDARD.encode(bytes);
        assert!(open_password(&host, &viewer.public(), "s1", vid, hid, &tampered).is_err());
        for garbage in ["", "not base64!", "AAAA"] {
            assert!(open_password(&host, &viewer.public(), "s1", vid, hid, garbage).is_err());
        }
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
        assert_eq!(
            open(&k, "surf-rac/input", "s1", &s),
            Err(CryptoError::Decrypt)
        );
        assert_eq!(
            open(&k, "surf-rac/input", "s1", &[0u8; 5]),
            Err(CryptoError::Decrypt)
        );
    }

    #[test]
    fn nonces_differ() {
        let k = SessionKey::random();
        assert_ne!(
            seal(&k, "t", "s", b"x")[..12],
            seal(&k, "t", "s", b"x")[..12]
        );
    }

    #[test]
    fn debug_hides_secrets() {
        let k = SessionKey::from_bytes([0xAB; 32]);
        assert_eq!(format!("{k:?}"), "SessionKey(..)");
        let id = IdentityKey::from_bytes([0xCD; 32]);
        let text = format!("{id:?}");
        assert!(!text.contains("205") && !text.to_lowercase().contains("cdcd"));
        let e = Ephemeral::generate();
        let secret_hex = hex::encode(e.secret.to_bytes());
        assert!(!format!("{e:?}").contains(&secret_hex));
    }
}
