//! Shared helpers for the server integration tests.

#![allow(dead_code)]

pub mod ws;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sqlx::PgPool;
use surf_rac_server::config::Config;
use surf_rac_server::state::AppState;

/// LiveKit API secret used by every test server.
pub const TEST_LIVEKIT_SECRET: &str = "test-livekit-secret-0123456789abcdef";

/// TURN shared secret used by every test server.
pub const TEST_TURN_SECRET: &str = "test-turn-secret-0123";

/// A running test server bound to a random local port.
pub struct TestApp {
    /// Address the server listens on.
    pub addr: SocketAddr,
    /// Base URL, e.g. `http://127.0.0.1:1234`.
    pub base: String,
    /// Pool connected to this test's database.
    pub pool: PgPool,
    /// HTTP client for requests against the server.
    pub client: reqwest::Client,
    /// State shared with the server, for direct inspection.
    pub state: AppState,
}

/// Returns the configuration every test server uses.
pub fn test_config() -> Config {
    Config {
        database_url: String::new(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        turn_secret: TEST_TURN_SECRET.into(),
        turn_urls: vec!["turn:turn.example:3478".into()],
        turn_ttl_secs: 3600,
        livekit_url: "ws://livekit.example:7880".into(),
        livekit_api_key: "testkey".into(),
        livekit_api_secret: TEST_LIVEKIT_SECRET.into(),
        trust_forwarded_for: true,
        log_json: false,
    }
}

/// Starts a server on a random port backed by `pool`.
pub async fn spawn(pool: PgPool) -> TestApp {
    spawn_with(pool, |_| {}).await
}

/// Starts a server like [`spawn`], letting `adjust` change the state first.
pub async fn spawn_with(pool: PgPool, adjust: impl FnOnce(&mut AppState)) -> TestApp {
    let mut state = AppState::new(pool.clone(), Arc::new(test_config()));
    adjust(&mut state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let served = state.clone();
    tokio::spawn(async move {
        surf_rac_server::serve(listener, served).await.unwrap();
    });
    TestApp {
        addr,
        base: format!("http://{addr}"),
        pool,
        client: reqwest::Client::new(),
        state,
    }
}

/// Password used for every test account.
pub const PASSWORD: &str = "correct horse battery";

/// Returns a valid 64-character lowercase hex fingerprint derived from `n`.
pub fn fingerprint(n: u32) -> String {
    format!("{n:064x}")
}

/// Source of distinct fake client IPs, so helpers never hit per-IP limits.
static NEXT_IP: AtomicU32 = AtomicU32::new(1);

/// Returns a fresh fake client IP in 172.16.0.0/12.
pub fn fresh_ip() -> String {
    let n = NEXT_IP.fetch_add(1, Ordering::Relaxed);
    format!("172.16.{}.{}", (n >> 8) & 0xff, n & 0xff)
}

/// Generates a random Ed25519 identity key.
pub fn identity_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

/// Returns the identity public key of `key` as standard base64.
pub fn public_key_b64(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().as_bytes())
}

/// Signs the connect challenge `nonce` with `key` and returns the signature as standard base64.
///
/// The signed message is the challenge domain tag followed by the nonce bytes.
pub fn sign_challenge(key: &SigningKey, nonce: &[u8]) -> String {
    let mut msg = b"surf-rac/challenge/v1".to_vec();
    msg.extend_from_slice(nonce);
    STANDARD.encode(key.sign(&msg).to_bytes())
}

/// Signs a device registration with `signer` over the registration message of `key`.
///
/// Returns the signature as standard base64. `signer` differs from `key` to
/// produce a registration signed by a key that does not match the request.
pub fn sign_registration(
    signer: &SigningKey,
    key: &SigningKey,
    fingerprint_hash: &str,
    name: &str,
) -> String {
    let message =
        surf_rac_protocol::register_message(key.verifying_key().as_bytes(), fingerprint_hash, name);
    STANDARD.encode(signer.sign(&message).to_bytes())
}

/// A registered device identity: its ID, key and fingerprint.
pub struct Identity {
    /// The device ID the server assigned.
    pub id: String,
    /// The device's identity key.
    pub key: SigningKey,
    /// The device's fingerprint hash.
    pub fingerprint: String,
}

impl TestApp {
    /// Builds a URL for `path` on this server.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// Calls `POST /v1/register` from a fresh client IP.
    pub async fn register(&self, username: &str, password: &str) -> reqwest::Response {
        self.register_from(username, password, &fresh_ip()).await
    }

    /// Calls `POST /v1/register` with `ip` as the forwarded client address.
    pub async fn register_from(
        &self,
        username: &str,
        password: &str,
        ip: &str,
    ) -> reqwest::Response {
        self.client
            .post(self.url("/v1/register"))
            .header("x-forwarded-for", ip)
            .json(&json!({"username": username, "password": password}))
            .send()
            .await
            .unwrap()
    }

    /// Calls `POST /v1/login` with `ip` as the forwarded client address.
    pub async fn login(&self, username: &str, password: &str, ip: &str) -> reqwest::Response {
        self.client
            .post(self.url("/v1/login"))
            .header("x-forwarded-for", ip)
            .json(&json!({"username": username, "password": password}))
            .send()
            .await
            .unwrap()
    }

    /// Registers `username` with [`PASSWORD`] and returns a session token.
    pub async fn register_and_login(&self, username: &str) -> String {
        let res = self.register(username, PASSWORD).await;
        assert_eq!(res.status(), 201, "register {username}");
        let res = self.login(username, PASSWORD, &fresh_ip()).await;
        assert_eq!(res.status(), 200, "login {username}");
        let body: Value = res.json().await.unwrap();
        body["token"].as_str().unwrap().to_owned()
    }

    /// Calls `POST /v1/devices` with `body`, from a fresh client IP and without credentials.
    pub async fn register_device_raw(&self, body: Value) -> reqwest::Response {
        self.client
            .post(self.url("/v1/devices"))
            .header("x-forwarded-for", fresh_ip())
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    /// Calls `POST /v1/devices` for `key`, `fingerprint_hash` and `name` at the current protocol version.
    ///
    /// The request is signed by `key` over exactly those values.
    pub async fn register_device(
        &self,
        key: &SigningKey,
        fingerprint_hash: &str,
        name: &str,
    ) -> reqwest::Response {
        let signature = sign_registration(key, key, fingerprint_hash, name);
        self.register_device_signed(key, fingerprint_hash, name, &signature)
            .await
    }

    /// Calls `POST /v1/devices` for `key`, `fingerprint_hash` and `name` carrying the given base64 `signature`.
    pub async fn register_device_signed(
        &self,
        key: &SigningKey,
        fingerprint_hash: &str,
        name: &str,
        signature: &str,
    ) -> reqwest::Response {
        self.register_device_raw(json!({
            "public_key": public_key_b64(key),
            "fingerprint_hash": fingerprint_hash,
            "name": name,
            "signature": signature,
            "protocol_version": surf_rac_protocol::PROTOCOL_VERSION,
        }))
        .await
    }

    /// Registers a device with a fresh identity key and fingerprint `n` and returns it.
    pub async fn new_device(&self, n: u32) -> Identity {
        let key = identity_key();
        let fingerprint = fingerprint(n);
        let res = self.register_device(&key, &fingerprint, "pc").await;
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        Identity {
            id: body["device_id"].as_str().unwrap().to_owned(),
            key,
            fingerprint,
        }
    }
}
