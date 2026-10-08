//! Shared helpers for the server integration tests.

#![allow(dead_code)]

pub mod ws;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::json;
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
fn fresh_ip() -> String {
    let n = NEXT_IP.fetch_add(1, Ordering::Relaxed);
    format!("172.16.{}.{}", (n >> 8) & 0xff, n & 0xff)
}

impl TestApp {
    /// Builds a URL for `path` on this server.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// Creates an invite code directly in the database.
    pub async fn invite(&self) -> String {
        surf_rac_server::accounts::create_invite(&self.pool, "test", chrono::Duration::hours(72))
            .await
            .unwrap()
    }

    /// Calls `POST /v1/register` from a fresh client IP.
    pub async fn register(&self, code: &str, username: &str, password: &str) -> reqwest::Response {
        self.register_from(code, username, password, &fresh_ip())
            .await
    }

    /// Calls `POST /v1/register` with `ip` as the forwarded client address.
    pub async fn register_from(
        &self,
        code: &str,
        username: &str,
        password: &str,
        ip: &str,
    ) -> reqwest::Response {
        self.client
            .post(self.url("/v1/register"))
            .header("x-forwarded-for", ip)
            .json(&json!({"invite_code": code, "username": username, "password": password}))
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

    /// Calls `POST /v1/devices` for `token`.
    pub async fn register_device(
        &self,
        token: &str,
        fingerprint_hash: &str,
        name: &str,
        device_id: Option<&str>,
    ) -> reqwest::Response {
        let mut body = json!({"fingerprint_hash": fingerprint_hash, "name": name});
        if let Some(id) = device_id {
            body["device_id"] = json!(id);
        }
        self.client
            .post(self.url("/v1/devices"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    /// Registers a device for `token` and returns `(device_id, device_secret)`.
    pub async fn new_device(&self, token: &str, fingerprint_hash: &str) -> (String, String) {
        let res = self
            .register_device(token, fingerprint_hash, "pc", None)
            .await;
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        (
            body["device_id"].as_str().unwrap().to_owned(),
            body["device_secret"].as_str().unwrap().to_owned(),
        )
    }

    /// Registers `username` with [`PASSWORD`] and returns a session token.
    pub async fn register_and_login(&self, username: &str) -> String {
        let code = self.invite().await;
        let res = self.register(&code, username, PASSWORD).await;
        assert_eq!(res.status(), 201, "register {username}");
        let res = self.login(username, PASSWORD, &fresh_ip()).await;
        assert_eq!(res.status(), 200, "login {username}");
        let body: serde_json::Value = res.json().await.unwrap();
        body["token"].as_str().unwrap().to_owned()
    }
}
