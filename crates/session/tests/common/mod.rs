//! Shared helpers for the session integration tests: an in-process signaling
//! server, registered devices and LiveKit tokens.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use sqlx::PgPool;
use surf_rac_protocol::DeviceId;
use surf_rac_server::config::Config;
use surf_rac_server::state::AppState;
use surf_rac_session::signaling::SignalingClient;
use surf_rac_session::{DeviceKeys, KnownKeys};

/// Reads a required environment variable.
pub fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

/// An in-process signaling server bound to a random local port.
pub struct TestEnv {
    /// HTTP base URL, e.g. `http://127.0.0.1:1234`.
    pub http: String,
    /// WebSocket base URL, e.g. `ws://127.0.0.1:1234`.
    pub ws: String,
    /// HTTP client for account and device setup.
    pub client: reqwest::Client,
    /// Pool of this test's database.
    pub pool: PgPool,
}

/// A registered, connected device.
pub struct TestDevice {
    /// Device ID.
    pub id: DeviceId,
    /// Session token of the owning account.
    pub token: String,
    /// Device secret.
    pub secret: String,
    /// Open signaling connection.
    pub signaling: SignalingClient,
    /// The device's key pair.
    pub keys: Arc<DeviceKeys>,
    /// The device's pinned peer keys.
    pub known: Arc<Mutex<KnownKeys>>,
}

impl TestEnv {
    /// Starts a server whose LiveKit settings come from the environment.
    pub async fn start(pool: PgPool) -> TestEnv {
        Self::start_with_livekit(pool, &env("LIVEKIT_URL")).await
    }

    /// Starts a server that hands out `livekit_url` to clients.
    pub async fn start_with_livekit(pool: PgPool, livekit_url: &str) -> TestEnv {
        let config = Config {
            database_url: String::new(),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            turn_secret: "test-turn-secret-0123".into(),
            turn_urls: vec!["turn:turn.example:3478".into()],
            turn_ttl_secs: 3600,
            livekit_url: livekit_url.into(),
            livekit_api_key: env("LIVEKIT_API_KEY"),
            livekit_api_secret: env("LIVEKIT_API_SECRET"),
            trust_forwarded_for: true,
            log_json: false,
        };
        let state = AppState::new(pool.clone(), Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            surf_rac_server::serve(listener, state).await.unwrap();
        });
        TestEnv {
            http: format!("http://{addr}"),
            ws: format!("ws://{addr}"),
            client: reqwest::Client::new(),
            pool,
        }
    }

    /// Posts `body` to `path` with an optional bearer token; returns status and JSON body.
    async fn post(&self, path: &str, token: Option<&str>, ip: &str, body: Value) -> (u16, Value) {
        let mut req = self
            .client
            .post(format!("{}{path}", self.http))
            .header("x-forwarded-for", ip)
            .json(&body);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let res = req.send().await.unwrap();
        let status = res.status().as_u16();
        (status, res.json().await.unwrap_or(Value::Null))
    }

    /// Registers account `username` with device number `n`; returns token, device ID and secret.
    pub async fn register(&self, username: &str, n: u32) -> (String, DeviceId, String) {
        let code = surf_rac_server::accounts::create_invite(
            &self.pool,
            "test",
            chrono::Duration::hours(1),
        )
        .await
        .unwrap();
        let ip = format!("172.16.{}.{}", n / 256, n % 256);
        let password = "correct horse battery";
        let (status, _) = self
            .post(
                "/v1/register",
                None,
                &ip,
                json!({"invite_code": code, "username": username, "password": password}),
            )
            .await;
        assert_eq!(status, 201, "register {username}");
        let (status, body) = self
            .post(
                "/v1/login",
                None,
                &ip,
                json!({"username": username, "password": password}),
            )
            .await;
        assert_eq!(status, 200, "login {username}");
        let token = body["token"].as_str().unwrap().to_owned();
        let (status, body) = self
            .post(
                "/v1/devices",
                Some(&token),
                &ip,
                json!({"fingerprint_hash": format!("{n:064x}"), "name": username}),
            )
            .await;
        assert_eq!(status, 200, "device {username}");
        let id: DeviceId = body["device_id"].as_str().unwrap().parse().unwrap();
        let secret = body["device_secret"].as_str().unwrap().to_owned();
        (token, id, secret)
    }

    /// Registers and connects device `n` of account `username`.
    pub async fn device(&self, username: &str, n: u32) -> TestDevice {
        let (token, id, secret) = self.register(username, n).await;
        let signaling = SignalingClient::connect(&self.ws, &token, id, &secret)
            .await
            .expect("signaling connect");
        TestDevice {
            id,
            token,
            secret,
            signaling,
            keys: Arc::new(DeviceKeys::generate()),
            known: Arc::new(Mutex::new(KnownKeys::default())),
        }
    }
}
