//! Shared helpers for the session integration tests: an in-process signaling
//! server, registered devices and LiveKit tokens.

#![allow(dead_code)]

pub mod stamp;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::PgPool;
use surf_rac_protocol::DeviceId;
use surf_rac_server::config::Config;
use surf_rac_server::state::AppState;
use surf_rac_session::host::{HostEvent, HostSession};
use surf_rac_session::signaling::SignalingClient;
use surf_rac_session::viewer::{RequestError, ViewerEvent, ViewerSession};
use surf_rac_session::{DeviceKeys, KnownKeys, SessionConfig};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinHandle;

/// Reads a required environment variable.
pub fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

/// Returns the current Unix time in seconds.
pub fn unix_now() -> i64 {
    stamp::now_micros() / 1_000_000
}

/// Mints a LiveKit token directly with the API secret, as the SFU operator could.
///
/// The token lets `identity` join `room` from `nbf` to `exp` (Unix seconds).
pub fn mint_token(room: &str, identity: &str, can_publish: bool, nbf: i64, exp: i64) -> String {
    let header = URL_SAFE_NO_PAD.encode(json!({"alg":"HS256","typ":"JWT"}).to_string());
    let claims = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": env("LIVEKIT_API_KEY"), "sub": identity, "name": identity,
            "nbf": nbf, "exp": exp,
            "video": {"room": room, "roomJoin": true, "canPublish": can_publish,
                      "canSubscribe": true, "canPublishData": true}
        })
        .to_string(),
    );
    let signed = format!("{header}.{claims}");
    let mut mac = Hmac::<Sha256>::new_from_slice(env("LIVEKIT_API_SECRET").as_bytes()).unwrap();
    mac.update(signed.as_bytes());
    format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

/// Starts a host session for `device` with a 640x480 track.
pub async fn start_host(
    device: &TestDevice,
    config: SessionConfig,
) -> (HostSession, Receiver<HostEvent>) {
    HostSession::start(
        device.signaling.clone(),
        Arc::clone(&device.keys),
        Arc::clone(&device.known),
        640,
        480,
        config,
    )
    .await
    .expect("host start")
}

/// Starts a viewer request from `viewer` to `host` in the background.
pub fn request(
    viewer: &TestDevice,
    host: DeviceId,
    config: SessionConfig,
) -> JoinHandle<Result<(ViewerSession, Receiver<ViewerEvent>), RequestError>> {
    let (signaling, keys, known) = (
        viewer.signaling.clone(),
        Arc::clone(&viewer.keys),
        Arc::clone(&viewer.known),
    );
    tokio::spawn(async move { ViewerSession::request(signaling, keys, known, host, config).await })
}

/// Waits up to `wait` for a host event matching `pred`, discarding others.
pub async fn host_event(
    events: &mut Receiver<HostEvent>,
    wait: Duration,
    pred: impl Fn(&HostEvent) -> bool,
) -> HostEvent {
    tokio::time::timeout(wait, async {
        loop {
            let ev = events.recv().await.expect("host events ended");
            if pred(&ev) {
                return ev;
            }
        }
    })
    .await
    .expect("timed out waiting for a host event")
}

/// Waits up to `wait` for a viewer event matching `pred`, discarding others.
pub async fn viewer_event(
    events: &mut Receiver<ViewerEvent>,
    wait: Duration,
    pred: impl Fn(&ViewerEvent) -> bool,
) -> ViewerEvent {
    tokio::time::timeout(wait, async {
        loop {
            let ev = events.recv().await.expect("viewer events ended");
            if pred(&ev) {
                return ev;
            }
        }
    })
    .await
    .expect("timed out waiting for a viewer event")
}

/// Accepts the next viewer request on `host` and returns the viewer's session once connected.
pub async fn accept_next(
    host: &HostSession,
    host_events: &mut Receiver<HostEvent>,
    pending: JoinHandle<Result<(ViewerSession, Receiver<ViewerEvent>), RequestError>>,
) -> (ViewerSession, Receiver<ViewerEvent>) {
    let ev = host_event(host_events, Duration::from_secs(10), |e| {
        matches!(e, HostEvent::ViewerRequested { .. })
    })
    .await;
    let HostEvent::ViewerRequested { session_id, .. } = ev else {
        unreachable!()
    };
    host.accept(&session_id).await.expect("accept");
    let (viewer, mut events) = pending.await.unwrap().expect("viewer request");
    viewer_event(&mut events, Duration::from_secs(30), |e| {
        matches!(e, ViewerEvent::Connected)
    })
    .await;
    (viewer, events)
}

/// Publishes stamped 640x480 frames on `host` at 30 fps until the returned task is aborted.
pub fn feed_frames(host: &HostSession) -> JoinHandle<()> {
    let host = host.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(33));
        loop {
            tick.tick().await;
            host.publish_frame(&stamp::stamp_frame(640, 480, stamp::now_micros()))
                .expect("publish frame");
        }
    })
}

/// Collects the stamps of the frames `events` delivers within `wait`.
pub async fn collect_stamps(events: &mut Receiver<ViewerEvent>, wait: Duration) -> Vec<(i64, i64)> {
    let deadline = tokio::time::Instant::now() + wait;
    let mut out = Vec::new();
    while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, events.recv()).await {
        if let ViewerEvent::VideoFrame(frame) = ev {
            if let Some(stamp) = stamp::read_stamp(&frame) {
                out.push((stamp, stamp::now_micros()));
            }
        }
    }
    out
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
