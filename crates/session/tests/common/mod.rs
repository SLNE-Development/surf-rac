//! Shared helpers for the session integration tests: an in-process signaling
//! server, devices registered by identity key and LiveKit tokens.

#![allow(dead_code)]

pub mod stamp;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::PgPool;
use surf_rac_protocol::DeviceId;
use surf_rac_server::config::Config;
use surf_rac_server::state::AppState;
use surf_rac_session::host::{HostEvent, HostSession};
use surf_rac_session::signaling::{SignalingClient, SignalingError};
use surf_rac_session::viewer::{RequestError, RequestOptions, ViewerEvent, ViewerSession};
use surf_rac_session::{IdentityKey, KnownKeys, SessionConfig};
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
        Arc::clone(&device.identity),
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
    request_with(viewer, host, RequestOptions::default(), config)
}

/// Starts a viewer request from `viewer` to `host` with `options` in the background.
pub fn request_with(
    viewer: &TestDevice,
    host: DeviceId,
    options: RequestOptions,
    config: SessionConfig,
) -> JoinHandle<Result<(ViewerSession, Receiver<ViewerEvent>), RequestError>> {
    let (signaling, identity, known) = (
        viewer.signaling.clone(),
        Arc::clone(&viewer.identity),
        Arc::clone(&viewer.known),
    );
    tokio::spawn(async move {
        ViewerSession::request_with(signaling, identity, known, host, options, config).await
    })
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
    /// HTTP client for device setup.
    pub client: reqwest::Client,
    /// Pool of this test's database.
    pub pool: PgPool,
}

/// A registered device that is not connected.
pub struct Registered {
    /// Device ID.
    pub id: DeviceId,
    /// The device's identity key.
    pub identity: Arc<IdentityKey>,
    /// Lowercase hex SHA-256 of the device's hardware fingerprint.
    pub fingerprint: String,
}

/// A registered, connected device.
pub struct TestDevice {
    /// Device ID.
    pub id: DeviceId,
    /// The device's name.
    pub name: String,
    /// The device's identity key.
    pub identity: Arc<IdentityKey>,
    /// Lowercase hex SHA-256 of the device's hardware fingerprint.
    pub fingerprint: String,
    /// Open signaling connection.
    pub signaling: SignalingClient,
    /// The device's pinned peer keys.
    pub known: Arc<Mutex<KnownKeys>>,
}

/// Returns the configuration of a test server that hands out `livekit_url`.
///
/// The registration and per-target session request limits are high enough
/// that no test hits them by accident.
pub fn test_config(livekit_url: &str) -> Config {
    Config {
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
        register_per_hour: 1000,
        session_requests_per_minute: 1000,
    }
}

/// Registers a device for `identity` with fingerprint `fingerprint` and name
/// `name` on the server at `http` and returns its ID.
///
/// The request is signed by `identity`; with `ip` set it claims that client
/// address in `x-forwarded-for`.
pub async fn register_device(
    client: &reqwest::Client,
    http: &str,
    ip: Option<&str>,
    identity: &IdentityKey,
    fingerprint: &str,
    name: &str,
) -> DeviceId {
    let public = identity.public().to_bytes();
    let message = surf_rac_protocol::register_message(&public, fingerprint, name);
    let signature = SigningKey::from_bytes(&identity.to_bytes()).sign(&message);
    let mut req = client.post(format!("{http}/v1/devices"));
    if let Some(ip) = ip {
        req = req.header("x-forwarded-for", ip);
    }
    let res = req
        .json(&json!({
            "public_key": STANDARD.encode(public),
            "fingerprint_hash": fingerprint,
            "name": name,
            "signature": STANDARD.encode(signature.to_bytes()),
            "protocol_version": surf_rac_protocol::PROTOCOL_VERSION,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "register {name}");
    let body: Value = res.json().await.unwrap();
    body["device_id"].as_str().unwrap().parse().unwrap()
}

/// Returns a random 64-character lowercase hex fingerprint hash.
pub fn random_fingerprint() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl TestEnv {
    /// Starts a server whose LiveKit settings come from the environment.
    pub async fn start(pool: PgPool) -> TestEnv {
        Self::start_with_livekit(pool, &env("LIVEKIT_URL")).await
    }

    /// Starts a server that hands out `livekit_url` to clients.
    pub async fn start_with_livekit(pool: PgPool, livekit_url: &str) -> TestEnv {
        Self::start_with(pool, livekit_url, |_| {}).await
    }

    /// Starts a server that hands out `livekit_url`, letting `adjust` change its state first.
    pub async fn start_with(
        pool: PgPool,
        livekit_url: &str,
        adjust: impl FnOnce(&mut AppState),
    ) -> TestEnv {
        let mut state = AppState::new(pool.clone(), Arc::new(test_config(livekit_url)));
        adjust(&mut state);
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

    /// Registers device number `n` named `name` with a fresh identity key, without connecting it.
    pub async fn register(&self, name: &str, n: u32) -> Registered {
        let identity = Arc::new(IdentityKey::generate());
        let fingerprint = format!("{n:064x}");
        let ip = format!("172.16.{}.{}", n / 256, n % 256);
        let id = register_device(
            &self.client,
            &self.http,
            Some(&ip),
            &identity,
            &fingerprint,
            name,
        )
        .await;
        Registered {
            id,
            identity,
            fingerprint,
        }
    }

    /// Connects the registered device `device` to the signaling server.
    pub async fn connect(&self, device: &Registered) -> Result<SignalingClient, SignalingError> {
        SignalingClient::connect(&self.ws, device.id, &device.identity, &device.fingerprint).await
    }

    /// Registers and connects device number `n` named `name`.
    pub async fn device(&self, name: &str, n: u32) -> TestDevice {
        let registered = self.register(name, n).await;
        let signaling = self.connect(&registered).await.expect("signaling connect");
        TestDevice {
            id: registered.id,
            name: name.to_owned(),
            identity: registered.identity,
            fingerprint: registered.fingerprint,
            signaling,
            known: Arc::new(Mutex::new(KnownKeys::default())),
        }
    }
}

impl TestDevice {
    /// Returns this device's registration, for opening another connection.
    pub fn registered(&self) -> Registered {
        Registered {
            id: self.id,
            identity: Arc::clone(&self.identity),
            fingerprint: self.fingerprint.clone(),
        }
    }
}

/// Publishes stamped frames on `host` at 30 fps: `width` x `height` until `switch_after`
/// has passed, then `then_width` x `then_height`, until the returned task is aborted.
pub fn feed_frames_resizing(
    host: &HostSession,
    (width, height): (u32, u32),
    switch_after: Duration,
    (then_width, then_height): (u32, u32),
) -> JoinHandle<()> {
    let host = host.clone();
    tokio::spawn(async move {
        let started = tokio::time::Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(33));
        loop {
            tick.tick().await;
            let (w, h) = if started.elapsed() < switch_after {
                (width, height)
            } else {
                (then_width, then_height)
            };
            host.publish_frame(&stamp::stamp_frame(w, h, stamp::now_micros()))
                .expect("publish frame");
        }
    })
}

/// Collects the size and stamp of every frame `events` delivers within `wait`.
pub async fn collect_sized(
    events: &mut Receiver<ViewerEvent>,
    wait: Duration,
) -> Vec<(u32, u32, Option<i64>)> {
    let deadline = tokio::time::Instant::now() + wait;
    let mut out = Vec::new();
    while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, events.recv()).await {
        if let ViewerEvent::VideoFrame(frame) = ev {
            out.push((frame.width, frame.height, stamp::read_stamp(&frame)));
        }
    }
    out
}
