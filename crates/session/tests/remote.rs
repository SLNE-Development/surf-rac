//! Smoke test against a deployed signaling server and its LiveKit.
//!
//! Ignored by default. Run it with:
//!
//! ```sh
//! SURF_RAC_SERVER=https://rac.slne.dev \
//!   cargo test -p surf-rac-session --test remote -- --ignored --nocapture
//! ```
//!
//! It registers two throwaway devices with fresh identity keys and runs a host
//! and a viewer session between them through the deployed server.
//!
//! For a test between two machines, run `remote_host` on one machine; it prints
//! its device ID. Then run `remote_viewer` on the other with
//! `SURF_RAC_HOST_ID=<that id>`. The host accepts the first request, streams a
//! moving test pattern and echoes key messages; the viewer reports frames per
//! second and data round-trip times. `SURF_RAC_DURATION` sets how long the host
//! stays up in seconds (default 300).

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{collect_stamps, feed_frames, host_event, stamp, viewer_event};
use surf_rac_protocol::DeviceId;
use surf_rac_protocol::data::DataMessage;
use surf_rac_session::host::{HostEvent, HostSession};
use surf_rac_session::signaling::SignalingClient;
use surf_rac_session::viewer::{ViewerEvent, ViewerSession};
use surf_rac_session::{IdentityKey, KnownKeys, SessionConfig};

/// A device registered on the deployed server for this test.
struct RemoteDevice {
    /// Device ID.
    id: DeviceId,
    /// The device's identity key.
    identity: Arc<IdentityKey>,
    /// Lowercase hex SHA-256 of the device's hardware fingerprint.
    fingerprint: String,
}

impl RemoteDevice {
    /// Registers a throwaway device named `name` with a fresh identity key on `server`.
    async fn register(client: &reqwest::Client, server: &str, name: &str) -> Self {
        let identity = Arc::new(IdentityKey::generate());
        let fingerprint = common::random_fingerprint();
        let id = common::register_device(client, server, None, &identity, &fingerprint, name).await;
        Self {
            id,
            identity,
            fingerprint,
        }
    }

    /// Connects this device to the signaling server at `ws`.
    async fn connect(&self, ws: &str) -> SignalingClient {
        SignalingClient::connect(ws, self.id, &self.identity, &self.fingerprint)
            .await
            .expect("signaling connect")
    }
}

/// Returns the WebSocket base URL of the HTTP base `server`.
fn ws_url(server: &str) -> String {
    server
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a deployed server; run on the first machine"]
async fn remote_host() {
    let server = common::env("SURF_RAC_SERVER");
    let duration = std::env::var("SURF_RAC_DURATION")
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(300);
    let client = reqwest::Client::new();
    let dev = RemoteDevice::register(&client, &server, "two-machine-host").await;
    println!(
        "HOST DEVICE ID: {}  (set SURF_RAC_HOST_ID to this on the viewer machine)",
        dev.id
    );
    let signaling = dev.connect(&ws_url(&server)).await;
    let (host, mut events) = HostSession::start(
        signaling,
        Arc::clone(&dev.identity),
        Arc::new(Mutex::new(KnownKeys::default())),
        1280,
        720,
        SessionConfig::default(),
    )
    .await
    .expect("host start");
    let feed = {
        let host = host.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(33));
            loop {
                tick.tick().await;
                let _ = host.publish_frame(&stamp::stamp_frame(1280, 720, stamp::now_micros()));
            }
        })
    };
    let run = async {
        while let Some(ev) = events.recv().await {
            match ev {
                HostEvent::ViewerRequested {
                    session_id,
                    viewer,
                    fingerprint,
                    ..
                } => {
                    println!("viewer {viewer} requests session (key {fingerprint}), accepting");
                    host.accept(&session_id).await.expect("accept");
                }
                HostEvent::DataReceived {
                    viewer,
                    message: message @ DataMessage::Key { .. },
                } => {
                    let _ = host.send(viewer, &message).await;
                }
                HostEvent::DataReceived { .. } => {}
                other => println!("host event: {other:?}"),
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(duration), run).await;
    feed.abort();
    host.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a running remote_host; run on the second machine"]
async fn remote_viewer() {
    let server = common::env("SURF_RAC_SERVER");
    let host: DeviceId = common::env("SURF_RAC_HOST_ID")
        .parse()
        .expect("SURF_RAC_HOST_ID");
    let client = reqwest::Client::new();
    let dev = RemoteDevice::register(&client, &server, "two-machine-viewer").await;
    let outcome = async {
        let signaling = dev.connect(&ws_url(&server)).await;
        let started = std::time::Instant::now();
        let (viewer, mut events) = ViewerSession::request(
            signaling,
            Arc::clone(&dev.identity),
            Arc::new(Mutex::new(KnownKeys::default())),
            host,
            SessionConfig::default(),
        )
        .await
        .expect("session request");
        viewer_event(&mut events, Duration::from_secs(30), |e| matches!(e, ViewerEvent::Connected)).await;
        println!("connected after {} ms", started.elapsed().as_millis());
        let frames = collect_stamps(&mut events, Duration::from_secs(10)).await;
        println!("received {} stamped 1280x720 frames in 10 s ({:.1} fps)", frames.len(), frames.len() as f64 / 10.0);
        let mut rtts = Vec::new();
        for code in 0..20u32 {
            let sent = std::time::Instant::now();
            viewer.send(&DataMessage::Key { code, down: true }).await.expect("send");
            viewer_event(&mut events, Duration::from_secs(5), |e| {
                matches!(e, ViewerEvent::DataReceived(DataMessage::Key { code: c, .. }) if *c == code)
            })
            .await;
            rtts.push(sent.elapsed().as_micros() as i64);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        rtts.sort_unstable();
        println!(
            "data round trip through the SFU: median {} ms, max {} ms (one way about half)",
            rtts[rtts.len() / 2] / 1000,
            rtts[rtts.len() - 1] / 1000
        );
        viewer.hangup().await;
        frames.len()
    }
    .await;
    assert!(outcome >= 100, "only {outcome} frames in 10 s");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a deployed server"]
async fn session_through_deployed_server() {
    let server = common::env("SURF_RAC_SERVER");
    let client = reqwest::Client::new();
    let host_dev = RemoteDevice::register(&client, &server, "smoke-host").await;
    let viewer_dev = RemoteDevice::register(&client, &server, "smoke-viewer").await;
    let ws = ws_url(&server);

    let outcome = tokio::time::timeout(Duration::from_secs(120), async {
        let host_sig = host_dev.connect(&ws).await;
        let viewer_sig = viewer_dev.connect(&ws).await;
        let (host, mut host_events) = HostSession::start(
            host_sig,
            Arc::clone(&host_dev.identity),
            Arc::new(Mutex::new(KnownKeys::default())),
            640,
            480,
            SessionConfig::default(),
        )
        .await
        .expect("host start");
        let feed = feed_frames(&host);
        let host_id = host_dev.id;
        let viewer_identity = Arc::clone(&viewer_dev.identity);
        let pending = tokio::spawn(async move {
            ViewerSession::request(
                viewer_sig,
                viewer_identity,
                Arc::new(Mutex::new(KnownKeys::default())),
                host_id,
                SessionConfig::default(),
            )
            .await
        });
        let HostEvent::ViewerRequested { session_id, .. } =
            host_event(&mut host_events, Duration::from_secs(15), |e| {
                matches!(e, HostEvent::ViewerRequested { .. })
            })
            .await
        else {
            unreachable!()
        };
        host.accept(&session_id).await.expect("accept");
        let (viewer, mut events) = pending.await.unwrap().expect("viewer request");
        viewer_event(&mut events, Duration::from_secs(30), |e| {
            matches!(e, ViewerEvent::Connected)
        })
        .await;

        let _warmup = collect_stamps(&mut events, Duration::from_secs(2)).await;
        let mut delays: Vec<i64> = collect_stamps(&mut events, Duration::from_secs(10))
            .await
            .into_iter()
            .map(|(sent, got)| got - sent)
            .collect();
        delays.sort_unstable();
        let median = delays.get(delays.len() / 2).copied();

        let key = DataMessage::Key {
            code: 30,
            down: true,
        };
        viewer.send(&key).await.expect("viewer send");
        host_event(
            &mut host_events,
            Duration::from_secs(10),
            |e| matches!(e, HostEvent::DataReceived { message, .. } if *message == key),
        )
        .await;
        let back = DataMessage::Key {
            code: 31,
            down: true,
        };
        host.send(viewer_dev.id, &back).await.expect("host send");
        viewer_event(
            &mut events,
            Duration::from_secs(10),
            |e| matches!(e, ViewerEvent::DataReceived(m) if *m == back),
        )
        .await;

        feed.abort();
        viewer.hangup().await;
        host.close().await;
        (delays.len(), median, stamp::now_micros())
    })
    .await;

    let (frames, median, _) = outcome.expect("session did not complete within 120 s");
    let median = median.expect("no frames received");
    println!(
        "deployed server: {frames} stamped frames, median one-way delay {} ms",
        median / 1000
    );
    assert!(frames >= 100, "only {frames} frames");
    assert!(median < 200_000, "median delay {median} us");
}
