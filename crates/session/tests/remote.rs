//! Smoke test against a deployed signaling server and its LiveKit.
//!
//! Ignored by default. Run it with an existing account:
//!
//! ```sh
//! SURF_RAC_SERVER=https://rac.slne.dev SURF_RAC_USERNAME=... SURF_RAC_PASSWORD=... \
//!   cargo test -p surf-rac-session --test remote -- --ignored --nocapture
//! ```
//!
//! It registers two throwaway devices on the account, runs a host and a viewer
//! session between them through the deployed server, and deletes the devices.
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
use rand::Rng;
use serde_json::{Value, json};
use surf_rac_protocol::DeviceId;
use surf_rac_protocol::data::DataMessage;
use surf_rac_session::host::{HostEvent, HostSession};
use surf_rac_session::signaling::SignalingClient;
use surf_rac_session::viewer::{ViewerEvent, ViewerSession};
use surf_rac_session::{DeviceKeys, KnownKeys, SessionConfig};

/// A device registered on the deployed server for this test.
struct RemoteDevice {
    /// Device ID.
    id: DeviceId,
    /// Device secret.
    secret: String,
}

/// Registers a throwaway device named `name` for `token` on `server`.
async fn register_device(
    client: &reqwest::Client,
    server: &str,
    token: &str,
    name: &str,
) -> RemoteDevice {
    let fingerprint: String = (0..64)
        .map(|_| char::from_digit(rand::thread_rng().gen_range(0..16), 16).unwrap())
        .collect();
    let res = client
        .post(format!("{server}/v1/devices"))
        .bearer_auth(token)
        .json(&json!({"fingerprint_hash": fingerprint, "name": name}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "register {name}");
    let body: Value = res.json().await.unwrap();
    RemoteDevice {
        id: body["device_id"].as_str().unwrap().parse().unwrap(),
        secret: body["device_secret"].as_str().unwrap().to_owned(),
    }
}

/// Deletes device `id` of `token` on `server`.
async fn delete_device(client: &reqwest::Client, server: &str, token: &str, id: DeviceId) {
    let res = client
        .delete(format!("{server}/v1/devices/{id}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    println!("deleted device {id}: HTTP {}", res.status());
}

/// Logs in to `server` with the account from the environment and returns the session token.
async fn login(client: &reqwest::Client, server: &str) -> String {
    let res = client
        .post(format!("{server}/v1/login"))
        .json(&json!({"username": common::env("SURF_RAC_USERNAME"), "password": common::env("SURF_RAC_PASSWORD")}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "login");
    res.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Returns the WebSocket base URL of the HTTP base `server`.
fn ws_url(server: &str) -> String {
    server
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a deployed server and an account; run on the first machine"]
async fn remote_host() {
    let server = common::env("SURF_RAC_SERVER");
    let duration = std::env::var("SURF_RAC_DURATION")
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(300);
    let client = reqwest::Client::new();
    let token = login(&client, &server).await;
    let dev = register_device(&client, &server, &token, "two-machine-host").await;
    println!(
        "HOST DEVICE ID: {}  (set SURF_RAC_HOST_ID to this on the viewer machine)",
        dev.id
    );
    let signaling = SignalingClient::connect(&ws_url(&server), &token, dev.id, &dev.secret)
        .await
        .expect("host signaling");
    let (host, mut events) = HostSession::start(
        signaling,
        Arc::new(DeviceKeys::generate()),
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
    delete_device(&client, &server, &token, dev.id).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a running remote_host; run on the second machine"]
async fn remote_viewer() {
    let server = common::env("SURF_RAC_SERVER");
    let host: DeviceId = common::env("SURF_RAC_HOST_ID")
        .parse()
        .expect("SURF_RAC_HOST_ID");
    let client = reqwest::Client::new();
    let token = login(&client, &server).await;
    let dev = register_device(&client, &server, &token, "two-machine-viewer").await;
    let outcome = async {
        let signaling = SignalingClient::connect(&ws_url(&server), &token, dev.id, &dev.secret)
            .await
            .expect("viewer signaling");
        let started = std::time::Instant::now();
        let (viewer, mut events) = ViewerSession::request(
            signaling,
            Arc::new(DeviceKeys::generate()),
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
    delete_device(&client, &server, &token, dev.id).await;
    assert!(outcome >= 100, "only {outcome} frames in 10 s");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a deployed server and an account"]
async fn session_through_deployed_server() {
    let server = common::env("SURF_RAC_SERVER");
    let client = reqwest::Client::new();
    let token = login(&client, &server).await;

    let host_dev = register_device(&client, &server, &token, "smoke-host").await;
    let viewer_dev = register_device(&client, &server, &token, "smoke-viewer").await;
    let ws = ws_url(&server);

    let outcome = tokio::time::timeout(Duration::from_secs(120), async {
        let host_sig = SignalingClient::connect(&ws, &token, host_dev.id, &host_dev.secret)
            .await
            .expect("host signaling");
        let viewer_sig = SignalingClient::connect(&ws, &token, viewer_dev.id, &viewer_dev.secret)
            .await
            .expect("viewer signaling");
        let (host, mut host_events) = HostSession::start(
            host_sig,
            Arc::new(DeviceKeys::generate()),
            Arc::new(Mutex::new(KnownKeys::default())),
            640,
            480,
            SessionConfig::default(),
        )
        .await
        .expect("host start");
        let feed = feed_frames(&host);
        let host_id = host_dev.id;
        let pending = tokio::spawn(async move {
            ViewerSession::request(
                viewer_sig,
                Arc::new(DeviceKeys::generate()),
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

    delete_device(&client, &server, &token, host_dev.id).await;
    delete_device(&client, &server, &token, viewer_dev.id).await;

    let (frames, median, _) = outcome.expect("session did not complete within 120 s");
    let median = median.expect("no frames received");
    println!(
        "deployed server: {frames} stamped frames, median one-way delay {} ms",
        median / 1000
    );
    assert!(frames >= 100, "only {frames} frames");
    assert!(median < 200_000, "median delay {median} us");
}
