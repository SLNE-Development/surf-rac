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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a deployed server and an account"]
async fn session_through_deployed_server() {
    let server = common::env("SURF_RAC_SERVER");
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{server}/v1/login"))
        .json(&json!({"username": common::env("SURF_RAC_USERNAME"), "password": common::env("SURF_RAC_PASSWORD")}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "login");
    let token = res.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let host_dev = register_device(&client, &server, &token, "smoke-host").await;
    let viewer_dev = register_device(&client, &server, &token, "smoke-viewer").await;
    let ws = server
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);

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
