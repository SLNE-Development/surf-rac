//! Tests against a deployed signaling server and its LiveKit.
//!
//! Ignored by default. Run them on Windows with an existing account:
//!
//! ```sh
//! SURF_RAC_SERVER=https://rac.slne.dev SURF_RAC_USERNAME=... SURF_RAC_PASSWORD=... \
//!   cargo test -p surf-rac-capture --release --test remote -- --ignored --nocapture
//! ```
//!
//! `passthrough_e2ee_reaches_viewer` sends hardware-encoded H.264 through the
//! pass-through track to a viewer on the same machine.

#![cfg(windows)]

#[path = "../../session/tests/common/mod.rs"]
mod common;

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{host_event, viewer_event};
use rand::Rng;
use serde_json::{Value, json};
use surf_rac_capture::mf::{EncodeError, MfEncoder};
use surf_rac_protocol::DeviceId;
use surf_rac_session::host::{HostEvent, HostSession};
use surf_rac_session::signaling::SignalingClient;
use surf_rac_session::viewer::{ViewerEvent, ViewerSession};
use surf_rac_session::{DeviceKeys, EncodedFrame, KnownKeys, SessionConfig, VideoInput};

/// A device registered on the deployed server for a test.
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

/// Returns a `w` x `h` NV12 frame with a white bar at a position set by `n`.
fn nv12_bar(w: u32, h: u32, n: u32) -> Vec<u8> {
    let (w, h) = (w as usize, h as usize);
    let mut data = vec![16u8; w * h];
    let x0 = (n as usize * 16) % w;
    for row in data.chunks_mut(w) {
        for px in row.iter_mut().skip(x0).take(64) {
            *px = 235;
        }
    }
    data.resize(w * h * 3 / 2, 128);
    data
}

/// Encodes a moving bar on the hardware encoder and publishes it on `host`
/// until `stop` is set, counting the keyframe requests it serves.
fn feed_encoded(host: HostSession, stop: Arc<AtomicBool>, requests: Arc<AtomicU32>) {
    let mut enc = MfEncoder::new(1280, 720, 5_000_000, 30).expect("encoder");
    let started = Instant::now();
    let mut n = 0u32;
    let mut busy = Duration::ZERO;
    while !stop.load(Ordering::SeqCst) {
        let t = Instant::now();
        let force = host.take_keyframe_request();
        if force {
            requests.fetch_add(1, Ordering::SeqCst);
        }
        let ts = started.elapsed().as_micros() as i64 + 1;
        for au in enc.encode(&nv12_bar(1280, 720, n), ts, force).expect("encode") {
            let frame = EncodedFrame {
                width: 1280,
                height: 720,
                timestamp_us: au.timestamp_us,
                keyframe: au.keyframe,
                data: &au.data,
            };
            host.publish_encoded(&frame).expect("publish encoded");
        }
        n += 1;
        busy += t.elapsed();
        let next = started + Duration::from_micros(33_333) * n;
        std::thread::sleep(next.saturating_duration_since(Instant::now()));
    }
    println!("host encoded {n} frames, {:?} per frame on average", busy / n.max(1));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a deployed server, an account and a hardware H.264 encoder"]
async fn passthrough_e2ee_reaches_viewer() {
    if matches!(MfEncoder::new(1280, 720, 5_000_000, 30), Err(EncodeError::NoHardware)) {
        eprintln!("no hardware H.264 encoder on this machine; skipped");
        return;
    }
    let server = common::env("SURF_RAC_SERVER");
    let client = reqwest::Client::new();
    let token = login(&client, &server).await;
    let h = register_device(&client, &server, &token, "spike-host").await;
    let v = register_device(&client, &server, &token, "spike-viewer").await;
    let outcome = async {
        let host_sig = SignalingClient::connect(&ws_url(&server), &token, h.id, &h.secret)
            .await
            .expect("host signaling");
        let (host, mut host_events) = HostSession::start(
            host_sig,
            Arc::new(DeviceKeys::generate()),
            Arc::new(Mutex::new(KnownKeys::default())),
            1280,
            720,
            SessionConfig::default(),
        )
        .await
        .expect("host start");
        host.set_video_input(VideoInput::Encoded, 1280, 720)
            .await
            .expect("encoded input");

        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicU32::new(0));
        let encoder = {
            let (host, stop, requests) = (host.clone(), stop.clone(), requests.clone());
            std::thread::spawn(move || feed_encoded(host, stop, requests))
        };

        let viewer_sig = SignalingClient::connect(&ws_url(&server), &token, v.id, &v.secret)
            .await
            .expect("viewer signaling");
        let pending = tokio::spawn(ViewerSession::request(
            viewer_sig,
            Arc::new(DeviceKeys::generate()),
            Arc::new(Mutex::new(KnownKeys::default())),
            h.id,
            SessionConfig::default(),
        ));
        let ev = host_event(&mut host_events, Duration::from_secs(15), |e| {
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

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let (mut frames, mut patterned) = (0, 0);
        while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, events.recv()).await {
            if let ViewerEvent::VideoFrame(f) = ev {
                frames += 1;
                let luma = &f.data[..(f.width * f.height) as usize];
                if (f.width, f.height) == (1280, 720)
                    && luma.iter().any(|&y| y > 200)
                    && luma.iter().any(|&y| y < 40)
                {
                    patterned += 1;
                }
            }
        }
        stop.store(true, Ordering::SeqCst);
        encoder.join().unwrap();
        let requests = requests.load(Ordering::SeqCst);
        println!(
            "viewer decoded {frames} frames in 10 s, {patterned} with the test pattern; host saw {requests} keyframe requests"
        );
        viewer.hangup().await;
        host.close().await;
        (patterned, requests)
    }
    .await;
    delete_device(&client, &server, &token, h.id).await;
    delete_device(&client, &server, &token, v.id).await;
    assert!(outcome.0 >= 100, "only {} patterned frames in 10 s", outcome.0);
    assert!(outcome.1 >= 1, "the host never saw a keyframe request");
}
