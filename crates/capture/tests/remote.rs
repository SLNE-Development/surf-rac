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
//!
//! For a real desktop share, run `remote_share_host` on the machine to share;
//! it prints its device ID and, with `SURF_RAC_HOST_ID_FILE`, also writes it to
//! that file. Then run `remote_share_viewer` with `SURF_RAC_HOST_ID` (or the
//! same `SURF_RAC_HOST_ID_FILE`). The viewer prints the screen state, saves a
//! received frame to `SURF_RAC_FRAME_PNG` (default `frame.png`), switches to
//! the Speed mode and, with two or more monitors, to the second monitor.
//! `SURF_RAC_DURATION` sets how long the host stays up in seconds (default 120).

#![cfg(windows)]

#[path = "../../session/tests/common/mod.rs"]
mod common;

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{host_event, viewer_event};
use livekit::webrtc::native::yuv_helper;
use surf_rac_capture::mf::{EncodeError, MfEncoder};
use surf_rac_capture::{ScreenShare, ShareOptions};
use surf_rac_protocol::DeviceId;
use surf_rac_protocol::data::{Control, DataMessage, QualityMode, ScreenState};
use surf_rac_session::Frame;
use surf_rac_session::host::{HostEvent, HostSession};
use surf_rac_session::signaling::SignalingClient;
use surf_rac_session::viewer::{ViewerEvent, ViewerSession};
use surf_rac_session::{EncodedFrame, IdentityKey, KnownKeys, SessionConfig, VideoInput};

/// A device registered on the deployed server for a test.
struct RemoteDevice {
    /// Device ID.
    id: DeviceId,
    /// The device's identity key.
    identity: Arc<IdentityKey>,
    /// Lowercase hex SHA-256 of the device's hardware fingerprint.
    fingerprint: String,
}

/// Registers a throwaway device named `name` with a fresh identity key on `server`.
async fn register_remote(client: &reqwest::Client, server: &str, name: &str) -> RemoteDevice {
    let identity = Arc::new(IdentityKey::generate());
    let fingerprint = common::random_fingerprint();
    let id = common::register_device(client, server, None, &identity, &fingerprint, name).await;
    RemoteDevice {
        id,
        identity,
        fingerprint,
    }
}

/// Opens the signaling connection of `device` to `server`.
async fn connect_remote(server: &str, device: &RemoteDevice) -> SignalingClient {
    SignalingClient::connect(&ws_url(server), device.id, &device.identity, &device.fingerprint)
        .await
        .expect("signaling connect")
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

/// Hardware-encoded frames passed through an end-to-end encrypted session via the deployed server
/// reach the viewer as at least 100 decoded test-pattern frames in 10 s, and the host sees a
/// keyframe request.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a deployed server, an account and a hardware H.264 encoder"]
async fn passthrough_e2ee_reaches_viewer() {
    if matches!(MfEncoder::new(1280, 720, 5_000_000, 30), Err(EncodeError::NoHardware)) {
        eprintln!("no hardware H.264 encoder on this machine; skipped");
        return;
    }
    let server = common::env("SURF_RAC_SERVER");
    let client = reqwest::Client::new();
    let h = register_remote(&client, &server, "spike-host").await;
    let v = register_remote(&client, &server, "spike-viewer").await;
    let outcome = async {
        let host_sig = connect_remote(&server, &h).await;
        let (host, mut host_events) = HostSession::start(
            host_sig,
            Arc::clone(&h.identity),
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

        let viewer_sig = connect_remote(&server, &v).await;
        let pending = tokio::spawn(ViewerSession::request(
            viewer_sig,
            Arc::clone(&v.identity),
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
    assert!(outcome.0 >= 100, "only {} patterned frames in 10 s", outcome.0);
    assert!(outcome.1 >= 1, "the host never saw a keyframe request");
}

/// Writes `frame` as an RGBA PNG to `path`.
fn save_png(frame: &Frame, path: &str) {
    let (w, h) = (frame.width, frame.height);
    let luma = (w * h) as usize;
    let chroma = luma / 4;
    let (y, rest) = frame.data.split_at(luma);
    let (u, v) = rest.split_at(chroma);
    let mut rgba = vec![0u8; luma * 4];
    yuv_helper::i420_to_abgr(y, w, u, w / 2, v, w / 2, &mut rgba, w * 4, w as i32, h as i32);
    let file = std::fs::File::create(path).expect("create png");
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), w, h);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .expect("png header")
        .write_image_data(&rgba)
        .expect("png data");
}

/// Waits up to 15 s for a screen state matching `pred`.
async fn state_where(
    events: &mut tokio::sync::mpsc::Receiver<ViewerEvent>,
    pred: impl Fn(&ScreenState) -> bool,
) -> ScreenState {
    let ev = viewer_event(events, Duration::from_secs(15), |e| {
        matches!(e, ViewerEvent::DataReceived(DataMessage::Control(Control::ScreenState(s))) if pred(s))
    })
    .await;
    let ViewerEvent::DataReceived(DataMessage::Control(Control::ScreenState(s))) = ev else {
        unreachable!()
    };
    s
}

/// Collects video frames for `wait`; returns their count and the last one.
async fn frames_for(
    events: &mut tokio::sync::mpsc::Receiver<ViewerEvent>,
    wait: Duration,
) -> (usize, Option<Frame>) {
    let deadline = tokio::time::Instant::now() + wait;
    let (mut count, mut last) = (0, None);
    while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, events.recv()).await {
        if let ViewerEvent::VideoFrame(f) = ev {
            count += 1;
            last = Some(f);
        }
    }
    (count, last)
}

/// Shares this machine's screen as a host on the deployed server for a set duration, accepting
/// every viewer and applying their screen controls.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a deployed server and an account; shares this machine's screen"]
async fn remote_share_host() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("surf_rac_capture=debug,surf_rac_session=info")
        .try_init();
    let server = common::env("SURF_RAC_SERVER");
    let duration = std::env::var("SURF_RAC_DURATION")
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(120);
    let client = reqwest::Client::new();
    let dev = register_remote(&client, &server, "share-host").await;
    println!("HOST DEVICE ID: {}", dev.id);
    if let Ok(path) = std::env::var("SURF_RAC_HOST_ID_FILE") {
        std::fs::write(path, dev.id.to_string()).expect("write host id file");
    }
    let signaling = connect_remote(&server, &dev).await;
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
    let share = ScreenShare::start(host.clone(), ShareOptions::default())
        .await
        .expect("share start");
    println!("screen state: {:?}", share.state());
    let run = async {
        while let Some(ev) = events.recv().await {
            match ev {
                HostEvent::ViewerRequested { session_id, viewer, .. } => {
                    println!("viewer {viewer} requests a session, accepting");
                    host.accept(&session_id).await.expect("accept");
                }
                HostEvent::ViewerJoined { viewer } => share.viewer_joined(viewer),
                HostEvent::DataReceived {
                    viewer,
                    message: DataMessage::Control(control),
                } => share.handle_control(viewer, &control),
                HostEvent::DataReceived { .. } => {}
                other => println!("host event: {other:?}"),
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(duration), run).await;
    share.stop().await;
    host.close().await;
}

/// Connects as a viewer to the running screen-share host, saves a frame as PNG, checks Speed mode
/// and monitor switching, and requires at least 100 frames in 10 s.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a running remote_share_host"]
async fn remote_share_viewer() {
    let server = common::env("SURF_RAC_SERVER");
    let host: DeviceId = match std::env::var("SURF_RAC_HOST_ID_FILE") {
        Ok(path) => std::fs::read_to_string(path).expect("read host id file"),
        Err(_) => common::env("SURF_RAC_HOST_ID"),
    }
    .trim()
    .parse()
    .expect("host device ID");
    let png_path = std::env::var("SURF_RAC_FRAME_PNG").unwrap_or_else(|_| "frame.png".into());
    let client = reqwest::Client::new();
    let dev = register_remote(&client, &server, "share-viewer").await;
    let outcome = async {
        let signaling = connect_remote(&server, &dev).await;
        let started = Instant::now();
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
        let state = state_where(&mut events, |_| true).await;
        println!("screen state: {state:?}");

        let (_, first) = frames_for(&mut events, Duration::from_secs(3)).await;
        let first = first.expect("no frame within 3 s");
        save_png(&first, &png_path);
        println!("saved a {}x{} frame to {png_path}", first.width, first.height);
        let (count, _) = frames_for(&mut events, Duration::from_secs(10)).await;
        println!("received {count} frames in 10 s ({:.1} fps) in {:?}", count as f64 / 10.0, state.mode);

        viewer
            .send(&DataMessage::Control(Control::SetQuality { mode: QualityMode::Speed }))
            .await
            .expect("send");
        state_where(&mut events, |s| s.mode == QualityMode::Speed).await;
        let (speed_count, speed) = frames_for(&mut events, Duration::from_secs(10)).await;
        let speed = speed.expect("no frame in Speed mode");
        println!(
            "Speed mode: {speed_count} frames in 10 s ({:.1} fps) at {}x{}",
            speed_count as f64 / 10.0,
            speed.width,
            speed.height
        );
        assert!(speed.width.max(speed.height) <= 1280, "Speed frame {}x{}", speed.width, speed.height);

        if state.monitors.len() >= 2 {
            let target = if state.selected == 0 { 1 } else { 0 };
            viewer
                .send(&DataMessage::Control(Control::SelectMonitor { index: target }))
                .await
                .expect("send");
            let switched = state_where(&mut events, |s| s.selected == target).await;
            let (_, other) = frames_for(&mut events, Duration::from_secs(3)).await;
            let other = other.expect("no frame after the monitor switch");
            println!(
                "switched to monitor {} ({:?}), frames now {}x{}",
                target, switched.monitors[usize::from(target)].name, other.width, other.height
            );
        } else {
            println!("one monitor only; monitor switch not exercised");
        }
        viewer.hangup().await;
        count
    }
    .await;
    assert!(outcome >= 100, "only {outcome} frames in 10 s");
}
