//! Capability spike: proves what the LiveKit SDK does against the LiveKit dev container.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use livekit::e2ee::key_provider::{KeyProvider, KeyProviderOptions};
use livekit::e2ee::{E2eeOptions, EncryptionType};
use livekit::options::TrackPublishOptions;
use livekit::prelude::*;
use livekit::webrtc::prelude::*;
use livekit::webrtc::video_source::native::NativeVideoSource;
use livekit::webrtc::video_stream::native::NativeVideoStream;
use livekit::{StreamByteOptions, StreamReader};
use rand::Rng;
use serde_json::json;
use sha2::Sha256;
use tokio::sync::mpsc::UnboundedReceiver;

/// Reads a required environment variable.
fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

/// Mints an HS256 LiveKit token for `identity` in `room`.
fn token(room: &str, identity: &str) -> String {
    let now = chrono_now();
    let header = URL_SAFE_NO_PAD.encode(json!({"alg":"HS256","typ":"JWT"}).to_string());
    let claims = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": env("LIVEKIT_API_KEY"), "sub": identity, "name": identity,
            "nbf": now - 5, "exp": now + 600,
            "video": {"room": room, "roomJoin": true, "canPublish": true, "canSubscribe": true, "canPublishData": true}
        })
        .to_string(),
    );
    let signed = format!("{header}.{claims}");
    let mut mac = Hmac::<Sha256>::new_from_slice(env("LIVEKIT_API_SECRET").as_bytes()).unwrap();
    mac.update(signed.as_bytes());
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

/// Returns the current Unix time in seconds.
fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Returns a fresh random room name.
fn room_name() -> String {
    format!("spike-{}", rand::thread_rng().r#gen::<u64>())
}

/// Joins `room` as `identity` with `options`.
async fn join(
    room: &str,
    identity: &str,
    options: RoomOptions,
) -> (Room, UnboundedReceiver<RoomEvent>) {
    Room::connect(&env("LIVEKIT_URL"), &token(room, identity), options)
        .await
        .expect("join")
}

/// Builds E2EE options with a per-participant key provider.
fn e2ee(provider: &KeyProvider) -> E2eeOptions {
    E2eeOptions {
        encryption_type: EncryptionType::Gcm,
        key_provider: provider.clone(),
    }
}

/// Publishes a 320x240 video track and feeds constant-luma frames until the task is aborted.
async fn publish_video(room: &Room, luma: u8) -> tokio::task::JoinHandle<()> {
    let source = NativeVideoSource::new(VideoResolution { width: 320, height: 240 }, true);
    let track = LocalVideoTrack::create_video_track("screen", RtcVideoSource::Native(source.clone()));
    room.local_participant()
        .publish_track(
            LocalTrack::Video(track),
            TrackPublishOptions { source: TrackSource::Screenshare, ..Default::default() },
        )
        .await
        .expect("publish");
    tokio::spawn(async move {
        let mut ts = 0i64;
        loop {
            let mut buf = I420Buffer::new(320, 240);
            {
                let (y, u, v) = buf.data_mut();
                y.fill(luma);
                u.fill(128);
                v.fill(128);
            }
            let mut frame = VideoFrame::new(VideoRotation::VideoRotation0, buf);
            frame.timestamp_us = ts;
            source.capture_frame(&frame);
            ts += 33_333;
            tokio::time::sleep(Duration::from_millis(33)).await;
        }
    })
}

/// Waits for a subscribed video track and returns the mean luma of each received frame for `window`.
async fn collect_luma(events: &mut UnboundedReceiver<RoomEvent>, window: Duration) -> Vec<f64> {
    let deadline = tokio::time::Instant::now() + window;
    let track = loop {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Some(RoomEvent::TrackSubscribed { track: RemoteTrack::Video(t), .. })) => break t,
            Ok(Some(_)) => continue,
            _ => return Vec::new(),
        }
    };
    let mut stream = NativeVideoStream::new(track.rtc_track());
    let mut lumas = Vec::new();
    while let Ok(Some(frame)) = tokio::time::timeout_at(deadline, stream.next()).await {
        let i420 = frame.buffer.to_i420();
        let (y, _, _) = i420.data();
        lumas.push(y.iter().map(|&b| b as f64).sum::<f64>() / y.len() as f64);
    }
    lumas
}

#[tokio::test(flavor = "multi_thread")]
async fn spike_video_frames() {
    let name = room_name();
    let (a, _ae) = join(&name, "100000001", RoomOptions::default()).await;
    let (_b, mut be) = join(&name, "100000002", RoomOptions::default()).await;
    let feed = publish_video(&a, 200).await;
    let lumas = collect_luma(&mut be, Duration::from_secs(10)).await;
    feed.abort();
    println!("spike_video_frames: {} frames", lumas.len());
    assert!(lumas.len() >= 10);
}

#[tokio::test(flavor = "multi_thread")]
async fn spike_data_lossy_and_reliable() {
    let name = room_name();
    let (a, _ae) = join(&name, "100000001", RoomOptions::default()).await;
    let (_b, mut be) = join(&name, "100000002", RoomOptions::default()).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    for i in 0..20u8 {
        for (topic, reliable) in [("t-lossy", false), ("t-rel", true)] {
            a.local_participant()
                .publish_data(DataPacket {
                    payload: vec![i],
                    topic: Some(topic.into()),
                    reliable,
                    ..Default::default()
                })
                .await
                .unwrap();
        }
    }
    let (mut lossy, mut rel) = (0, Vec::new());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, be.recv()).await {
        if let RoomEvent::DataReceived { payload, topic, .. } = ev {
            match topic.as_deref() {
                Some("t-lossy") => lossy += 1,
                Some("t-rel") => rel.push(payload[0]),
                _ => {}
            }
            if rel.len() == 20 && lossy > 0 {
                break;
            }
        }
    }
    println!("spike_data: lossy {lossy}, reliable {}", rel.len());
    assert!(lossy >= 1);
    assert_eq!(rel, (0..20).collect::<Vec<u8>>());
}

#[tokio::test(flavor = "multi_thread")]
async fn spike_byte_stream() {
    let name = room_name();
    let (a, _ae) = join(&name, "100000001", RoomOptions::default()).await;
    let (_b, mut be) = join(&name, "100000002", RoomOptions::default()).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let data: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();
    a.local_participant()
        .send_bytes(
            &data,
            StreamByteOptions {
                destination_identities: vec!["100000002".into()],
                ..StreamByteOptions::new_with_topic("t-bytes")
            },
        )
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout_at(deadline, be.recv()).await {
            Ok(Some(RoomEvent::ByteStreamOpened { reader, topic, .. })) if topic == "t-bytes" => {
                let got = reader.take().unwrap().read_all().await.unwrap();
                assert_eq!(&got[..], &data[..]);
                println!("spike_byte_stream: 1 MiB received intact");
                return;
            }
            Ok(Some(_)) => continue,
            other => panic!("no byte stream: {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn spike_forced_relay() {
    let name = room_name();
    let mut options = RoomOptions::default();
    options.rtc_config.ice_transport_type = IceTransportsType::Relay;
    let (a, _ae) = join(&name, "100000001", options.clone()).await;
    let (_b, mut be) = join(&name, "100000002", options).await;
    let feed = publish_video(&a, 200).await;
    let lumas = collect_luma(&mut be, Duration::from_secs(15)).await;
    feed.abort();
    println!("spike_forced_relay: {} frames", lumas.len());
    assert!(lumas.len() >= 10);
}

#[allow(deprecated)]
#[tokio::test(flavor = "multi_thread")]
async fn spike_frame_encryption() {
    let name = room_name();
    let (k0, k1, wrong) = ([1u8; 32].to_vec(), [2u8; 32].to_vec(), [3u8; 32].to_vec());
    let host: ParticipantIdentity = "100000001".into();
    let pa = KeyProvider::new(KeyProviderOptions::default());
    let pb = KeyProvider::new(KeyProviderOptions::default());
    let pc = KeyProvider::new(KeyProviderOptions::default());
    pa.set_key(&host, 0, k0.clone());
    pb.set_key(&host, 0, k0.clone());
    pc.set_key(&host, 0, wrong);
    let opts = |p: &KeyProvider| {
        let mut o = RoomOptions::default();
        o.e2ee = Some(e2ee(p));
        o
    };
    let (a, _ae) = join(&name, "100000001", opts(&pa)).await;
    a.e2ee_manager().set_enabled(true);
    let (b, mut be) = join(&name, "100000002", opts(&pb)).await;
    b.e2ee_manager().set_enabled(true);
    let (c, mut ce) = join(&name, "100000003", opts(&pc)).await;
    c.e2ee_manager().set_enabled(true);
    let feed = publish_video(&a, 200).await;
    let (lb, lc) = tokio::join!(
        collect_luma(&mut be, Duration::from_secs(10)),
        collect_luma(&mut ce, Duration::from_secs(10))
    );
    let good = |l: &[f64]| l.iter().filter(|&&m| (190.0..210.0).contains(&m)).count();
    println!("spike_frame_encryption: B {} good of {}, C {} good of {}", good(&lb), lb.len(), good(&lc), lc.len());
    assert!(good(&lb) >= 10);
    assert_eq!(good(&lc), 0);

    // Switch the sender to key index 1.
    pb.set_key(&host, 1, k1.clone());
    pa.set_key(&host, 1, k1);
    for ((id, _), cryptor) in a.e2ee_manager().frame_cryptors() {
        if id == host {
            cryptor.set_key_index(1);
        }
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let track = b
        .remote_participants()
        .values()
        .flat_map(|p| p.track_publications().into_values())
        .find_map(|p| match p.track() {
            Some(RemoteTrack::Video(t)) => Some(t),
            _ => None,
        })
        .expect("b has the video track");
    let mut stream = NativeVideoStream::new(track.rtc_track());
    let mut after = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while let Ok(Some(frame)) = tokio::time::timeout_at(deadline, stream.next()).await {
        let i420 = frame.buffer.to_i420();
        let (y, _, _) = i420.data();
        let mean = y.iter().map(|&v| v as f64).sum::<f64>() / y.len() as f64;
        if (190.0..210.0).contains(&mean) {
            after += 1;
        }
    }
    let indices: Vec<i32> = a.e2ee_manager().frame_cryptors().values().map(|c| c.key_index()).collect();
    println!("spike_frame_encryption: after switch B {after} good frames, sender indices {indices:?}");
    feed.abort();
    assert!(after >= 10);
}

#[allow(deprecated)]
#[tokio::test(flavor = "multi_thread")]
async fn spike_data_e2ee() {
    let name = room_name();
    let host: ParticipantIdentity = "100000001".into();
    let pa = KeyProvider::new(KeyProviderOptions::default());
    let pc = KeyProvider::new(KeyProviderOptions::default());
    pa.set_key(&host, 0, [1u8; 32].to_vec());
    pc.set_key(&host, 0, [3u8; 32].to_vec());
    for (label, use_encryption_field) in [("e2ee field", false), ("encryption field", true)] {
        let opts = |p: &KeyProvider| {
            let mut o = RoomOptions::default();
            if use_encryption_field {
                o.encryption = Some(e2ee(p));
            } else {
                o.e2ee = Some(e2ee(p));
            }
            o
        };
        let room = format!("{name}-{use_encryption_field}");
        let (a, _ae) = join(&room, "100000001", opts(&pa)).await;
        let (_c, mut ce) = join(&room, "100000003", opts(&pc)).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        a.local_participant()
            .publish_data(DataPacket {
                payload: b"secret-payload".to_vec(),
                topic: Some("t".into()),
                reliable: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let mut seen = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, ce.recv()).await {
            if let RoomEvent::DataReceived { payload, .. } = ev {
                seen = Some(payload.to_vec());
                break;
            }
        }
        println!(
            "spike_data_e2ee [{label}]: wrong-key participant saw {:?}",
            seen.as_deref().map(String::from_utf8_lossy)
        );
    }
}
