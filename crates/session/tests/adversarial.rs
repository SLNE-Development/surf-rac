//! Key rotation and attacks from inside the SFU path.

mod common;

use std::time::Duration;

use common::{
    TestEnv, accept_next, collect_stamps, feed_frames, host_event, mint_token, request, start_host,
    unix_now, viewer_event,
};
use futures_util::StreamExt;
use livekit::StreamByteOptions;
use livekit::e2ee::key_provider::{KeyProvider, KeyProviderOptions};
use livekit::e2ee::{E2eeOptions, EncryptionType};
use livekit::prelude::*;
use livekit::webrtc::prelude::VideoBuffer;
use livekit::webrtc::video_stream::native::NativeVideoStream;
use sqlx::PgPool;
use surf_rac_protocol::data::{DataMessage, TOPIC_CLIPBOARD, TOPIC_INPUT};
use surf_rac_session::host::HostEvent;
use surf_rac_session::viewer::ViewerEvent;
use surf_rac_session::{EndReason, SessionConfig};

/// Identity of the eavesdropping participant.
const EAVESDROPPER: &str = "999999999";

/// Joins `room` with a token minted from the API secret, as the SFU operator could,
/// with frame decryption keyed by a random key for `host`.
#[allow(deprecated)]
async fn eavesdrop(
    room: &str,
    host: &str,
) -> (Room, tokio::sync::mpsc::UnboundedReceiver<RoomEvent>) {
    let now = unix_now();
    let token = mint_token(room, EAVESDROPPER, true, now - 5, now + 600);
    let provider = KeyProvider::new(KeyProviderOptions::default());
    provider.set_key(&host.to_string().into(), 0, vec![0x5a; 32]);
    let mut options = RoomOptions::default();
    options.e2ee = Some(E2eeOptions {
        encryption_type: EncryptionType::Gcm,
        key_provider: provider,
    });
    let (lk_room, events) = Room::connect(&common::env("LIVEKIT_URL"), &token, options)
        .await
        .expect("eavesdropper joins");
    lk_room.e2ee_manager().set_enabled(true);
    (lk_room, events)
}

#[sqlx::test(migrations = "../server/migrations")]
async fn key_rotates_when_viewer_leaves(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let h = env.device("host", 1).await;
    let (v1, v2) = (
        env.device("viewer1", 2).await,
        env.device("viewer2", 3).await,
    );
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let feed = feed_frames(&host);
    let pending = request(&v1, h.id, SessionConfig::default());
    let (s1, _e1) = accept_next(&host, &mut host_events, pending).await;
    let pending = request(&v2, h.id, SessionConfig::default());
    let (s2, mut e2) = accept_next(&host, &mut host_events, pending).await;
    assert_eq!(s2.media_key_index(), Some(0));

    s1.hangup().await;
    host_event(
        &mut host_events,
        Duration::from_secs(10),
        |e| matches!(e, HostEvent::ViewerLeft { viewer } if *viewer == v1.id),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while s2.media_key_index() != Some(1) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("remaining viewer got the rotated key");
    tokio::time::sleep(Duration::from_secs(1)).await;
    let stamps = collect_stamps(&mut e2, Duration::from_secs(5)).await;
    feed.abort();
    assert!(
        stamps.len() >= 10,
        "only {} frames after rotation",
        stamps.len()
    );
}

#[sqlx::test(migrations = "../server/migrations")]
async fn hangup_rotates_key_for_remaining_viewers(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let h = env.device("host", 1).await;
    let (v1, v2) = (
        env.device("viewer1", 2).await,
        env.device("viewer2", 3).await,
    );
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v1, h.id, SessionConfig::default());
    let (_s1, mut e1) = accept_next(&host, &mut host_events, pending).await;
    let pending = request(&v2, h.id, SessionConfig::default());
    let (s2, _e2) = accept_next(&host, &mut host_events, pending).await;
    host.hangup(v1.id).await.unwrap();
    viewer_event(&mut e1, Duration::from_secs(5), |e| {
        matches!(
            e,
            ViewerEvent::Ended {
                reason: EndReason::Hangup
            }
        )
    })
    .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while s2.media_key_index() != Some(1) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("remaining viewer got the rotated key");
}

#[sqlx::test(migrations = "../server/migrations")]
async fn sfu_path_payload_is_encrypted(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let feed = feed_frames(&host);
    let pending = request(&v, h.id, SessionConfig::default());
    let (_viewer, mut events) = accept_next(&host, &mut host_events, pending).await;

    let (spy, mut spy_events) = eavesdrop(&format!("host-{}", h.id), &h.id.to_string()).await;
    let spy_frames = tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        let track = loop {
            match tokio::time::timeout_at(deadline, spy_events.recv()).await {
                Ok(Some(RoomEvent::TrackSubscribed {
                    track: RemoteTrack::Video(t),
                    ..
                })) => break Some(t),
                Ok(Some(_)) => continue,
                _ => break None,
            }
        };
        let (mut decoded, mut stamped) = (0, 0);
        if let Some(track) = track {
            let mut stream = NativeVideoStream::new(track.rtc_track());
            while let Ok(Some(frame)) = tokio::time::timeout_at(deadline, stream.next()).await {
                decoded += 1;
                let i420 = frame.buffer.to_i420();
                let (y, _, _) = i420.data();
                let w = i420.width() as usize;
                let probe = surf_rac_session::Frame {
                    width: i420.width(),
                    height: i420.height(),
                    timestamp_us: 0,
                    format: surf_rac_session::PixelFormat::I420,
                    data: (0..i420.height() as usize)
                        .flat_map(|r| y[r * w..r * w + w].to_vec())
                        .chain(std::iter::repeat_n(
                            128,
                            2 * (w.div_ceil(2)) * (i420.height() as usize).div_ceil(2),
                        ))
                        .collect(),
                };
                if common::stamp::read_stamp(&probe).is_some() {
                    stamped += 1;
                }
            }
        }
        (decoded, stamped)
    });
    let legit = collect_stamps(&mut events, Duration::from_secs(8)).await;
    let (decoded, stamped) = spy_frames.await.unwrap();
    feed.abort();
    spy.close().await.unwrap();
    println!(
        "legitimate viewer: {} stamped; eavesdropper: {decoded} decoded, {stamped} stamped",
        legit.len()
    );
    assert!(legit.len() >= 10);
    assert_eq!(stamped, 0, "eavesdropper read the screen");
}

#[sqlx::test(migrations = "../server/migrations")]
async fn forged_data_from_eavesdropper_is_ignored(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let (viewer, mut events) = accept_next(&host, &mut host_events, pending).await;

    let (spy, _spy_events) = eavesdrop(&format!("host-{}", h.id), &h.id.to_string()).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    for target in [h.id.to_string(), v.id.to_string()] {
        for i in 0..20u8 {
            spy.local_participant()
                .publish_data(DataPacket {
                    payload: vec![i; 64],
                    topic: Some(TOPIC_INPUT.into()),
                    reliable: true,
                    destination_identities: vec![target.clone().into()],
                })
                .await
                .unwrap();
        }
        spy.local_participant()
            .send_bytes(
                vec![1u8; 4096],
                StreamByteOptions {
                    destination_identities: vec![target.clone().into()],
                    ..StreamByteOptions::new_with_topic(TOPIC_CLIPBOARD)
                },
            )
            .await
            .unwrap();
    }
    let host_got = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(HostEvent::DataReceived { .. }) = host_events.recv().await {
                return;
            }
        }
    })
    .await;
    assert!(host_got.is_err(), "host accepted forged data");

    let key = DataMessage::Key {
        code: 30,
        down: true,
    };
    viewer.send(&key).await.unwrap();
    let got = host_event(&mut host_events, Duration::from_secs(5), |e| {
        matches!(e, HostEvent::DataReceived { .. })
    })
    .await;
    assert!(
        matches!(got, HostEvent::DataReceived { viewer: id, message } if id == v.id && message == key)
    );
    let back = DataMessage::Key {
        code: 31,
        down: true,
    };
    host.send(v.id, &back).await.unwrap();
    viewer_event(
        &mut events,
        Duration::from_secs(5),
        |e| matches!(e, ViewerEvent::DataReceived(m) if *m == back),
    )
    .await;
    spy.close().await.unwrap();
}
