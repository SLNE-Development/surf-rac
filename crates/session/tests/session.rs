//! Host and viewer sessions through the signaling server and LiveKit.

mod common;

use std::time::Duration;

use common::{
    TestEnv, accept_next, collect_stamps, feed_frames, host_event, request, request_with,
    start_host, viewer_event,
};
use sqlx::PgPool;
use surf_rac_protocol::data::{ClipboardKind, DataMessage};
use surf_rac_session::host::HostEvent;
use surf_rac_session::viewer::{RequestError, RequestOptions, ViewerEvent};
use surf_rac_session::{EndReason, FrameError, SessionConfig, VideoInput};

/// Returns request options that authenticate with `password`.
fn with_password(password: &str) -> RequestOptions {
    RequestOptions {
        password: Some(password.into()),
    }
}

/// An attended request with password access on reaches the host as a prompt naming the viewer, its
/// key and fingerprint, and connects once accepted.
#[sqlx::test(migrations = "../server/migrations")]
async fn attended_request_reaches_host_as_prompt(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    host.set_password_access(true);
    let pending = request(&v, h.id, SessionConfig::default());
    let ev = host_event(&mut host_events, Duration::from_secs(10), |e| {
        matches!(
            e,
            HostEvent::ViewerRequested { .. } | HostEvent::PasswordReceived { .. }
        )
    })
    .await;
    let HostEvent::ViewerRequested {
        session_id,
        viewer,
        name,
        viewer_key,
        fingerprint,
        unattended,
    } = ev
    else {
        panic!("attended request produced {ev:?}")
    };
    assert_eq!(viewer, v.id);
    assert_eq!(name, "viewer");
    assert_eq!(viewer_key, v.identity.public());
    assert_eq!(fingerprint, v.identity.public().fingerprint());
    assert!(!unattended);
    host.accept(&session_id).await.unwrap();
    let (_viewer, mut events) = pending.await.unwrap().expect("viewer request");
    viewer_event(&mut events, Duration::from_secs(30), |e| {
        matches!(e, ViewerEvent::Connected)
    })
    .await;
}

/// An unattended request with a password reaches the host as `PasswordReceived` with the opened
/// password hidden from debug output, and the viewer pins the host key after accepting.
#[sqlx::test(migrations = "../server/migrations")]
async fn unattended_password_is_accepted(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    host.set_password_access(true);
    let pending = request_with(
        &v,
        h.id,
        with_password("hunter22"),
        SessionConfig::default(),
    );
    let ev = host_event(&mut host_events, Duration::from_secs(10), |e| {
        matches!(
            e,
            HostEvent::ViewerRequested { .. } | HostEvent::PasswordReceived { .. }
        )
    })
    .await;
    let HostEvent::PasswordReceived {
        session_id,
        viewer,
        viewer_key,
        password,
        ..
    } = ev
    else {
        panic!("unattended request produced {ev:?}")
    };
    assert_eq!(viewer, v.id);
    assert_eq!(viewer_key, v.identity.public());
    assert_eq!(
        password.as_ref().map(|p| p.as_str()),
        Some("hunter22"),
        "host opens the sealed password"
    );
    assert!(
        !format!("{password:?}").contains("hunter22"),
        "debug output hides the password"
    );
    host.accept(&session_id).await.unwrap();
    let (_viewer, mut events) = pending.await.unwrap().expect("viewer request");
    viewer_event(&mut events, Duration::from_secs(30), |e| {
        matches!(e, ViewerEvent::Connected)
    })
    .await;
    assert_eq!(
        v.known.lock().unwrap().get(h.id),
        Some(&h.identity.public()),
        "viewer pinned the host key from the challenge"
    );
}

/// A rejected password turns the unattended request into a prompt for the same session, which can
/// then be accepted but not rejected again.
#[sqlx::test(migrations = "../server/migrations")]
async fn wrong_password_falls_back_to_prompt(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    host.set_password_access(true);
    let pending = request_with(&v, h.id, with_password("wrong"), SessionConfig::default());
    let HostEvent::PasswordReceived {
        session_id,
        password,
        ..
    } = host_event(&mut host_events, Duration::from_secs(10), |e| {
        matches!(e, HostEvent::PasswordReceived { .. })
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(password.as_ref().map(|p| p.as_str()), Some("wrong"));
    host.reject_password(&session_id).await.unwrap();
    let ev = host_event(&mut host_events, Duration::from_secs(5), |e| {
        matches!(e, HostEvent::ViewerRequested { .. })
    })
    .await;
    let HostEvent::ViewerRequested {
        session_id: prompted,
        viewer,
        unattended,
        ..
    } = ev
    else {
        unreachable!()
    };
    assert_eq!(prompted, session_id);
    assert_eq!(viewer, v.id);
    assert!(unattended);
    assert!(
        host.reject_password(&session_id).await.is_err(),
        "a prompt has no password to reject"
    );
    host.accept(&session_id).await.unwrap();
    let (_viewer, mut events) = pending.await.unwrap().expect("viewer request");
    viewer_event(&mut events, Duration::from_secs(30), |e| {
        matches!(e, ViewerEvent::Connected)
    })
    .await;
}

/// An unattended request to a host without password access arrives as a prompt marked unattended
/// rather than as a password.
#[sqlx::test(migrations = "../server/migrations")]
async fn unattended_request_prompts_without_password_access(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request_with(
        &v,
        h.id,
        with_password("hunter22"),
        SessionConfig::default(),
    );
    let ev = host_event(&mut host_events, Duration::from_secs(10), |e| {
        matches!(
            e,
            HostEvent::ViewerRequested { .. } | HostEvent::PasswordReceived { .. }
        )
    })
    .await;
    let HostEvent::ViewerRequested {
        session_id,
        unattended,
        ..
    } = ev
    else {
        panic!("request without password access produced {ev:?}")
    };
    assert!(unattended);
    host.deny(&session_id).await.unwrap();
    assert_eq!(pending.await.unwrap().err(), Some(RequestError::Denied));
}

/// An accepted viewer joins the host's room and receives at least ten stamped video frames.
#[sqlx::test(migrations = "../server/migrations")]
async fn viewer_receives_video(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let feed = feed_frames(&host);
    let pending = request(&v, h.id, SessionConfig::default());
    let (_viewer, mut events) = accept_next(&host, &mut host_events, pending).await;
    host_event(
        &mut host_events,
        Duration::from_secs(5),
        |e| matches!(e, HostEvent::ViewerJoined { viewer } if *viewer == v.id),
    )
    .await;
    let stamps = collect_stamps(&mut events, Duration::from_secs(15)).await;
    feed.abort();
    assert!(stamps.len() >= 10, "only {} stamped frames", stamps.len());
}

/// Pointer, key and clipboard messages reach the host from the viewer, and a 1 MiB clipboard image
/// and a key reach the viewer from the host.
#[sqlx::test(migrations = "../server/migrations")]
async fn data_flows_both_ways_on_all_topics(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let (viewer, mut events) = accept_next(&host, &mut host_events, pending).await;

    for i in 0..50 {
        viewer
            .send(&DataMessage::PointerMove {
                x: i,
                y: i,
                monitor: 0,
            })
            .await
            .unwrap();
    }
    host_event(&mut host_events, Duration::from_secs(5), |e| {
        matches!(
            e,
            HostEvent::DataReceived {
                message: DataMessage::PointerMove { .. },
                ..
            }
        )
    })
    .await;

    let key = DataMessage::Key {
        code: 30,
        down: true,
    };
    viewer.send(&key).await.unwrap();
    let got = host_event(&mut host_events, Duration::from_secs(5), |e| {
        matches!(
            e,
            HostEvent::DataReceived {
                message: DataMessage::Key { .. },
                ..
            }
        )
    })
    .await;
    assert!(
        matches!(got, HostEvent::DataReceived { viewer: id, message } if id == v.id && message == key)
    );

    let text = DataMessage::Clipboard {
        kind: ClipboardKind::Text,
        bytes: vec![b'a'; 100 * 1024],
    };
    viewer.send(&text).await.unwrap();
    let got = host_event(&mut host_events, Duration::from_secs(10), |e| {
        matches!(
            e,
            HostEvent::DataReceived {
                message: DataMessage::Clipboard { .. },
                ..
            }
        )
    })
    .await;
    assert!(matches!(got, HostEvent::DataReceived { message, .. } if message == text));

    let image = DataMessage::Clipboard {
        kind: ClipboardKind::Image,
        bytes: (0..1_048_576u32).map(|i| i as u8).collect(),
    };
    host.send(v.id, &image).await.unwrap();
    let back_key = DataMessage::Key {
        code: 31,
        down: false,
    };
    host.send(v.id, &back_key).await.unwrap();
    let mut got_image = false;
    let mut got_key = false;
    tokio::time::timeout(Duration::from_secs(10), async {
        while !(got_image && got_key) {
            match events.recv().await.expect("viewer events ended") {
                ViewerEvent::DataReceived(m) if m == image => got_image = true,
                ViewerEvent::DataReceived(m) if m == back_key => got_key = true,
                _ => {}
            }
        }
    })
    .await
    .expect("viewer did not get host data");
}

/// A host hangup ends the viewer with `EndReason::Hangup` and reports the viewer as left on the
/// host.
#[sqlx::test(migrations = "../server/migrations")]
async fn hangup_ends_viewer(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let (_viewer, mut events) = accept_next(&host, &mut host_events, pending).await;
    host.hangup(v.id).await.unwrap();
    viewer_event(&mut events, Duration::from_secs(5), |e| {
        matches!(
            e,
            ViewerEvent::Ended {
                reason: EndReason::Hangup
            }
        )
    })
    .await;
    host_event(
        &mut host_events,
        Duration::from_secs(5),
        |e| matches!(e, HostEvent::ViewerLeft { viewer } if *viewer == v.id),
    )
    .await;
}

/// A viewer hangup is reported to the host as `ViewerLeft` for that viewer.
#[sqlx::test(migrations = "../server/migrations")]
async fn viewer_hangup_reaches_host(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let (viewer, _events) = accept_next(&host, &mut host_events, pending).await;
    viewer.hangup().await;
    host_event(
        &mut host_events,
        Duration::from_secs(10),
        |e| matches!(e, HostEvent::ViewerLeft { viewer } if *viewer == v.id),
    )
    .await;
}

/// A viewer that does not read its events for three seconds while frames arrive still receives a
/// data message from the host.
#[sqlx::test(migrations = "../server/migrations")]
async fn slow_consumer_still_gets_data(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let feed = feed_frames(&host);
    let pending = request(&v, h.id, SessionConfig::default());
    let (_viewer, mut events) = accept_next(&host, &mut host_events, pending).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let key = DataMessage::Key {
        code: 44,
        down: true,
    };
    host.send(v.id, &key).await.unwrap();
    viewer_event(
        &mut events,
        Duration::from_secs(5),
        |e| matches!(e, ViewerEvent::DataReceived(m) if *m == key),
    )
    .await;
    feed.abort();
}

/// A session with forced TURN relay on both sides delivers at least ten stamped frames.
#[sqlx::test(migrations = "../server/migrations")]
async fn forced_relay_session(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let relay = SessionConfig {
        force_relay: true,
        ..SessionConfig::default()
    };
    let (host, mut host_events) = start_host(&h, relay.clone()).await;
    let feed = feed_frames(&host);
    let pending = request(&v, h.id, relay);
    let (_viewer, mut events) = accept_next(&host, &mut host_events, pending).await;
    let stamps = collect_stamps(&mut events, Duration::from_secs(15)).await;
    feed.abort();
    assert!(
        stamps.len() >= 10,
        "only {} stamped frames over relay",
        stamps.len()
    );
}

/// Over at least 100 frames after a warm-up, the median one-way frame delay stays below 200 ms.
#[sqlx::test(migrations = "../server/migrations")]
async fn median_frame_delay_under_200ms(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let feed = feed_frames(&host);
    let pending = request(&v, h.id, SessionConfig::default());
    let (_viewer, mut events) = accept_next(&host, &mut host_events, pending).await;
    let _warmup = collect_stamps(&mut events, Duration::from_secs(2)).await;
    let mut delays: Vec<i64> = collect_stamps(&mut events, Duration::from_secs(10))
        .await
        .into_iter()
        .map(|(sent, got)| got - sent)
        .collect();
    feed.abort();
    println!("received {} stamped frames", delays.len());
    assert!(delays.len() >= 100, "only {} frames", delays.len());
    delays.sort_unstable();
    let median = delays[delays.len() / 2];
    println!(
        "median one-way frame delay: {} ms over {} frames",
        median / 1000,
        delays.len()
    );
    assert!(median < 200_000, "median delay {median} us");
}

/// A key sent while a maximum-size clipboard upload is in progress returns before the upload
/// finishes and reaches the host.
#[sqlx::test(migrations = "../server/migrations")]
async fn clipboard_upload_does_not_delay_input(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let (viewer, _events) = accept_next(&host, &mut host_events, pending).await;
    let big = DataMessage::Clipboard {
        kind: ClipboardKind::Image,
        bytes: vec![7; surf_rac_protocol::data::MAX_CLIPBOARD_BYTES],
    };
    let uploader = viewer.clone();
    let upload = tokio::spawn(async move { uploader.send(&big).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let key = DataMessage::Key {
        code: 30,
        down: true,
    };
    viewer.send(&key).await.unwrap();
    assert!(
        !upload.is_finished(),
        "input send waited for the whole clipboard upload"
    );
    host_event(
        &mut host_events,
        Duration::from_secs(30),
        |e| matches!(e, HostEvent::DataReceived { message, .. } if *message == key),
    )
    .await;
    upload.await.unwrap().unwrap();
}

/// The viewer receives frames at the old size and at least ten stamped frames at the new size after
/// the host's frame size changes.
#[sqlx::test(migrations = "../server/migrations")]
async fn viewer_keeps_receiving_across_size_change(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let (_viewer, mut events) = accept_next(&host, &mut host_events, pending).await;
    let feed = common::feed_frames_resizing(&host, (640, 480), Duration::from_secs(3), (800, 600));
    let frames = common::collect_sized(&mut events, Duration::from_secs(12)).await;
    feed.abort();
    assert!(
        frames.iter().any(|(w, h, _)| (*w, *h) == (640, 480)),
        "no 640x480 frames before the switch"
    );
    let after = frames
        .iter()
        .filter(|(w, h, s)| (*w, *h) == (800, 600) && s.is_some())
        .count();
    assert!(
        after >= 10,
        "only {after} stamped 800x600 frames after the switch"
    );
}

/// With encoded video input the host refuses raw frames with `FrameError::WrongInput`, and after
/// switching back to raw input the viewer receives stamped frames again.
#[sqlx::test(migrations = "../server/migrations")]
async fn encoded_input_rejects_raw_frames_and_switches_back(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let (_viewer, mut events) = accept_next(&host, &mut host_events, pending).await;
    assert_eq!(host.video_input(), VideoInput::Raw);

    host.set_video_input(VideoInput::Encoded, 640, 480)
        .await
        .unwrap();
    assert_eq!(host.video_input(), VideoInput::Encoded);
    assert_eq!(
        host.publish_frame(&common::stamp::stamp_frame(
            640,
            480,
            common::stamp::now_micros()
        )),
        Err(FrameError::WrongInput)
    );

    host.set_video_input(VideoInput::Raw, 640, 480)
        .await
        .unwrap();
    assert_eq!(host.video_input(), VideoInput::Raw);
    let feed = feed_frames(&host);
    let stamps = collect_stamps(&mut events, Duration::from_secs(15)).await;
    feed.abort();
    assert!(
        stamps.len() >= 10,
        "only {} stamped frames after switching back",
        stamps.len()
    );
}
