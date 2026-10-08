//! Host and viewer sessions through the signaling server and LiveKit.

mod common;

use std::time::Duration;

use common::{TestEnv, accept_next, collect_stamps, feed_frames, host_event, request, start_host, viewer_event};
use sqlx::PgPool;
use surf_rac_protocol::data::{ClipboardKind, DataMessage};
use surf_rac_session::host::HostEvent;
use surf_rac_session::viewer::ViewerEvent;
use surf_rac_session::{EndReason, SessionConfig};

#[sqlx::test(migrations = "../server/migrations")]
async fn viewer_receives_video(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let feed = feed_frames(&host);
    let pending = request(&v, h.id, SessionConfig::default());
    let (_viewer, mut events) = accept_next(&host, &mut host_events, pending).await;
    host_event(&mut host_events, Duration::from_secs(5), |e| {
        matches!(e, HostEvent::ViewerJoined { viewer } if *viewer == v.id)
    })
    .await;
    let stamps = collect_stamps(&mut events, Duration::from_secs(15)).await;
    feed.abort();
    assert!(stamps.len() >= 10, "only {} stamped frames", stamps.len());
}

#[sqlx::test(migrations = "../server/migrations")]
async fn data_flows_both_ways_on_all_topics(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let (viewer, mut events) = accept_next(&host, &mut host_events, pending).await;

    for i in 0..50 {
        viewer.send(&DataMessage::PointerMove { x: i, y: i, monitor: 0 }).await.unwrap();
    }
    host_event(&mut host_events, Duration::from_secs(5), |e| {
        matches!(e, HostEvent::DataReceived { message: DataMessage::PointerMove { .. }, .. })
    })
    .await;

    let key = DataMessage::Key { code: 30, down: true };
    viewer.send(&key).await.unwrap();
    let got = host_event(&mut host_events, Duration::from_secs(5), |e| {
        matches!(e, HostEvent::DataReceived { message: DataMessage::Key { .. }, .. })
    })
    .await;
    assert!(matches!(got, HostEvent::DataReceived { viewer: id, message } if id == v.id && message == key));

    let text = DataMessage::Clipboard { kind: ClipboardKind::Text, bytes: vec![b'a'; 100 * 1024] };
    viewer.send(&text).await.unwrap();
    let got = host_event(&mut host_events, Duration::from_secs(10), |e| {
        matches!(e, HostEvent::DataReceived { message: DataMessage::Clipboard { .. }, .. })
    })
    .await;
    assert!(matches!(got, HostEvent::DataReceived { message, .. } if message == text));

    let image = DataMessage::Clipboard { kind: ClipboardKind::Image, bytes: (0..1_048_576u32).map(|i| i as u8).collect() };
    host.send(v.id, &image).await.unwrap();
    let back_key = DataMessage::Key { code: 31, down: false };
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

#[sqlx::test(migrations = "../server/migrations")]
async fn hangup_ends_viewer(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let (_viewer, mut events) = accept_next(&host, &mut host_events, pending).await;
    host.hangup(v.id).await.unwrap();
    viewer_event(&mut events, Duration::from_secs(5), |e| {
        matches!(e, ViewerEvent::Ended { reason: EndReason::Hangup })
    })
    .await;
    host_event(&mut host_events, Duration::from_secs(5), |e| {
        matches!(e, HostEvent::ViewerLeft { viewer } if *viewer == v.id)
    })
    .await;
}

#[sqlx::test(migrations = "../server/migrations")]
async fn viewer_hangup_reaches_host(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let (viewer, _events) = accept_next(&host, &mut host_events, pending).await;
    viewer.hangup().await;
    host_event(&mut host_events, Duration::from_secs(10), |e| {
        matches!(e, HostEvent::ViewerLeft { viewer } if *viewer == v.id)
    })
    .await;
}

#[sqlx::test(migrations = "../server/migrations")]
async fn slow_consumer_still_gets_data(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let feed = feed_frames(&host);
    let pending = request(&v, h.id, SessionConfig::default());
    let (_viewer, mut events) = accept_next(&host, &mut host_events, pending).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let key = DataMessage::Key { code: 44, down: true };
    host.send(v.id, &key).await.unwrap();
    viewer_event(&mut events, Duration::from_secs(5), |e| {
        matches!(e, ViewerEvent::DataReceived(m) if *m == key)
    })
    .await;
    feed.abort();
}

#[sqlx::test(migrations = "../server/migrations")]
async fn forced_relay_session(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let relay = SessionConfig { force_relay: true, ..SessionConfig::default() };
    let (host, mut host_events) = start_host(&h, relay.clone()).await;
    let feed = feed_frames(&host);
    let pending = request(&v, h.id, relay);
    let (_viewer, mut events) = accept_next(&host, &mut host_events, pending).await;
    let stamps = collect_stamps(&mut events, Duration::from_secs(15)).await;
    feed.abort();
    assert!(stamps.len() >= 10, "only {} stamped frames over relay", stamps.len());
}

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
    println!("median one-way frame delay: {} ms over {} frames", median / 1000, delays.len());
    assert!(median < 200_000, "median delay {median} us");
}
