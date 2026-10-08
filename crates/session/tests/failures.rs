//! Session request failure paths.

mod common;

use std::time::{Duration, Instant};

use base64::Engine;
use common::{TestEnv, accept_next, collect_stamps, feed_frames, host_event, request, start_host};
use sqlx::PgPool;
use surf_rac_protocol::{ClientMessage, ServerMessage};
use surf_rac_session::host::{HostEvent, HostSession, StartError};
use surf_rac_session::viewer::RequestError;
use surf_rac_session::{DeviceKeys, MAX_VIEWERS, SessionConfig};

#[sqlx::test(migrations = "../server/migrations")]
async fn offline_host(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (_, host_id, _) = env.register("host", 1).await;
    let v = env.device("viewer", 2).await;
    let result = request(&v, host_id, SessionConfig::default())
        .await
        .unwrap();
    assert_eq!(result.err(), Some(RequestError::Offline));
}

#[sqlx::test(migrations = "../server/migrations")]
async fn denied(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let HostEvent::ViewerRequested { session_id, .. } =
        host_event(&mut host_events, Duration::from_secs(10), |e| {
            matches!(e, HostEvent::ViewerRequested { .. })
        })
        .await
    else {
        unreachable!()
    };
    host.deny(&session_id).await.unwrap();
    assert_eq!(pending.await.unwrap().err(), Some(RequestError::Denied));
    assert!(
        host.accept(&session_id).await.is_err(),
        "answered request stays answered"
    );
}

#[sqlx::test(migrations = "../server/migrations")]
async fn request_times_out(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (_host, _host_events) = start_host(&h, SessionConfig::default()).await;
    let config = SessionConfig {
        request_timeout: Duration::from_secs(2),
        ..SessionConfig::default()
    };
    let started = Instant::now();
    let result = request(&v, h.id, config).await.unwrap();
    assert_eq!(result.err(), Some(RequestError::Timeout));
    assert!(started.elapsed() >= Duration::from_secs(2));
}

#[sqlx::test(migrations = "../server/migrations")]
async fn changed_host_key_blocks_session(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    v.known
        .lock()
        .unwrap()
        .trust_key(h.id, DeviceKeys::generate().public_key());
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let HostEvent::ViewerRequested { session_id, .. } =
        host_event(&mut host_events, Duration::from_secs(10), |e| {
            matches!(e, HostEvent::ViewerRequested { .. })
        })
        .await
    else {
        unreachable!()
    };
    host.accept(&session_id).await.unwrap();
    match pending.await.unwrap().err() {
        Some(RequestError::KeyChanged(k)) => {
            assert_eq!(k.device_id, h.id);
            assert_eq!(k.new_fingerprint, h.keys.public_key().fingerprint());
        }
        other => panic!("expected KeyChanged, got {other:?}"),
    }

    v.known.lock().unwrap().trust_key(h.id, h.keys.public_key());
    let pending = request(&v, h.id, SessionConfig::default());
    accept_next(&host, &mut host_events, pending).await;
}

#[sqlx::test(migrations = "../server/migrations")]
async fn changed_viewer_key_blocks_on_host(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    h.known
        .lock()
        .unwrap()
        .trust_key(v.id, DeviceKeys::generate().public_key());
    let (_host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let ev = host_event(&mut host_events, Duration::from_secs(10), |e| {
        matches!(e, HostEvent::KeyChanged(_))
    })
    .await;
    assert!(matches!(ev, HostEvent::KeyChanged(k) if k.device_id == v.id));
    assert_eq!(pending.await.unwrap().err(), Some(RequestError::Denied));
}

#[sqlx::test(migrations = "../server/migrations")]
async fn sixth_viewer_gets_room_full(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let h = env.device("host", 1).await;
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let mut sessions = Vec::new();
    for n in 0..MAX_VIEWERS as u32 {
        let v = env.device(&format!("viewer{n}"), 10 + n).await;
        let pending = request(&v, h.id, SessionConfig::default());
        sessions.push((accept_next(&host, &mut host_events, pending).await, v));
    }
    let sixth = env.device("viewer6", 20).await;
    let pending = request(&sixth, h.id, SessionConfig::default());
    let HostEvent::ViewerRequested { session_id, .. } =
        host_event(&mut host_events, Duration::from_secs(10), |e| {
            matches!(e, HostEvent::ViewerRequested { .. })
        })
        .await
    else {
        unreachable!()
    };
    host.accept(&session_id).await.unwrap();
    assert_eq!(pending.await.unwrap().err(), Some(RequestError::RoomFull));
}

#[sqlx::test(migrations = "../server/migrations")]
async fn duplicate_request_is_denied(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let feed = feed_frames(&host);
    let pending = request(&v, h.id, SessionConfig::default());
    let (_viewer, mut events) = accept_next(&host, &mut host_events, pending).await;
    let second = request(&v, h.id, SessionConfig::default()).await.unwrap();
    assert_eq!(second.err(), Some(RequestError::Denied));
    let stamps = collect_stamps(&mut events, Duration::from_secs(5)).await;
    feed.abort();
    assert!(stamps.len() >= 10, "first viewer lost its stream");
}

#[sqlx::test(migrations = "../server/migrations")]
async fn token_for_other_room_cannot_reach_host_room(pool: PgPool) {
    use livekit::prelude::*;

    let env = TestEnv::start(pool).await;
    let (a, b, c) = (
        env.device("hosta", 1).await,
        env.device("hostb", 2).await,
        env.device("carol", 3).await,
    );
    let (_host, _host_events) = start_host(&a, SessionConfig::default()).await;
    let mut carol_events = c.signaling.subscribe();
    b.signaling
        .send(ClientMessage::ViewerTokenRequest {
            session_id: "s1".into(),
            viewer_device_id: c.id,
        })
        .await
        .unwrap();
    let (url, room, token) = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(ServerMessage::ViewerToken {
                url, room, token, ..
            }) = carol_events.recv().await
            {
                return (url, room, token);
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(room, format!("host-{}", b.id));
    let (lk_room, _events) = Room::connect(&url, &token, RoomOptions::default())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let identities: Vec<String> = lk_room
        .remote_participants()
        .keys()
        .map(|id| id.0.clone())
        .collect();
    assert!(!identities.contains(&a.id.to_string()), "{identities:?}");
    lk_room.close().await.unwrap();
}

#[sqlx::test(migrations = "../server/migrations")]
async fn livekit_unreachable(pool: PgPool) {
    let env = TestEnv::start_with_livekit(pool, "ws://127.0.0.1:1").await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let started = HostSession::start(
        h.signaling.clone(),
        h.keys.clone(),
        h.known.clone(),
        640,
        480,
        SessionConfig::default(),
    )
    .await;
    assert!(matches!(
        started.err(),
        Some(StartError::MediaUnavailable(_))
    ));

    // Act as the host by hand so the viewer receives a token for the unreachable server.
    let mut host_sig = h.signaling.subscribe();
    let pending = request(&v, h.id, SessionConfig::default());
    let session_id = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(ServerMessage::SessionRequest { session_id, .. }) = host_sig.recv().await {
                return session_id;
            }
        }
    })
    .await
    .unwrap();
    h.signaling
        .send(ClientMessage::SessionResponse {
            to: v.id,
            session_id: session_id.clone(),
            accepted: true,
            reason: None,
            host_public_key: Some(h.keys.public_key().to_base64()),
            host_nonce: Some(base64::engine::general_purpose::STANDARD.encode([3u8; 32])),
        })
        .await
        .unwrap();
    h.signaling
        .send(ClientMessage::ViewerTokenRequest {
            session_id,
            viewer_device_id: v.id,
        })
        .await
        .unwrap();
    assert!(matches!(
        pending.await.unwrap().err(),
        Some(RequestError::MediaUnavailable(_))
    ));

    let mut events = v.signaling.subscribe();
    v.signaling.send(ClientMessage::Ping).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while events.recv().await != Some(ServerMessage::Pong) {}
    })
    .await
    .expect("signaling still works");
}

#[sqlx::test(migrations = "../server/migrations")]
async fn request_flood_does_not_exhaust_host(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, attacker, v) = (
        env.device("host", 1).await,
        env.device("attacker", 2).await,
        env.device("viewer", 3).await,
    );
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let mut attacker_events = attacker.signaling.subscribe();
    let key = attacker.keys.public_key().to_base64();
    for i in 0..150 {
        attacker
            .signaling
            .send(ClientMessage::SessionRequest {
                to: h.id,
                session_id: format!("flood-{i}"),
                viewer_public_key: key.clone(),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut answers = 0;
    while let Ok(Some(msg)) =
        tokio::time::timeout(Duration::from_secs(2), attacker_events.recv()).await
    {
        if matches!(msg, ServerMessage::SessionResponse { .. }) {
            answers += 1;
        }
    }
    assert!(answers <= 5, "host answered {answers} flooded requests");
    while host_events.try_recv().is_ok() {}
    let pending = request(&v, h.id, SessionConfig::default());
    accept_next(&host, &mut host_events, pending).await;
}
