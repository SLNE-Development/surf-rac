//! Session request failure paths.

mod common;

use std::time::{Duration, Instant};

use base64::Engine;
use common::{TestEnv, accept_next, collect_stamps, feed_frames, host_event, request, start_host};
use sqlx::PgPool;
use surf_rac_protocol::{ClientMessage, ServerMessage};
use surf_rac_session::crypto::{self, Ephemeral, Role};
use surf_rac_session::host::{HostEvent, HostSession, StartError};
use surf_rac_session::viewer::RequestError;
use surf_rac_session::{IdentityKey, MAX_VIEWERS, SessionConfig};

#[sqlx::test(migrations = "../server/migrations")]
async fn offline_host(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let host_id = env.register("host", 1).await.id;
    let v = env.device("viewer", 2).await;
    let result = request(&v, host_id, SessionConfig::default())
        .await
        .unwrap();
    assert_eq!(result.err(), Some(RequestError::Offline));
}

/// Checks that a request to an offline host fails on its own while another
/// request of the same viewer stays pending and is then accepted.
#[sqlx::test(migrations = "../server/migrations")]
async fn offline_error_fails_only_its_own_request(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let offline_id = env.register("offline", 3).await.id;
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
    let offline = request(&v, offline_id, SessionConfig::default())
        .await
        .unwrap();
    assert_eq!(offline.err(), Some(RequestError::Offline));
    assert!(!pending.is_finished(), "the other request was failed too");
    host.accept(&session_id).await.unwrap();
    assert!(pending.await.unwrap().is_ok());
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
        .trust_key(h.id, IdentityKey::generate().public());
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
            assert_eq!(k.new_fingerprint, h.identity.public().fingerprint());
        }
        other => panic!("expected KeyChanged, got {other:?}"),
    }

    v.known.lock().unwrap().trust_key(h.id, h.identity.public());
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
        .trust_key(v.id, IdentityKey::generate().public());
    let (_host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let ev = host_event(&mut host_events, Duration::from_secs(10), |e| {
        matches!(e, HostEvent::KeyChanged(_))
    })
    .await;
    assert!(matches!(ev, HostEvent::KeyChanged(k) if k.device_id == v.id));
    assert_eq!(
        pending.await.unwrap().err(),
        Some(RequestError::KeyNotRecognised)
    );
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
        h.identity.clone(),
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
    let ephemeral = Ephemeral::generate();
    let signature = h
        .identity
        .sign_session(Role::Host, &session_id, &ephemeral.public());
    h.signaling
        .send(ClientMessage::SessionResponse {
            to: v.id,
            session_id: session_id.clone(),
            accepted: true,
            reason: None,
            session_key: Some(ephemeral.public().to_base64()),
            signature: Some(crypto::signature_to_base64(&signature)),
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
    let ephemeral = Ephemeral::generate();
    for i in 0..150 {
        let session_id = format!("flood-{i}");
        let signature =
            attacker
                .identity
                .sign_session(Role::Viewer, &session_id, &ephemeral.public());
        attacker
            .signaling
            .send(ClientMessage::SessionRequest {
                to: h.id,
                session_id,
                session_key: ephemeral.public().to_base64(),
                signature: crypto::signature_to_base64(&signature),
                unattended: false,
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

#[sqlx::test(migrations = "../server/migrations")]
async fn unread_host_events_do_not_stall_requests(pool: PgPool) {
    use surf_rac_protocol::data::DataMessage;

    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let pending = request(&v, h.id, SessionConfig::default());
    let (viewer, _events) = accept_next(&host, &mut host_events, pending).await;
    for i in 0..1500u32 {
        viewer
            .send(&DataMessage::Key {
                code: i,
                down: true,
            })
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    let other = env.device("other", 3).await;
    h.known
        .lock()
        .unwrap()
        .trust_key(other.id, IdentityKey::generate().public());
    let config = SessionConfig {
        request_timeout: Duration::from_secs(5),
        ..SessionConfig::default()
    };
    let result = request(&other, h.id, config).await.unwrap();
    assert_eq!(
        result.err(),
        Some(RequestError::KeyNotRecognised),
        "host refused the changed key without the app reading events"
    );
}

/// Sends a session request from `from` to `to` whose signature covers `signed_key`
/// but which carries `sent_key` as its per-session key.
async fn send_request(
    from: &common::TestDevice,
    to: surf_rac_protocol::DeviceId,
    session_id: &str,
    signed_key: &Ephemeral,
    sent_key: &Ephemeral,
) {
    let signature = from
        .identity
        .sign_session(Role::Viewer, session_id, &signed_key.public());
    from.signaling
        .send(ClientMessage::SessionRequest {
            to,
            session_id: session_id.into(),
            session_key: sent_key.public().to_base64(),
            signature: crypto::signature_to_base64(&signature),
            unattended: false,
        })
        .await
        .unwrap();
}

#[sqlx::test(migrations = "../server/migrations")]
async fn tampered_session_key_is_dropped(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, attacker, v) = (
        env.device("host", 1).await,
        env.device("attacker", 2).await,
        env.device("viewer", 3).await,
    );
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let mut attacker_events = attacker.signaling.subscribe();
    let (signed, swapped) = (Ephemeral::generate(), Ephemeral::generate());
    send_request(&attacker, h.id, "tampered", &signed, &swapped).await;
    let other_session = Ephemeral::generate();
    let signature =
        attacker
            .identity
            .sign_session(Role::Viewer, "signed-for-other", &other_session.public());
    attacker
        .signaling
        .send(ClientMessage::SessionRequest {
            to: h.id,
            session_id: "replayed".into(),
            session_key: other_session.public().to_base64(),
            signature: crypto::signature_to_base64(&signature),
            unattended: false,
        })
        .await
        .unwrap();
    let silence = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match attacker_events.recv().await {
                Some(ServerMessage::SessionResponse { session_id, .. }) => return session_id,
                Some(_) => {}
                None => std::future::pending::<()>().await,
            }
        }
    })
    .await;
    assert!(
        silence.is_err(),
        "host answered a tampered request: {silence:?}"
    );
    while let Ok(ev) = host_events.try_recv() {
        assert!(
            !matches!(
                ev,
                HostEvent::ViewerRequested { .. } | HostEvent::KeyChanged(_)
            ),
            "tampered request surfaced as {ev:?}"
        );
    }
    assert!(
        h.known.lock().unwrap().get(attacker.id).is_none(),
        "a tampered request pins nothing"
    );
    let pending = request(&v, h.id, SessionConfig::default());
    accept_next(&host, &mut host_events, pending).await;
}

/// Waits up to `wait` for the first signaling message on `events` that `pick` maps to a value.
async fn next_signal<T>(
    events: &mut surf_rac_session::signaling::SignalingEvents,
    wait: Duration,
    pick: impl Fn(ServerMessage) -> Option<T>,
) -> T {
    tokio::time::timeout(wait, async {
        loop {
            let msg = events.recv().await.expect("signaling ended");
            if let Some(value) = pick(msg) {
                return value;
            }
        }
    })
    .await
    .expect("timed out waiting for a signaling message")
}

#[sqlx::test(migrations = "../server/migrations")]
async fn response_with_other_key_than_challenge_is_rejected(pool: PgPool) {
    use base64::engine::general_purpose::STANDARD;
    use surf_rac_session::viewer::RequestOptions;

    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let mut host_sig = h.signaling.subscribe();
    let options = RequestOptions {
        password: Some("hunter22".into()),
    };
    let pending = common::request_with(&v, h.id, options, SessionConfig::default());
    let session_id = next_signal(&mut host_sig, Duration::from_secs(5), |m| match m {
        ServerMessage::SessionRequest { session_id, .. } => Some(session_id),
        _ => None,
    })
    .await;
    let nonce = STANDARD.encode([3u8; 32]);
    let signed = |key: &Ephemeral| {
        crypto::signature_to_base64(&h.identity.sign_session(
            Role::Host,
            &session_id,
            &key.public(),
        ))
    };
    let (challenged, answered) = (Ephemeral::generate(), Ephemeral::generate());
    h.signaling
        .send(ClientMessage::PasswordChallenge {
            to: v.id,
            session_id: session_id.clone(),
            session_key: challenged.public().to_base64(),
            signature: signed(&challenged),
            host_nonce: nonce.clone(),
        })
        .await
        .unwrap();
    next_signal(&mut host_sig, Duration::from_secs(5), |m| match m {
        ServerMessage::SessionPassword { .. } => Some(()),
        _ => None,
    })
    .await;
    h.signaling
        .send(ClientMessage::SessionResponse {
            to: v.id,
            session_id: session_id.clone(),
            accepted: true,
            reason: None,
            session_key: Some(answered.public().to_base64()),
            signature: Some(signed(&answered)),
            host_nonce: Some(nonce),
        })
        .await
        .unwrap();
    assert_eq!(
        pending.await.unwrap().err(),
        Some(RequestError::ChallengeMismatch)
    );
}

#[sqlx::test(migrations = "../server/migrations")]
async fn expired_challenge_is_denied_to_viewer(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let config = SessionConfig {
        challenge_timeout: Duration::from_secs(1),
        ..SessionConfig::default()
    };
    let (host, mut host_events) = start_host(&h, config).await;
    host.set_password_access(true);
    let mut viewer_sig = v.signaling.subscribe();
    let ephemeral = Ephemeral::generate();
    let signature = v
        .identity
        .sign_session(Role::Viewer, "silent", &ephemeral.public());
    v.signaling
        .send(ClientMessage::SessionRequest {
            to: h.id,
            session_id: "silent".into(),
            session_key: ephemeral.public().to_base64(),
            signature: crypto::signature_to_base64(&signature),
            unattended: true,
        })
        .await
        .unwrap();
    next_signal(&mut viewer_sig, Duration::from_secs(5), |m| match m {
        ServerMessage::PasswordChallenge { session_id, .. } if session_id == "silent" => Some(()),
        _ => None,
    })
    .await;
    let started = Instant::now();
    let accepted = next_signal(&mut viewer_sig, Duration::from_secs(4), |m| match m {
        ServerMessage::SessionResponse {
            session_id,
            accepted,
            ..
        } if session_id == "silent" => Some(accepted),
        _ => None,
    })
    .await;
    assert!(!accepted, "an expired challenge is refused");
    assert!(started.elapsed() < Duration::from_secs(4));
    let ev = host_event(&mut host_events, Duration::from_secs(2), |e| {
        matches!(e, HostEvent::RequestExpired { .. })
    })
    .await;
    assert!(matches!(ev, HostEvent::RequestExpired { session_id, .. } if session_id == "silent"));
}

#[sqlx::test(migrations = "../server/migrations")]
async fn request_awaiting_password_cannot_be_accepted(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, _host_events) = start_host(&h, SessionConfig::default()).await;
    host.set_password_access(true);
    let mut viewer_sig = v.signaling.subscribe();
    let ephemeral = Ephemeral::generate();
    let signature = v
        .identity
        .sign_session(Role::Viewer, "waiting", &ephemeral.public());
    v.signaling
        .send(ClientMessage::SessionRequest {
            to: h.id,
            session_id: "waiting".into(),
            session_key: ephemeral.public().to_base64(),
            signature: crypto::signature_to_base64(&signature),
            unattended: true,
        })
        .await
        .unwrap();
    next_signal(&mut viewer_sig, Duration::from_secs(5), |m| match m {
        ServerMessage::PasswordChallenge { .. } => Some(()),
        _ => None,
    })
    .await;
    assert!(
        host.accept("waiting").await.is_err(),
        "a request without its password cannot be accepted"
    );
    host.deny("waiting").await.unwrap();
}

#[sqlx::test(migrations = "../server/migrations")]
async fn eleventh_request_to_one_host_fails_fast_as_rate_limited(pool: PgPool) {
    let env = TestEnv::start_with(pool, &common::env("LIVEKIT_URL"), |state| {
        let mut config = common::test_config(&common::env("LIVEKIT_URL"));
        config.session_requests_per_minute = 10;
        state.limits = std::sync::Arc::new(surf_rac_server::limits::Limits::from_config(&config));
    })
    .await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let ephemeral = Ephemeral::generate();
    for i in 0..10 {
        send_request(&v, h.id, &format!("fill-{i}"), &ephemeral, &ephemeral).await;
    }
    let started = Instant::now();
    let result = request(&v, h.id, SessionConfig::default()).await.unwrap();
    assert_eq!(result.err(), Some(RequestError::RateLimited));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "took {:?}",
        started.elapsed()
    );
}
