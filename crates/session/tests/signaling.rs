//! Signaling client against the in-process server.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{Registered, TestEnv};
use sqlx::PgPool;
use surf_rac_protocol::{ClientMessage, ServerMessage};
use surf_rac_session::crypto::{self, Ephemeral, Role};
use surf_rac_session::signaling::{SignalingClient, SignalingError, SignalingEvents};
use surf_rac_session::{IdentityKey, IdentityPublic};

/// Waits up to 5 s for the first message matching `pred`.
async fn next_matching(
    events: &mut SignalingEvents,
    pred: impl Fn(&ServerMessage) -> bool,
) -> ServerMessage {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = events.recv().await.expect("connection ended");
            if pred(&msg) {
                return msg;
            }
        }
    })
    .await
    .expect("timed out")
}

#[sqlx::test(migrations = "../server/migrations")]
async fn connect_and_ping(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let a = env.device("alice", 1).await;
    let mut events = a.signaling.subscribe();
    a.signaling.send(ClientMessage::Ping).await.unwrap();
    next_matching(&mut events, |m| *m == ServerMessage::Pong).await;
}

#[sqlx::test(migrations = "../server/migrations")]
async fn wrong_identity_key_is_bad_signature(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let device = env.register("alice", 1).await;
    let impostor = Registered {
        identity: Arc::new(IdentityKey::generate()),
        ..device
    };
    assert_eq!(
        env.connect(&impostor).await.err(),
        Some(SignalingError::BadSignature)
    );
}

#[sqlx::test(migrations = "../server/migrations")]
async fn other_fingerprint_is_clone_detected(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let device = env.register("alice", 1).await;
    let clone = Registered {
        fingerprint: format!("{:064x}", 99),
        ..device
    };
    assert_eq!(
        env.connect(&clone).await.err(),
        Some(SignalingError::CloneDetected)
    );
}

#[sqlx::test(migrations = "../server/migrations")]
async fn unregistered_device_is_unknown(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let device = env.register("alice", 1).await;
    let unknown = Registered {
        id: if device.id.get() == 123_456_789 {
            "223456789".parse().unwrap()
        } else {
            "123456789".parse().unwrap()
        },
        ..device
    };
    assert_eq!(
        env.connect(&unknown).await.err(),
        Some(SignalingError::UnknownDevice)
    );
}

#[sqlx::test(migrations = "../server/migrations")]
async fn disabled_device_is_refused(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let device = env.register("alice", 1).await;
    sqlx::query("update devices set disabled = true")
        .execute(&env.pool)
        .await
        .unwrap();
    assert_eq!(
        env.connect(&device).await.err(),
        Some(SignalingError::DeviceDisabled)
    );
}

#[sqlx::test(migrations = "../server/migrations")]
async fn device_disabled_while_connected_reports_why(pool: PgPool) {
    let env = TestEnv::start_with(pool, &common::env("LIVEKIT_URL"), |state| {
        state.ws_revalidate_interval = Duration::from_millis(200);
    })
    .await;
    let a = env.device("alice", 1).await;
    let mut events = a.signaling.subscribe();
    sqlx::query("update devices set disabled = true")
        .execute(&env.pool)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while events.recv().await.is_some() {}
    })
    .await
    .expect("connection did not end");
    assert_eq!(
        a.signaling.end_reason(),
        Some(SignalingError::DeviceDisabled)
    );
    assert_eq!(
        a.signaling.send(ClientMessage::Ping).await.err(),
        Some(SignalingError::DeviceDisabled)
    );
}

#[sqlx::test(migrations = "../server/migrations")]
async fn relays_signed_session_request(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let a = env.device("alice", 1).await;
    let b = env.device("bob", 2).await;
    let mut events = b.signaling.subscribe();
    let ephemeral = Ephemeral::generate();
    let signature = a
        .identity
        .sign_session(Role::Viewer, "s1", &ephemeral.public());
    a.signaling
        .send(ClientMessage::SessionRequest {
            to: b.id,
            session_id: "s1".into(),
            session_key: ephemeral.public().to_base64(),
            signature: crypto::signature_to_base64(&signature),
            unattended: false,
        })
        .await
        .unwrap();
    let msg = next_matching(&mut events, |m| {
        matches!(m, ServerMessage::SessionRequest { .. })
    })
    .await;
    let ServerMessage::SessionRequest {
        from,
        session_id,
        identity_key,
        name,
        ..
    } = msg
    else {
        unreachable!()
    };
    assert_eq!(from, a.id);
    assert_eq!(session_id, "s1");
    assert_eq!(name, "alice");
    assert_eq!(
        IdentityPublic::from_base64(&identity_key).unwrap(),
        a.identity.public()
    );
}

#[sqlx::test(migrations = "../server/migrations")]
async fn replaced_connection_ends_subscribers(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let a = env.device("alice", 1).await;
    let mut events = a.signaling.subscribe();
    let _second: SignalingClient = env.connect(&a.registered()).await.unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        while events.recv().await.is_some() {}
    })
    .await;
    assert!(ended.is_ok(), "subscriber did not see the end");
    let err = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Err(e) = a.signaling.send(ClientMessage::Ping).await {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(err, SignalingError::Closed);
}

/// Serves one connection with a bare HTTP `status` response that has no error body.
async fn bare_status_server(status: &'static str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;
        let response =
            format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        let _ = stream.write_all(response.as_bytes()).await;
    });
    format!("ws://{addr}")
}

#[tokio::test]
async fn bare_404_and_403_without_error_body_are_plain_rejections() {
    let identity = IdentityKey::generate();
    let id = "123456789".parse().unwrap();
    let fingerprint = "ab".repeat(32);
    for (status, code) in [("404 Not Found", 404), ("403 Forbidden", 403)] {
        let url = bare_status_server(status).await;
        let result = SignalingClient::connect(&url, id, &identity, &fingerprint).await;
        assert_eq!(
            result.err(),
            Some(SignalingError::Rejected(code)),
            "{status}"
        );
    }
}
