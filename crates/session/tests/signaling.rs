//! Signaling client against the in-process server.

mod common;

use std::time::Duration;

use common::TestEnv;
use sqlx::PgPool;
use surf_rac_protocol::{ClientMessage, ServerMessage};
use surf_rac_session::signaling::{SignalingClient, SignalingError, SignalingEvents};

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
async fn bad_secret_is_rejected(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (token, id, _) = env.register("alice", 1).await;
    let err = SignalingClient::connect(&env.ws, &token, id, "wrong")
        .await
        .err();
    assert_eq!(err, Some(SignalingError::Rejected(401)));
}

#[sqlx::test(migrations = "../server/migrations")]
async fn relays_session_request(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let a = env.device("alice", 1).await;
    let b = env.device("bob", 2).await;
    let mut events = b.signaling.subscribe();
    a.signaling
        .send(ClientMessage::SessionRequest {
            to: b.id,
            session_id: "s1".into(),
            viewer_public_key: a.keys.public_key().to_base64(),
            password: None,
        })
        .await
        .unwrap();
    let msg = next_matching(&mut events, |m| {
        matches!(m, ServerMessage::SessionRequest { .. })
    })
    .await;
    match msg {
        ServerMessage::SessionRequest {
            from, session_id, ..
        } => {
            assert_eq!(from, a.id);
            assert_eq!(session_id, "s1");
        }
        _ => unreachable!(),
    }
}

#[sqlx::test(migrations = "../server/migrations")]
async fn replaced_connection_ends_subscribers(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let a = env.device("alice", 1).await;
    let mut events = a.signaling.subscribe();
    let _second = SignalingClient::connect(&env.ws, &a.token, a.id, &a.secret)
        .await
        .unwrap();
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
