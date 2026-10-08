//! Session negotiation and LiveKit token issuance over the WebSocket.

mod common;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::TEST_LIVEKIT_SECRET;
use common::ws::{recv_type, send};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::PgPool;

/// Standard base64 of 32 zero bytes, a well-formed public key.
fn key_b64() -> String {
    STANDARD.encode([7u8; 32])
}

/// Verifies `token`'s signature under the test secret and returns its claims.
fn claims(token: &str) -> Value {
    let (signed, sig) = token.rsplit_once('.').unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(TEST_LIVEKIT_SECRET.as_bytes()).unwrap();
    mac.update(signed.as_bytes());
    mac.verify_slice(&URL_SAFE_NO_PAD.decode(sig).unwrap())
        .expect("token signature");
    let payload = signed.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn session_request_is_relayed_with_sender(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device("alice", 1).await;
    let mut bob = app.online_device("bob", 2).await;
    send(
        &mut bob.ws,
        json!({"type":"session_request","to":alice.id,"session_id":"s1","viewer_public_key":key_b64()}),
    )
    .await;
    let got = recv_type(&mut alice.ws, "session_request").await;
    assert_eq!(
        got,
        json!({"type":"session_request","from":bob.id,"session_id":"s1","viewer_public_key":key_b64()})
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn session_request_rejects_bad_key(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.online_device("alice", 1).await;
    let mut bob = app.online_device("bob", 2).await;
    for key in ["AAAA", "not base64!", ""] {
        send(
            &mut bob.ws,
            json!({"type":"session_request","to":alice.id,"session_id":"s1","viewer_public_key":key}),
        )
        .await;
        let err = recv_type(&mut bob.ws, "error").await;
        assert_eq!(err["code"], "bad_message", "{key}");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn session_request_rejects_bad_session_id(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.online_device("alice", 1).await;
    let mut bob = app.online_device("bob", 2).await;
    send(
        &mut bob.ws,
        json!({"type":"session_request","to":alice.id,"session_id":"","viewer_public_key":key_b64()}),
    )
    .await;
    assert_eq!(recv_type(&mut bob.ws, "error").await["code"], "bad_message");
}

#[sqlx::test(migrations = "./migrations")]
async fn session_request_to_offline_host(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut bob = app.online_device("bob", 2).await;
    send(
        &mut bob.ws,
        json!({"type":"session_request","to":"123456789","session_id":"s1","viewer_public_key":key_b64()}),
    )
    .await;
    assert_eq!(
        recv_type(&mut bob.ws, "error").await["code"],
        "target_offline"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn session_response_is_relayed(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device("alice", 1).await;
    let mut bob = app.online_device("bob", 2).await;
    send(
        &mut alice.ws,
        json!({"type":"session_response","to":bob.id,"session_id":"s1","accepted":true,"host_public_key":key_b64()}),
    )
    .await;
    let got = recv_type(&mut bob.ws, "session_response").await;
    assert_eq!(
        got,
        json!({"type":"session_response","from":alice.id,"session_id":"s1","accepted":true,"host_public_key":key_b64()})
    );
    send(
        &mut alice.ws,
        json!({"type":"session_response","to":bob.id,"session_id":"s2","accepted":false,"reason":"room_full"}),
    )
    .await;
    let got = recv_type(&mut bob.ws, "session_response").await;
    assert_eq!(got["reason"], "room_full");
    assert!(got.get("host_public_key").is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn session_response_rejects_bad_host_key(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device("alice", 1).await;
    let bob = app.online_device("bob", 2).await;
    send(
        &mut alice.ws,
        json!({"type":"session_response","to":bob.id,"session_id":"s1","accepted":true,"host_public_key":"AAAA"}),
    )
    .await;
    assert_eq!(
        recv_type(&mut alice.ws, "error").await["code"],
        "bad_message"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn host_token_is_for_own_room(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device("alice", 1).await;
    send(&mut alice.ws, json!({"type":"host_token_request"})).await;
    let got = recv_type(&mut alice.ws, "host_token").await;
    let room = format!("host-{}", alice.id);
    assert_eq!(got["room"], room.as_str());
    assert_eq!(got["url"], "ws://livekit.example:7880");
    let c = claims(got["token"].as_str().unwrap());
    assert_eq!(c["iss"], "testkey");
    assert_eq!(c["sub"], alice.id.as_str());
    assert_eq!(c["video"]["room"], room.as_str());
    assert_eq!(c["video"]["canPublish"], true);
}

#[sqlx::test(migrations = "./migrations")]
async fn viewer_token_goes_to_viewer(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device("alice", 1).await;
    let mut bob = app.online_device("bob", 2).await;
    send(
        &mut alice.ws,
        json!({"type":"viewer_token_request","session_id":"s1","viewer_device_id":bob.id}),
    )
    .await;
    let got = recv_type(&mut bob.ws, "viewer_token").await;
    assert_eq!(got["from"], alice.id.as_str());
    assert_eq!(got["session_id"], "s1");
    assert_eq!(got["room"], format!("host-{}", alice.id).as_str());
    let c = claims(got["token"].as_str().unwrap());
    assert_eq!(c["sub"], bob.id.as_str());
    assert_eq!(c["video"]["room"], format!("host-{}", alice.id).as_str());
    assert_eq!(c["video"]["canPublish"], false);
    assert_eq!(c["video"]["canPublishData"], true);
    assert_eq!(c["exp"].as_u64().unwrap() - c["nbf"].as_u64().unwrap(), 60);
}

#[sqlx::test(migrations = "./migrations")]
async fn viewer_token_for_self_is_forbidden(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device("alice", 1).await;
    send(
        &mut alice.ws,
        json!({"type":"viewer_token_request","session_id":"s1","viewer_device_id":alice.id}),
    )
    .await;
    assert_eq!(recv_type(&mut alice.ws, "error").await["code"], "forbidden");
}

#[sqlx::test(migrations = "./migrations")]
async fn viewer_token_cannot_target_other_room(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.online_device("alice", 1).await;
    let mut bob = app.online_device("bob", 2).await;
    let mut carol = app.online_device("carol", 3).await;
    send(
        &mut bob.ws,
        json!({"type":"viewer_token_request","session_id":"s1","viewer_device_id":carol.id}),
    )
    .await;
    let got = recv_type(&mut carol.ws, "viewer_token").await;
    let c = claims(got["token"].as_str().unwrap());
    assert_eq!(c["video"]["room"], format!("host-{}", bob.id).as_str());
    assert_ne!(c["video"]["room"], format!("host-{}", alice.id).as_str());
}

#[sqlx::test(migrations = "./migrations")]
async fn viewer_token_to_offline_viewer(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device("alice", 1).await;
    send(
        &mut alice.ws,
        json!({"type":"viewer_token_request","session_id":"s1","viewer_device_id":"123456789"}),
    )
    .await;
    assert_eq!(
        recv_type(&mut alice.ws, "error").await["code"],
        "target_offline"
    );
}
