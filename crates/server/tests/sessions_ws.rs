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
    let mut alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
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
async fn session_request_relays_sealed_password(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    send(
        &mut bob.ws,
        json!({"type":"session_request","to":alice.id,"session_id":"s1",
               "viewer_public_key":key_b64(),"password":"c2VhbGVk"}),
    )
    .await;
    let got = recv_type(&mut alice.ws, "session_request").await;
    assert_eq!(got["password"], "c2VhbGVk");
}

#[sqlx::test(migrations = "./migrations")]
async fn session_request_rejects_oversized_password(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    let long = "A".repeat(surf_rac_protocol::MAX_SEALED_PASSWORD_LEN + 1);
    send(
        &mut bob.ws,
        json!({"type":"session_request","to":alice.id,"session_id":"s1",
               "viewer_public_key":key_b64(),"password":long}),
    )
    .await;
    assert_eq!(recv_type(&mut bob.ws, "error").await["code"], "bad_message");
    send(
        &mut bob.ws,
        json!({"type":"session_request","to":alice.id,"session_id":"s2","viewer_public_key":key_b64()}),
    )
    .await;
    let got = recv_type(&mut alice.ws, "session_request").await;
    assert_eq!(
        got["session_id"], "s2",
        "the oversized request must not be relayed"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn session_request_rejects_bad_key(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
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
    let alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
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
    let mut bob = app.online_device(2).await;
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
    let mut alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    send(
        &mut alice.ws,
        json!({"type":"session_response","to":bob.id,"session_id":"s1","accepted":true,"host_public_key":key_b64(),"host_nonce":key_b64()}),
    )
    .await;
    let got = recv_type(&mut bob.ws, "session_response").await;
    assert_eq!(
        got,
        json!({"type":"session_response","from":alice.id,"session_id":"s1","accepted":true,"host_public_key":key_b64(),"host_nonce":key_b64()})
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
    let mut alice = app.online_device(1).await;
    let bob = app.online_device(2).await;
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
    let mut alice = app.online_device(1).await;
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
    let mut alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
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
    let mut alice = app.online_device(1).await;
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
    let alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    let mut carol = app.online_device(3).await;
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
    let mut alice = app.online_device(1).await;
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

#[sqlx::test(migrations = "./migrations")]
async fn session_response_rejects_bad_nonce(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let bob = app.online_device(2).await;
    send(
        &mut alice.ws,
        json!({"type":"session_response","to":bob.id,"session_id":"s1","accepted":true,
               "host_public_key":key_b64(),"host_nonce":"AAAA"}),
    )
    .await;
    assert_eq!(
        recv_type(&mut alice.ws, "error").await["code"],
        "bad_message"
    );
}

/// Returns a well-formed session request to `to` with session ID `session_id`.
fn session_request(to: &str, session_id: &str) -> Value {
    json!({"type":"session_request","to":to,"session_id":session_id,
           "session_key":key_b64(),"signature":STANDARD.encode([9u8; 64]),"unattended":false})
}

#[sqlx::test(migrations = "./migrations")]
async fn session_requests_are_limited_per_target(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    for i in 0..10 {
        send(&mut bob.ws, session_request(&alice.id, &format!("s{i}"))).await;
        let got = recv_type(&mut alice.ws, "session_request").await;
        assert_eq!(got["session_id"], format!("s{i}").as_str());
    }
    send(&mut bob.ws, session_request(&alice.id, "s10")).await;
    assert_eq!(
        recv_type(&mut bob.ws, "error").await["code"],
        "rate_limited"
    );
    common::ws::expect_silence(&mut alice.ws, std::time::Duration::from_millis(300)).await;
    send(&mut alice.ws, session_request(&bob.id, "to-bob")).await;
    let got = recv_type(&mut bob.ws, "session_request").await;
    assert_eq!(got["session_id"], "to-bob", "another target is not limited");
}

#[sqlx::test(migrations = "./migrations")]
async fn password_messages_do_not_count_against_the_target_limit(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    for i in 0..10 {
        send(&mut bob.ws, session_request(&alice.id, &format!("s{i}"))).await;
        recv_type(&mut alice.ws, "session_request").await;
    }
    send(
        &mut bob.ws,
        json!({"type":"session_password","to":alice.id,"session_id":"s0","password":"c2VhbGVk"}),
    )
    .await;
    let got = recv_type(&mut alice.ws, "session_password").await;
    assert_eq!(got["session_id"], "s0");
}
