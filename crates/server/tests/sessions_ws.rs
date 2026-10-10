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

/// Standard base64 of 32 bytes, a well-formed per-session key or nonce.
fn key_b64() -> String {
    STANDARD.encode([7u8; 32])
}

/// Standard base64 of 64 bytes, a well-formed signature.
fn signature_b64() -> String {
    STANDARD.encode([9u8; 64])
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

/// A session request is relayed to the target with the sender's device ID, identity key and
/// device name added.
#[sqlx::test(migrations = "./migrations")]
async fn session_request_is_relayed_with_sender(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    send(&mut bob.ws, session_request(&alice.id, "s1")).await;
    let got = recv_type(&mut alice.ws, "session_request").await;
    assert_eq!(
        got,
        json!({"type":"session_request","from":bob.id,"session_id":"s1",
               "session_key":key_b64(),"signature":signature_b64(),
               "identity_key":common::public_key_b64(&bob.key),"name":"pc","unattended":false})
    );
}

/// A relayed session request and response carry the sender's registered identity key, not one
/// the sender supplied.
#[sqlx::test(migrations = "./migrations")]
async fn relayed_identity_key_is_the_registered_key(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    let mut request = session_request(&alice.id, "s1");
    request["identity_key"] = json!(STANDARD.encode([1u8; 32]));
    send(&mut bob.ws, request).await;
    let got = recv_type(&mut alice.ws, "session_request").await;
    assert_eq!(
        got["identity_key"],
        common::public_key_b64(&bob.key).as_str()
    );
    send(&mut alice.ws, accepted_response(&bob.id, "s1")).await;
    let got = recv_type(&mut bob.ws, "session_response").await;
    assert_eq!(
        got["identity_key"],
        common::public_key_b64(&alice.key).as_str()
    );
}

/// A password challenge is relayed to the target with the sender's device ID and identity key
/// added.
#[sqlx::test(migrations = "./migrations")]
async fn password_challenge_is_relayed_with_sender(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    send(
        &mut alice.ws,
        json!({"type":"password_challenge","to":bob.id,"session_id":"s1",
               "session_key":key_b64(),"signature":signature_b64(),"host_nonce":key_b64()}),
    )
    .await;
    let got = recv_type(&mut bob.ws, "password_challenge").await;
    assert_eq!(
        got,
        json!({"type":"password_challenge","from":alice.id,"session_id":"s1",
               "session_key":key_b64(),"signature":signature_b64(),"host_nonce":key_b64(),
               "identity_key":common::public_key_b64(&alice.key)})
    );
}

/// A password challenge with a malformed session key, signature or host nonce is refused with
/// `bad_message`.
#[sqlx::test(migrations = "./migrations")]
async fn password_challenge_rejects_bad_fields(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let bob = app.online_device(2).await;
    for (key, signature, nonce) in [
        ("AAAA".to_owned(), signature_b64(), key_b64()),
        (key_b64(), "AAAA".to_owned(), key_b64()),
        (key_b64(), signature_b64(), "AAAA".to_owned()),
    ] {
        send(
            &mut alice.ws,
            json!({"type":"password_challenge","to":bob.id,"session_id":"s1",
                   "session_key":key,"signature":signature,"host_nonce":nonce}),
        )
        .await;
        assert_eq!(
            recv_type(&mut alice.ws, "error").await["code"],
            "bad_message"
        );
    }
}

/// A sealed session password is relayed to the target with the sender's device ID.
#[sqlx::test(migrations = "./migrations")]
async fn session_password_is_relayed_with_sender(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    send(
        &mut bob.ws,
        json!({"type":"session_password","to":alice.id,"session_id":"s1","password":"c2VhbGVk"}),
    )
    .await;
    let got = recv_type(&mut alice.ws, "session_password").await;
    assert_eq!(
        got,
        json!({"type":"session_password","from":bob.id,"session_id":"s1","password":"c2VhbGVk"})
    );
}

/// A sealed password one byte over the maximum length is refused with `bad_message` and not
/// relayed, while one at the maximum is relayed.
#[sqlx::test(migrations = "./migrations")]
async fn session_password_rejects_oversized_password(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    let long = "A".repeat(surf_rac_protocol::MAX_SEALED_PASSWORD_LEN + 1);
    send(
        &mut bob.ws,
        json!({"type":"session_password","to":alice.id,"session_id":"s1","password":long}),
    )
    .await;
    assert_eq!(recv_type(&mut bob.ws, "error").await["code"], "bad_message");
    let longest = "A".repeat(surf_rac_protocol::MAX_SEALED_PASSWORD_LEN);
    send(
        &mut bob.ws,
        json!({"type":"session_password","to":alice.id,"session_id":"s2","password":longest}),
    )
    .await;
    let got = recv_type(&mut alice.ws, "session_password").await;
    assert_eq!(
        got["session_id"], "s2",
        "the oversized password must not be relayed"
    );
}

/// A session request whose session key is too short, not base64 or empty is refused with
/// `bad_message`.
#[sqlx::test(migrations = "./migrations")]
async fn session_request_rejects_bad_key(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    for key in ["AAAA", "not base64!", ""] {
        let mut request = session_request(&alice.id, "s1");
        request["session_key"] = json!(key);
        send(&mut bob.ws, request).await;
        let err = recv_type(&mut bob.ws, "error").await;
        assert_eq!(err["code"], "bad_message", "{key}");
    }
}

/// A session request whose signature is not 64 bytes is refused with `bad_message`.
#[sqlx::test(migrations = "./migrations")]
async fn session_request_rejects_bad_signature_format(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    let mut request = session_request(&alice.id, "s1");
    request["signature"] = json!(key_b64());
    send(&mut bob.ws, request).await;
    assert_eq!(recv_type(&mut bob.ws, "error").await["code"], "bad_message");
}

/// Checks that a session request with an invalid session ID is refused with an
/// error that names no session.
#[sqlx::test(migrations = "./migrations")]
async fn session_request_rejects_bad_session_id(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    send(&mut bob.ws, session_request(&alice.id, "")).await;
    let err = recv_type(&mut bob.ws, "error").await;
    assert_eq!(err["code"], "bad_message");
    assert!(err.get("session_id").is_none(), "{err}");
}

/// Checks that a session request to an offline host is answered with a
/// `target_offline` error naming the request's session.
#[sqlx::test(migrations = "./migrations")]
async fn session_request_to_offline_host(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut bob = app.online_device(2).await;
    send(&mut bob.ws, session_request("123456789", "s1")).await;
    let err = recv_type(&mut bob.ws, "error").await;
    assert_eq!(err["code"], "target_offline");
    assert_eq!(err["session_id"], "s1");
}

/// Checks that every relayed session message to an offline device, and a
/// malformed one, is answered with an error naming the message's session.
#[sqlx::test(migrations = "./migrations")]
async fn session_message_errors_name_their_session(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let offline = "123456789";
    let mut bad_key = session_request(offline, "bad-key");
    bad_key["session_key"] = json!("AAAA");
    let cases = [
        (
            json!({"type":"password_challenge","to":offline,"session_id":"pc",
                   "session_key":key_b64(),"signature":signature_b64(),"host_nonce":key_b64()}),
            "target_offline",
            "pc",
        ),
        (
            json!({"type":"session_password","to":offline,"session_id":"pw","password":"c2VhbGVk"}),
            "target_offline",
            "pw",
        ),
        (accepted_response(offline, "resp"), "target_offline", "resp"),
        (
            json!({"type":"viewer_token_request","session_id":"vt","viewer_device_id":offline}),
            "target_offline",
            "vt",
        ),
        (
            json!({"type":"signal","to":offline,"session_id":"sig","kind":"offer","data":{}}),
            "target_offline",
            "sig",
        ),
        (bad_key, "bad_message", "bad-key"),
    ];
    for (msg, code, session_id) in cases {
        send(&mut alice.ws, msg).await;
        let err = recv_type(&mut alice.ws, "error").await;
        assert_eq!(err["code"], code, "{err}");
        assert_eq!(err["session_id"], session_id, "{err}");
    }
}

/// Checks that an error answering a message outside any session names no session.
#[sqlx::test(migrations = "./migrations")]
async fn errors_outside_a_session_name_none(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    send(
        &mut alice.ws,
        json!({"type":"link_account","token":"garbage"}),
    )
    .await;
    let err = recv_type(&mut alice.ws, "error").await;
    assert_eq!(err["code"], "forbidden");
    assert!(err.get("session_id").is_none(), "{err}");
    common::ws::send_raw(&mut alice.ws, "not json").await;
    let err = recv_type(&mut alice.ws, "error").await;
    assert_eq!(err["code"], "bad_message");
    assert!(err.get("session_id").is_none(), "{err}");
}

/// Checks that a message dropped by the connection's message rate limit is
/// answered with a `rate_limited` error naming the message's session.
#[sqlx::test(migrations = "./migrations")]
async fn flood_rate_limit_names_the_dropped_session(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    for _ in 0..300 {
        send(
            &mut alice.ws,
            json!({"type":"signal","to":"123456789","session_id":"flood","kind":"ice","data":{}}),
        )
        .await;
    }
    let err = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let err = recv_type(&mut alice.ws, "error").await;
            if err["code"] == "rate_limited" {
                return err;
            }
        }
    })
    .await
    .expect("no rate_limited error");
    assert_eq!(err["session_id"], "flood", "{err}");
}

/// An accepted session response is relayed with the sender's ID and identity key, and a refusal
/// is relayed with its reason but no keys.
#[sqlx::test(migrations = "./migrations")]
async fn session_response_is_relayed(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let mut bob = app.online_device(2).await;
    send(&mut alice.ws, accepted_response(&bob.id, "s1")).await;
    let got = recv_type(&mut bob.ws, "session_response").await;
    assert_eq!(
        got,
        json!({"type":"session_response","from":alice.id,"session_id":"s1","accepted":true,
               "session_key":key_b64(),"signature":signature_b64(),"host_nonce":key_b64(),
               "identity_key":common::public_key_b64(&alice.key)})
    );
    send(
        &mut alice.ws,
        json!({"type":"session_response","to":bob.id,"session_id":"s2","accepted":false,"reason":"room_full"}),
    )
    .await;
    let got = recv_type(&mut bob.ws, "session_response").await;
    assert_eq!(got["reason"], "room_full");
    assert!(got.get("session_key").is_none());
    assert!(
        got.get("identity_key").is_none(),
        "a refusal carries no identity key"
    );
}

/// An accepted session response with a malformed session key is refused with `bad_message`.
#[sqlx::test(migrations = "./migrations")]
async fn session_response_rejects_bad_host_key(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let bob = app.online_device(2).await;
    let mut response = accepted_response(&bob.id, "s1");
    response["session_key"] = json!("AAAA");
    send(&mut alice.ws, response).await;
    assert_eq!(
        recv_type(&mut alice.ws, "error").await["code"],
        "bad_message"
    );
}

/// A host token request returns the LiveKit URL and a signed token that lets the device publish
/// in its own room.
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

/// A viewer token requested by a host is delivered to the viewer, scoped to the host's room,
/// without media publishing and valid for 60 seconds.
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

/// Requesting a viewer token for the requesting device itself is refused with `forbidden`.
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

/// A viewer token is always scoped to the requesting host's own room, never another host's.
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

/// A viewer token request for an offline viewer is answered with `target_offline`.
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

/// An accepted session response with a malformed host nonce is refused with `bad_message`.
#[sqlx::test(migrations = "./migrations")]
async fn session_response_rejects_bad_nonce(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut alice = app.online_device(1).await;
    let bob = app.online_device(2).await;
    let mut response = accepted_response(&bob.id, "s1");
    response["host_nonce"] = json!("AAAA");
    send(&mut alice.ws, response).await;
    assert_eq!(
        recv_type(&mut alice.ws, "error").await["code"],
        "bad_message"
    );
}

/// Returns a well-formed session request to `to` with session ID `session_id`.
fn session_request(to: &str, session_id: &str) -> Value {
    json!({"type":"session_request","to":to,"session_id":session_id,
           "session_key":key_b64(),"signature":signature_b64(),"unattended":false})
}

/// Returns a well-formed accepted session response to `to` for session `session_id`.
fn accepted_response(to: &str, session_id: &str) -> Value {
    json!({"type":"session_response","to":to,"session_id":session_id,"accepted":true,
           "session_key":key_b64(),"signature":signature_b64(),"host_nonce":key_b64()})
}

/// Checks that the eleventh session request to one host within a minute is
/// refused with a `rate_limited` error naming its session, while requests to
/// another host still pass.
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
    let err = recv_type(&mut bob.ws, "error").await;
    assert_eq!(err["code"], "rate_limited");
    assert_eq!(err["session_id"], "s10");
    common::ws::expect_silence(&mut alice.ws, std::time::Duration::from_millis(300)).await;
    send(&mut alice.ws, session_request(&bob.id, "to-bob")).await;
    let got = recv_type(&mut bob.ws, "session_request").await;
    assert_eq!(got["session_id"], "to-bob", "another target is not limited");
}

/// A session password sent after the per-target session request limit is reached is still
/// relayed.
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
