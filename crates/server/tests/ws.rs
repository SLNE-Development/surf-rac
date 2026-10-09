//! WebSocket challenge authentication and signaling relay tests.

mod common;

use std::time::Duration;

use common::ws::{
    expect_closed, expect_closed_within, expect_silence, recv, recv_type, send, send_raw,
};
use common::{fingerprint, identity_key, sign_challenge};
use serde_json::json;
use sqlx::PgPool;
use surf_rac_protocol::DeviceId;

#[sqlx::test(migrations = "./migrations")]
async fn valid_signature_gets_hello_and_device_is_online(pool: PgPool) {
    let app = common::spawn(pool).await;
    let dev = app.online_device(1).await;
    let id: DeviceId = dev.id.parse().unwrap();
    assert!(app.state.hub.is_online(id));
    let seen: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("select last_seen_at from devices")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert!(seen.is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn wrong_signature_closes_with_bad_signature(pool: PgPool) {
    let app = common::spawn(pool).await;
    let dev = app.new_device(1).await;
    let (mut ws, nonce) = app.ws_challenged(&dev.id).await;
    let other = identity_key();
    send(
        &mut ws,
        json!({"type":"authenticate","signature":sign_challenge(&other, &nonce),
               "fingerprint_hash":dev.fingerprint}),
    )
    .await;
    let err = recv(&mut ws).await;
    assert_eq!(err["type"], "error");
    assert_eq!(err["code"], "bad_signature");
    expect_closed(&mut ws).await;
    assert!(!app.state.hub.is_online(dev.id.parse().unwrap()));
}

#[sqlx::test(migrations = "./migrations")]
async fn malformed_signature_closes_with_bad_signature(pool: PgPool) {
    let app = common::spawn(pool).await;
    let dev = app.new_device(1).await;
    for signature in ["not base64!", "AAAA"] {
        let (mut ws, _) = app.ws_challenged(&dev.id).await;
        send(
            &mut ws,
            json!({"type":"authenticate","signature":signature,"fingerprint_hash":dev.fingerprint}),
        )
        .await;
        assert_eq!(recv(&mut ws).await["code"], "bad_signature", "{signature}");
        expect_closed(&mut ws).await;
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn replayed_signature_on_new_connection_is_rejected(pool: PgPool) {
    let app = common::spawn(pool).await;
    let dev = app.new_device(1).await;
    let (mut first, nonce) = app.ws_challenged(&dev.id).await;
    let captured = json!({"type":"authenticate","signature":sign_challenge(&dev.key, &nonce),
                          "fingerprint_hash":dev.fingerprint});
    send(&mut first, captured.clone()).await;
    assert_eq!(recv(&mut first).await["type"], "hello");

    let (mut second, second_nonce) = app.ws_challenged(&dev.id).await;
    assert_ne!(nonce, second_nonce);
    send(&mut second, captured).await;
    assert_eq!(recv(&mut second).await["code"], "bad_signature");
    expect_closed(&mut second).await;

    send(&mut first, json!({"type":"ping"})).await;
    assert_eq!(recv(&mut first).await["type"], "pong");
}

#[sqlx::test(migrations = "./migrations")]
async fn successive_connections_get_different_nonces(pool: PgPool) {
    let app = common::spawn(pool).await;
    let dev = app.new_device(1).await;
    let mut seen = Vec::new();
    for _ in 0..5 {
        let (_ws, nonce) = app.ws_challenged(&dev.id).await;
        assert!(!seen.contains(&nonce), "nonce repeated");
        seen.push(nonce);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn authenticate_after_handshake_is_refused(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut dev = app.online_device(1).await;
    send(
        &mut dev.ws,
        json!({"type":"authenticate","signature":"AAAA","fingerprint_hash":dev.fingerprint}),
    )
    .await;
    assert_eq!(recv(&mut dev.ws).await["code"], "bad_message");
    send(&mut dev.ws, json!({"type":"ping"})).await;
    assert_eq!(recv(&mut dev.ws).await["type"], "pong");
}

#[sqlx::test(migrations = "./migrations")]
async fn mismatched_fingerprint_closes_with_clone_detected(pool: PgPool) {
    let app = common::spawn(pool).await;
    let dev = app.new_device(1).await;
    let (mut ws, nonce) = app.ws_challenged(&dev.id).await;
    send(
        &mut ws,
        json!({"type":"authenticate","signature":sign_challenge(&dev.key, &nonce),
               "fingerprint_hash":fingerprint(2)}),
    )
    .await;
    let err = recv(&mut ws).await;
    assert_eq!(err["type"], "error");
    assert_eq!(err["code"], "clone_detected");
    expect_closed(&mut ws).await;
    assert!(!app.state.hub.is_online(dev.id.parse().unwrap()));
}

#[sqlx::test(migrations = "./migrations")]
async fn no_authenticate_in_time_closes_socket(pool: PgPool) {
    let app = common::spawn_with(pool, |s| {
        s.ws_auth_timeout = Duration::from_millis(300);
    })
    .await;
    let dev = app.new_device(1).await;
    let (mut ws, _) = app.ws_challenged(&dev.id).await;
    expect_closed_within(&mut ws, Duration::from_secs(3)).await;
    assert!(!app.state.hub.is_online(dev.id.parse().unwrap()));
}

#[sqlx::test(migrations = "./migrations")]
async fn auth_timeout_defaults_to_ten_seconds(pool: PgPool) {
    let app = common::spawn(pool).await;
    assert_eq!(app.state.ws_auth_timeout, Duration::from_secs(10));
}

#[sqlx::test(migrations = "./migrations")]
async fn other_first_message_closes_with_bad_message(pool: PgPool) {
    let app = common::spawn(pool).await;
    let dev = app.new_device(1).await;
    let (mut ws, _) = app.ws_challenged(&dev.id).await;
    send(&mut ws, json!({"type":"ping"})).await;
    assert_eq!(recv(&mut ws).await["code"], "bad_message");
    expect_closed(&mut ws).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn wrong_or_missing_protocol_version_is_update_required(pool: PgPool) {
    let app = common::spawn(pool).await;
    let dev = app.new_device(1).await;
    for version in [Some("1"), Some("3"), Some("two"), None] {
        let refused = app.ws_open(Some(&dev.id), version).await.err().unwrap();
        assert_eq!(refused.status, 426, "{version:?}");
        assert_eq!(
            refused.body.as_ref().map(|b| b["error"].clone()),
            Some(json!("update_required")),
            "{version:?}"
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_unknown_or_disabled_device_is_unauthorized(pool: PgPool) {
    let app = common::spawn(pool).await;
    let version = surf_rac_protocol::PROTOCOL_VERSION.to_string();
    for id in [None, Some("abc"), Some("123456789")] {
        let refused = app.ws_open(id, Some(&version)).await.err().unwrap();
        assert_eq!(refused.status, 401, "{id:?}");
    }
    let dev = app.new_device(1).await;
    sqlx::query("update devices set disabled = true")
        .execute(&app.pool)
        .await
        .unwrap();
    let refused = app
        .ws_open(Some(&dev.id), Some(&version))
        .await
        .err()
        .unwrap();
    assert_eq!(refused.status, 401);
}

#[sqlx::test(migrations = "./migrations")]
async fn offer_answer_ice_hangup_relayed(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device(1).await;
    let mut b = app.online_device(2).await;
    for (kind, data) in [
        ("offer", json!({"sdp": "v=0 offer"})),
        ("ice", json!({"candidate": "c1"})),
    ] {
        send(
            &mut a.ws,
            json!({"type":"signal","to":b.id,"session_id":"s1","kind":kind,"data":data}),
        )
        .await;
        let got = recv(&mut b.ws).await;
        assert_eq!(
            got,
            json!({"type":"signal","from":a.id,"session_id":"s1","kind":kind,"data":data})
        );
    }
    for (kind, data) in [
        ("answer", json!({"sdp": "v=0 answer"})),
        ("hangup", json!(null)),
    ] {
        send(
            &mut b.ws,
            json!({"type":"signal","to":a.id,"session_id":"s1","kind":kind,"data":data}),
        )
        .await;
        let got = recv(&mut a.ws).await;
        assert_eq!(got["from"], b.id.as_str());
        assert_eq!(got["kind"], kind);
        assert_eq!(got["data"], data);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn from_is_stamped_by_server(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device(1).await;
    let mut b = app.online_device(2).await;
    send(
        &mut a.ws,
        json!({"type":"signal","from":"111111111","to":b.id,"session_id":"s","kind":"offer","data":{}}),
    )
    .await;
    let got = recv(&mut b.ws).await;
    assert_eq!(got["from"], a.id.as_str());
}

#[sqlx::test(migrations = "./migrations")]
async fn target_offline_error(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device(1).await;
    let offline = app.new_device(2).await;
    for to in [offline.id.as_str(), "123456789"] {
        send(
            &mut a.ws,
            json!({"type":"signal","to":to,"session_id":"s","kind":"offer","data":{}}),
        )
        .await;
        let got = recv(&mut a.ws).await;
        assert_eq!(got["type"], "error");
        assert_eq!(got["code"], "target_offline");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn malformed_message_bad_message_and_socket_stays_open(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device(1).await;
    for raw in [
        "not json".to_string(),
        json!({"type":"nope"}).to_string(),
        json!({"type":"signal","to":"123456789","session_id":"","kind":"offer","data":{}}).to_string(),
        json!({"type":"signal","to":"123456789","session_id":"x".repeat(65),"kind":"offer","data":{}}).to_string(),
    ] {
        send_raw(&mut a.ws, &raw).await;
        let got = recv(&mut a.ws).await;
        assert_eq!(got["code"], "bad_message", "{raw}");
    }
    send(&mut a.ws, json!({"type":"ping"})).await;
    assert_eq!(recv(&mut a.ws).await, json!({"type":"pong"}));
}

#[sqlx::test(migrations = "./migrations")]
async fn oversized_message_closes_socket(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device(1).await;
    let big = json!({"type":"ping","pad":"x".repeat(70_000)}).to_string();
    send_raw(&mut a.ws, &big).await;
    expect_closed(&mut a.ws).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn second_connection_replaces_first(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut first = app.online_device(1).await;
    let mut second = app.ws_connect(&first.identity()).await;
    assert_eq!(recv(&mut second).await["type"], "hello");
    assert_eq!(recv(&mut first.ws).await, json!({"type":"replaced"}));
    expect_closed(&mut first.ws).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn unauthenticated_connection_does_not_replace_live_one(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut live = app.online_device(1).await;
    let (mut pending, _) = app.ws_challenged(&live.id).await;
    send(
        &mut pending,
        json!({"type":"authenticate","signature":sign_challenge(&identity_key(), &[0u8; 32]),
               "fingerprint_hash":live.fingerprint}),
    )
    .await;
    assert_eq!(recv(&mut pending).await["code"], "bad_signature");
    send(&mut live.ws, json!({"type":"ping"})).await;
    assert_eq!(recv(&mut live.ws).await["type"], "pong");
}

#[sqlx::test(migrations = "./migrations")]
async fn replaced_connection_cleanup_keeps_new(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut first = app.online_device(1).await;
    let mut second = app.ws_connect(&first.identity()).await;
    recv(&mut second).await;
    expect_closed(&mut first.ws).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut b = app.online_device(2).await;
    send(
        &mut b.ws,
        json!({"type":"signal","to":first.id,"session_id":"s","kind":"offer","data":{}}),
    )
    .await;
    let got = recv(&mut second).await;
    assert_eq!(got["from"], b.id.as_str());
}

#[sqlx::test(migrations = "./migrations")]
async fn disabled_device_closes_socket(pool: PgPool) {
    let app = common::spawn_with(pool, |s| {
        s.ws_revalidate_interval = Duration::from_millis(200);
    })
    .await;
    let mut a = app.online_device(1).await;
    let mut b = app.online_device(2).await;
    sqlx::query("update devices set disabled = true where id = $1")
        .bind(a.id.parse::<i64>().unwrap())
        .execute(&app.pool)
        .await
        .unwrap();
    expect_closed(&mut a.ws).await;
    send(&mut b.ws, json!({"type":"ping"})).await;
    assert_eq!(recv(&mut b.ws).await["type"], "pong");
}

#[sqlx::test(migrations = "./migrations")]
async fn flood_gets_rate_limited(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device(1).await;
    for _ in 0..300 {
        send(&mut a.ws, json!({"type":"ping"})).await;
    }
    let mut limited = false;
    for _ in 0..300 {
        if recv(&mut a.ws).await["type"] == "error" {
            limited = true;
            break;
        }
    }
    assert!(limited);
    tokio::time::sleep(Duration::from_millis(200)).await;
    send(&mut a.ws, json!({"type":"ping"})).await;
    let _ = recv_type(&mut a.ws, "pong").await;
}

#[sqlx::test(migrations = "./migrations")]
async fn idle_socket_receives_nothing_unexpected(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device(1).await;
    expect_silence(&mut a.ws, Duration::from_millis(300)).await;
}
