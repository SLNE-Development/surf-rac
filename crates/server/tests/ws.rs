//! WebSocket connect and signaling relay tests.

mod common;

use std::time::Duration;

use common::fingerprint;
use common::ws::{expect_closed, expect_silence, recv, recv_type, send, send_raw};
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn ws_rejects_missing_token(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    let (id, secret) = app.new_device(&token, &fingerprint(1)).await;
    assert_eq!(app.ws_connect(None, &id, &secret).await.err(), Some(401));
    assert_eq!(app.ws_connect(Some("garbage"), &id, &secret).await.err(), Some(401));
}

#[sqlx::test(migrations = "./migrations")]
async fn ws_rejects_wrong_secret(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    let (id, _) = app.new_device(&token, &fingerprint(1)).await;
    assert_eq!(app.ws_connect(Some(&token), &id, "wrong").await.err(), Some(401));
    assert_eq!(app.ws_connect(Some(&token), "abc", "wrong").await.err(), Some(401));
}

#[sqlx::test(migrations = "./migrations")]
async fn ws_rejects_device_of_other_account(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let bob = app.register_and_login("bob").await;
    let (id, secret) = app.new_device(&alice, &fingerprint(1)).await;
    assert_eq!(app.ws_connect(Some(&bob), &id, &secret).await.err(), Some(401));
}

#[sqlx::test(migrations = "./migrations")]
async fn ws_hello_on_connect_and_online(pool: PgPool) {
    let app = common::spawn(pool).await;
    let dev = app.online_device("alice", 1).await;
    let res = app
        .client
        .get(app.url(&format!("/v1/presence/{}", dev.id)))
        .bearer_auth(&dev.token)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["online"], true);
    let seen: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("select last_seen_at from devices")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert!(seen.is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn offer_answer_ice_hangup_relayed(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device("alice", 1).await;
    let mut b = app.online_device("bob", 2).await;
    for (kind, data) in [
        ("offer", json!({"sdp": "v=0 offer"})),
        ("ice", json!({"candidate": "c1"})),
    ] {
        send(&mut a.ws, json!({"type":"signal","to":b.id,"session_id":"s1","kind":kind,"data":data})).await;
        let got = recv(&mut b.ws).await;
        assert_eq!(
            got,
            json!({"type":"signal","from":a.id,"session_id":"s1","kind":kind,"data":data})
        );
    }
    for (kind, data) in [("answer", json!({"sdp": "v=0 answer"})), ("hangup", json!(null))] {
        send(&mut b.ws, json!({"type":"signal","to":a.id,"session_id":"s1","kind":kind,"data":data})).await;
        let got = recv(&mut a.ws).await;
        assert_eq!(got["from"], b.id.as_str());
        assert_eq!(got["kind"], kind);
        assert_eq!(got["data"], data);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn from_is_stamped_by_server(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device("alice", 1).await;
    let mut b = app.online_device("bob", 2).await;
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
    let mut a = app.online_device("alice", 1).await;
    let bob = app.register_and_login("bob").await;
    let (offline_id, _) = app.new_device(&bob, &fingerprint(2)).await;
    for to in [offline_id.as_str(), "123456789"] {
        send(&mut a.ws, json!({"type":"signal","to":to,"session_id":"s","kind":"offer","data":{}})).await;
        let got = recv(&mut a.ws).await;
        assert_eq!(got["type"], "error");
        assert_eq!(got["code"], "target_offline");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn malformed_message_bad_message_and_socket_stays_open(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device("alice", 1).await;
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
    let mut a = app.online_device("alice", 1).await;
    let big = json!({"type":"ping","pad":"x".repeat(70_000)}).to_string();
    send_raw(&mut a.ws, &big).await;
    expect_closed(&mut a.ws).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn second_connection_replaces_first(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut first = app.online_device("alice", 1).await;
    let mut second = app
        .ws_connect(Some(&first.token), &first.id, &first.secret)
        .await
        .unwrap();
    assert_eq!(recv(&mut second).await["type"], "hello");
    assert_eq!(recv(&mut first.ws).await, json!({"type":"replaced"}));
    expect_closed(&mut first.ws).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn replaced_connection_cleanup_keeps_new(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut first = app.online_device("alice", 1).await;
    let mut second = app
        .ws_connect(Some(&first.token), &first.id, &first.secret)
        .await
        .unwrap();
    recv(&mut second).await;
    expect_closed(&mut first.ws).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut b = app.online_device("bob", 2).await;
    send(&mut b.ws, json!({"type":"signal","to":first.id,"session_id":"s","kind":"offer","data":{}})).await;
    let got = recv(&mut second).await;
    assert_eq!(got["from"], b.id.as_str());
}

#[sqlx::test(migrations = "./migrations")]
async fn rebind_closes_live_socket(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device("alice", 1).await;
    let (id, new_secret) = app.new_device(&a.token, &fingerprint(1)).await;
    assert_eq!(id, a.id);
    assert_eq!(recv(&mut a.ws).await["type"], "replaced");
    expect_closed(&mut a.ws).await;
    assert_eq!(app.ws_connect(Some(&a.token), &id, &a.secret).await.err(), Some(401));
    assert!(app.ws_connect(Some(&a.token), &id, &new_secret).await.is_ok());
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_device_closes_live_socket(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device("alice", 1).await;
    let res = app
        .client
        .delete(app.url(&format!("/v1/devices/{}", a.id)))
        .bearer_auth(&a.token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    expect_closed(&mut a.ws).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn revoked_session_closes_socket(pool: PgPool) {
    let app = common::spawn_with(pool, |s| {
        s.ws_revalidate_interval = Duration::from_millis(200);
    })
    .await;
    let mut a = app.online_device("alice", 1).await;
    let mut b = app.online_device("bob", 2).await;
    surf_rac_server::admin::revoke_sessions(&app.pool, "alice").await.unwrap();
    expect_closed(&mut a.ws).await;
    send(&mut b.ws, json!({"type":"ping"})).await;
    assert_eq!(recv(&mut b.ws).await["type"], "pong");
}

#[sqlx::test(migrations = "./migrations")]
async fn flood_gets_rate_limited(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device("alice", 1).await;
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
    let mut a = app.online_device("alice", 1).await;
    expect_silence(&mut a.ws, Duration::from_millis(300)).await;
}
