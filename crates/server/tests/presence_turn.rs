//! Presence push and TURN credential tests.

mod common;

use std::time::Duration;

use base64::Engine;
use common::ws::{expect_silence, recv_type, send};
use common::{TEST_TURN_SECRET, fingerprint};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha1::Sha1;
use sqlx::PgPool;

/// Adds `device_id` to the contacts of `token`.
async fn add_contact(app: &common::TestApp, token: &str, device_id: &str) {
    let res = app
        .client
        .put(app.url(&format!("/v1/contacts/{device_id}")))
        .bearer_auth(token)
        .json(&json!({"alias": "friend"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
}

#[sqlx::test(migrations = "./migrations")]
async fn ws_turn_request_returns_credentials(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device("alice", 1).await;
    send(&mut a.ws, json!({"type":"turn_request"})).await;
    let creds = recv_type(&mut a.ws, "turn_credentials").await;
    assert_eq!(creds["ttl_secs"], 3600);
    assert_eq!(creds["urls"], json!(["turn:turn.example:3478"]));
    let username = creds["username"].as_str().unwrap();
    let (expiry, id) = username.split_once(':').unwrap();
    assert_eq!(id, a.id);
    let now = chrono::Utc::now().timestamp();
    let expiry: i64 = expiry.parse().unwrap();
    assert!((expiry - now - 3600).abs() <= 5, "{expiry} vs {now}");
    let mut mac = Hmac::<Sha1>::new_from_slice(TEST_TURN_SECRET.as_bytes()).unwrap();
    mac.update(username.as_bytes());
    let expected = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    assert_eq!(creds["password"], expected);
}

#[sqlx::test(migrations = "./migrations")]
async fn contact_sees_presence_online_and_offline(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut watcher = app.online_device("alice", 1).await;
    let bob = app.register_and_login("bob").await;
    let (bob_id, bob_secret) = app.new_device(&bob, &fingerprint(2)).await;
    add_contact(&app, &watcher.token, &bob_id).await;

    let ws = app
        .ws_connect(Some(&bob), &bob_id, &bob_secret)
        .await
        .unwrap();
    let online = recv_type(&mut watcher.ws, "presence").await;
    assert_eq!(
        online,
        json!({"type":"presence","device_id":bob_id,"online":true})
    );

    drop(ws);
    let offline = recv_type(&mut watcher.ws, "presence").await;
    assert_eq!(
        offline,
        json!({"type":"presence","device_id":bob_id,"online":false})
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn owner_other_device_sees_presence(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut first = app.online_device("alice", 1).await;
    let second = app.connect_new_device(&first.token, 2).await;
    let got = recv_type(&mut first.ws, "presence").await;
    assert_eq!(
        got,
        json!({"type":"presence","device_id":second.id,"online":true})
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn stranger_gets_no_presence(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut stranger = app.online_device("alice", 1).await;
    let mut bob = app.online_device("bob", 2).await;
    expect_silence(&mut stranger.ws, Duration::from_millis(300)).await;
    expect_silence(&mut bob.ws, Duration::from_millis(100)).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn device_gets_no_presence_about_itself(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device("alice", 1).await;
    expect_silence(&mut a.ws, Duration::from_millis(300)).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn replacement_does_not_broadcast_offline(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut watcher = app.online_device("alice", 1).await;
    let bob = app.register_and_login("bob").await;
    let (bob_id, bob_secret) = app.new_device(&bob, &fingerprint(2)).await;
    add_contact(&app, &watcher.token, &bob_id).await;

    let _first = app
        .ws_connect(Some(&bob), &bob_id, &bob_secret)
        .await
        .unwrap();
    assert_eq!(recv_type(&mut watcher.ws, "presence").await["online"], true);
    let _second = app
        .ws_connect(Some(&bob), &bob_id, &bob_secret)
        .await
        .unwrap();
    expect_silence(&mut watcher.ws, Duration::from_millis(400)).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn rebind_and_delete_broadcast_offline(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut watcher = app.online_device("alice", 1).await;
    let bob = app.register_and_login("bob").await;
    for n in [2u32, 3] {
        let (id, secret) = app.new_device(&bob, &fingerprint(n)).await;
        add_contact(&app, &watcher.token, &id).await;
        let _ws = app.ws_connect(Some(&bob), &id, &secret).await.unwrap();
        assert_eq!(recv_type(&mut watcher.ws, "presence").await["online"], true);
        if n == 2 {
            app.new_device(&bob, &fingerprint(n)).await;
        } else {
            let res = app
                .client
                .delete(app.url(&format!("/v1/devices/{id}")))
                .bearer_auth(&bob)
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), 204);
        }
        let offline = recv_type(&mut watcher.ws, "presence").await;
        assert_eq!(
            offline,
            json!({"type":"presence","device_id":id,"online":false})
        );
    }
}
