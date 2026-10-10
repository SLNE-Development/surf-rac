//! Presence push and TURN credential tests.

mod common;

use std::time::Duration;

use base64::Engine;
use common::TEST_TURN_SECRET;
use common::ws::{expect_silence, recv_type, send};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha1::Sha1;
use sqlx::PgPool;

/// A TURN request over the WebSocket returns one-hour credentials whose username names the device
/// and expiry and whose password is the HMAC-SHA1 of the username.
#[sqlx::test(migrations = "./migrations")]
async fn ws_turn_request_returns_credentials(pool: PgPool) {
    let app = common::spawn(pool).await;
    let mut a = app.online_device(1).await;
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

/// A device of an account that has a contact receives presence when that contact connects and
/// disconnects.
#[sqlx::test(migrations = "./migrations")]
async fn contact_sees_presence_online_and_offline(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let mut watcher = app.linked_device(1, &alice).await;
    let bob = app.new_device(2).await;
    let bob_id = bob.id.clone();
    assert_eq!(app.put_contact(&alice, &bob_id, "bob").await.status(), 204);

    let device = app.connect_device(bob).await;
    let online = recv_type(&mut watcher.ws, "presence").await;
    assert_eq!(
        online,
        json!({"type":"presence","device_id":bob_id,"online":true})
    );

    drop(device);
    let offline = recv_type(&mut watcher.ws, "presence").await;
    assert_eq!(
        offline,
        json!({"type":"presence","device_id":bob_id,"online":false})
    );
}

/// Presence of a contact reaches every online device of the watching account.
#[sqlx::test(migrations = "./migrations")]
async fn presence_reaches_every_online_device_of_a_watcher(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let mut first = app.linked_device(1, &alice).await;
    let mut second = app.linked_device(2, &alice).await;
    let target = app.new_device(3).await;
    let target_id = target.id.clone();
    assert_eq!(app.put_contact(&alice, &target_id, "t").await.status(), 204);
    let _target = app.connect_device(target).await;
    let expected = json!({"type":"presence","device_id":target_id,"online":true});
    assert_eq!(recv_type(&mut first.ws, "presence").await, expected);
    assert_eq!(recv_type(&mut second.ws, "presence").await, expected);
}

/// A device linked to an account is watched by that account's other devices without being a
/// contact.
#[sqlx::test(migrations = "./migrations")]
async fn linked_device_is_watched_by_its_account(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let mut watcher = app.linked_device(1, &alice).await;
    let other = app.linked_device(2, &alice).await;
    let identity = other.identity();
    let id = identity.id.clone();
    drop(other);
    assert_eq!(
        recv_type(&mut watcher.ws, "presence").await,
        json!({"type":"presence","device_id":id,"online":false})
    );
    let _again = app.connect_device(identity).await;
    assert_eq!(
        recv_type(&mut watcher.ws, "presence").await,
        json!({"type":"presence","device_id":id,"online":true})
    );
}

/// After a device is unlinked, its disconnect sends no presence to the account's other devices.
#[sqlx::test(migrations = "./migrations")]
async fn presence_stops_after_unlink(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let mut watcher = app.linked_device(1, &alice).await;
    let other = app.linked_device(2, &alice).await;
    let res = app
        .client
        .delete(app.url(&format!("/v1/my-devices/{}", other.id)))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    drop(other);
    expect_silence(&mut watcher.ws, Duration::from_millis(400)).await;
}

/// Devices that are neither contacts nor linked to the same account receive no presence about each
/// other.
#[sqlx::test(migrations = "./migrations")]
async fn stranger_gets_no_presence(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let mut stranger = app.linked_device(1, &alice).await;
    let mut bob = app.online_device(2).await;
    expect_silence(&mut stranger.ws, Duration::from_millis(300)).await;
    expect_silence(&mut bob.ws, Duration::from_millis(100)).await;
}

/// A reconnecting device receives no presence about itself.
#[sqlx::test(migrations = "./migrations")]
async fn device_gets_no_presence_about_itself(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let a = app.linked_device(1, &alice).await;
    let identity = a.identity();
    drop(a);
    let mut again = app.connect_device(identity).await;
    expect_silence(&mut again.ws, Duration::from_millis(300)).await;
}

/// A connection replaced by a new one for the same device sends no offline presence to watchers.
#[sqlx::test(migrations = "./migrations")]
async fn replacement_does_not_broadcast_offline(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let mut watcher = app.linked_device(1, &alice).await;
    let bob = app.new_device(2).await;
    assert_eq!(app.put_contact(&alice, &bob.id, "bob").await.status(), 204);

    let first = app.connect_device(bob).await;
    assert_eq!(recv_type(&mut watcher.ws, "presence").await["online"], true);
    let _second = app.connect_device(first.identity()).await;
    expect_silence(&mut watcher.ws, Duration::from_millis(400)).await;
}

/// A device linked to two accounts that both have a contact receives that contact's presence only
/// once.
#[sqlx::test(migrations = "./migrations")]
async fn device_of_two_watching_accounts_gets_presence_once(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let bob = app.register_and_login("bob").await;
    let mut watcher = app.linked_device(1, &alice).await;
    assert_eq!(
        common::ws::link(&mut watcher.ws, &bob).await["type"],
        "linked"
    );
    let target = app.new_device(2).await;
    for token in [&alice, &bob] {
        assert_eq!(app.put_contact(token, &target.id, "t").await.status(), 204);
    }
    let _target = app.connect_device(target).await;
    assert_eq!(recv_type(&mut watcher.ws, "presence").await["online"], true);
    expect_silence(&mut watcher.ws, Duration::from_millis(400)).await;
}
