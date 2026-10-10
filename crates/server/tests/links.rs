//! Account links over the device WebSocket, My devices and account deletion tests.

mod common;

use std::time::Duration;

use common::PASSWORD;
use common::ws::{link, recv, send};
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn link_account_links_device_and_answers_linked(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let mut device = app.online_device(1).await;
    let reply = link(&mut device.ws, &alice).await;
    assert_eq!(reply, json!({"type": "linked", "username": "alice"}));
    let listed = app.my_devices(&alice).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["device_id"], device.id.as_str());
    assert_eq!(listed[0]["name"], "pc");
    assert_eq!(listed[0]["online"], true);
}

#[sqlx::test(migrations = "./migrations")]
async fn link_twice_is_idempotent(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let mut device = app.linked_device(1, &alice).await;
    let reply = link(&mut device.ws, &alice).await;
    assert_eq!(reply["type"], "linked");
    assert_eq!(app.my_device_ids(&alice).await, vec![device.id.clone()]);
}

#[sqlx::test(migrations = "./migrations")]
async fn link_with_invalid_token_fails_without_linking(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let mut device = app.online_device(1).await;
    for token in ["garbage", ""] {
        let reply = link(&mut device.ws, token).await;
        assert_eq!(reply["type"], "error", "{reply}");
        assert_eq!(reply["code"], "forbidden");
    }
    // A revoked token is refused as well.
    let res = app
        .client
        .post(app.url("/v1/logout"))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    let reply = link(&mut device.ws, &alice).await;
    assert_eq!(reply["code"], "forbidden");
    assert_eq!(app.count("device_links", "true").await, 0);
    // The connection stays usable.
    send(&mut device.ws, json!({"type": "ping"})).await;
    assert_eq!(recv(&mut device.ws).await["type"], "pong");
}

/// Checks that `unlink_account` is not a WebSocket message: it is refused as
/// `bad_message` and the device stays linked.
#[sqlx::test(migrations = "./migrations")]
async fn unlink_account_is_not_a_message(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let mut device = app.linked_device(1, &alice).await;
    send(
        &mut device.ws,
        json!({"type": "unlink_account", "token": alice}),
    )
    .await;
    let reply = recv(&mut device.ws).await;
    assert_eq!(reply["type"], "error", "{reply}");
    assert_eq!(reply["code"], "bad_message");
    assert_eq!(app.my_device_ids(&alice).await, vec![device.id.clone()]);
}

#[sqlx::test(migrations = "./migrations")]
async fn device_linked_to_two_accounts_is_listed_for_both(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let bob = app.register_and_login("bob").await;
    let mut device = app.linked_device(1, &alice).await;
    assert_eq!(link(&mut device.ws, &bob).await["type"], "linked");
    assert_eq!(app.my_device_ids(&alice).await, vec![device.id.clone()]);
    assert_eq!(app.my_device_ids(&bob).await, vec![device.id.clone()]);
}

#[sqlx::test(migrations = "./migrations")]
async fn account_deletion_removes_contacts_and_links_but_never_devices(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let bob = app.register_and_login("bob").await;
    let mut shared = app.linked_device(1, &alice).await;
    assert_eq!(link(&mut shared.ws, &bob).await["type"], "linked");
    let only_alice = app.linked_device(2, &alice).await;
    assert_eq!(
        app.put_contact(&alice, "123456789", "friend")
            .await
            .status(),
        204
    );
    assert_eq!(
        app.put_contact(&bob, "123456789", "friend").await.status(),
        204
    );

    let res = app.delete_account(&alice, "wrong password!").await;
    assert_eq!(res.status(), 401);
    assert_eq!(app.count("users", "username = 'alice'").await, 1);

    let res = app.delete_account(&alice, PASSWORD).await;
    assert_eq!(res.status(), 204);

    assert_eq!(app.count("users", "username = 'alice'").await, 0);
    assert_eq!(app.count("device_links", "true").await, 1);
    assert_eq!(app.count("contacts", "true").await, 1);
    assert_eq!(app.count("sessions", "true").await, 1);
    for id in [&shared.id, &only_alice.id] {
        assert_eq!(app.count("devices", &format!("id = {id}")).await, 1, "{id}");
    }
    assert_eq!(app.my_device_ids(&bob).await, vec![shared.id.clone()]);
    let res = app
        .client
        .get(app.url("/v1/my-devices"))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_account_locks_after_five_wrong_passwords(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    for _ in 0..5 {
        let res = app.delete_account(&alice, "wrong password!").await;
        assert_eq!(res.status(), 401);
    }
    let res = app.delete_account(&alice, PASSWORD).await;
    assert_eq!(res.status(), 429);
    assert!(res.headers().contains_key("retry-after"));
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "locked");
    assert_eq!(app.count("users", "username = 'alice'").await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_account_requires_session(pool: PgPool) {
    let app = common::spawn(pool).await;
    app.register_and_login("alice").await;
    let res = app.delete_account("garbage", PASSWORD).await;
    assert_eq!(res.status(), 401);
    assert_eq!(app.count("users", "true").await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_my_device_unlinks_only(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let bob = app.register_and_login("bob").await;
    let mut device = app.linked_device(1, &alice).await;
    assert_eq!(link(&mut device.ws, &bob).await["type"], "linked");
    let url = app.url(&format!("/v1/my-devices/{}", device.id));

    let res = app
        .client
        .delete(&url)
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    assert!(app.my_device_ids(&alice).await.is_empty());
    assert_eq!(app.my_device_ids(&bob).await, vec![device.id.clone()]);
    assert_eq!(
        app.count("devices", &format!("id = {}", device.id)).await,
        1
    );
    // The device stays connected.
    send(&mut device.ws, json!({"type": "ping"})).await;
    assert_eq!(recv(&mut device.ws).await["type"], "pong");

    let res = app
        .client
        .delete(&url)
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let res = app
        .client
        .delete(app.url("/v1/my-devices/12"))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let res = app.client.delete(&url).send().await.unwrap();
    assert_eq!(res.status(), 401);
}

#[sqlx::test(migrations = "./migrations")]
async fn my_devices_shows_offline_devices_and_needs_a_session(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let device = app.linked_device(1, &alice).await;
    let id = device.id.clone();
    drop(device);
    let mut offline = false;
    for _ in 0..50 {
        let listed = app.my_devices(&alice).await;
        if listed[0]["online"] == false {
            offline = true;
            assert!(listed[0]["last_seen_at"].is_string());
            assert_eq!(listed[0]["device_id"], id.as_str());
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(offline);
    let res = app
        .client
        .get(app.url("/v1/my-devices"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[sqlx::test(migrations = "./migrations")]
async fn old_device_list_routes_are_gone(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let device = app.linked_device(1, &alice).await;
    let res = app
        .client
        .get(app.url("/v1/devices"))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 405);
    let res = app
        .client
        .delete(app.url(&format!("/v1/devices/{}", device.id)))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(app.my_device_ids(&alice).await, vec![device.id.clone()]);
}
