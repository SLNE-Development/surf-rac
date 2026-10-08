//! Device registration, re-bind, contacts and presence query tests.

mod common;

use common::{TestApp, fingerprint};
use serde_json::{Value, json};
use sqlx::PgPool;

/// Registers a device for `token` and returns the response body, asserting 200.
async fn register_ok(app: &TestApp, token: &str, fp: &str, device_id: Option<&str>) -> Value {
    let res = app.register_device(token, fp, "pc", device_id).await;
    assert_eq!(res.status(), 200);
    res.json().await.unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn register_new_device_returns_9_digit_id_and_secret(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    let body = register_ok(&app, &token, &fingerprint(1), None).await;
    let id = body["device_id"].as_str().unwrap();
    assert_eq!(id.len(), 9);
    assert!(id.bytes().all(|b| b.is_ascii_digit()) && !id.starts_with('0'));
    assert_eq!(body["device_secret"].as_str().unwrap().len(), 43);
    assert_eq!(body["rebound"], false);
    let stored: Vec<u8> = sqlx::query_scalar("select secret_hash from devices")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(stored.len(), 32);
}

#[sqlx::test(migrations = "./migrations")]
async fn same_fingerprint_same_account_rebinds(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    let first = register_ok(&app, &token, &fingerprint(1), None).await;
    let second = register_ok(&app, &token, &fingerprint(1), None).await;
    assert_eq!(first["device_id"], second["device_id"]);
    assert_eq!(second["rebound"], true);
    assert_ne!(first["device_secret"], second["device_secret"]);
    let count: i64 = sqlx::query_scalar("select count(*) from devices")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn rebind_by_device_id_with_new_fingerprint(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    let first = register_ok(&app, &token, &fingerprint(1), None).await;
    let id = first["device_id"].as_str().unwrap();
    let second = register_ok(&app, &token, &fingerprint(2), Some(id)).await;
    assert_eq!(second["device_id"], id);
    assert_eq!(second["rebound"], true);
    let fp: String = sqlx::query_scalar("select fingerprint_hash from devices")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(fp, fingerprint(2));
}

#[sqlx::test(migrations = "./migrations")]
async fn rebind_foreign_device_id_forbidden(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let bob = app.register_and_login("bob").await;
    let dev = register_ok(&app, &alice, &fingerprint(1), None).await;
    let id = dev["device_id"].as_str().unwrap();
    let res = app
        .register_device(&bob, &fingerprint(9), "evil", Some(id))
        .await;
    assert_eq!(res.status(), 403);
    let owner: String =
        sqlx::query_scalar("select u.username from devices d join users u on u.id = d.user_id")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(owner, "alice");
}

#[sqlx::test(migrations = "./migrations")]
async fn rebind_unknown_device_id_not_found(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    let res = app
        .register_device(&token, &fingerprint(1), "pc", Some("123456789"))
        .await;
    assert_eq!(res.status(), 404);
}

#[sqlx::test(migrations = "./migrations")]
async fn rebind_onto_fingerprint_of_other_own_device_conflicts(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    let a = register_ok(&app, &token, &fingerprint(1), None).await;
    register_ok(&app, &token, &fingerprint(2), None).await;
    let res = app
        .register_device(&token, &fingerprint(2), "pc", a["device_id"].as_str())
        .await;
    assert_eq!(res.status(), 409);
}

#[sqlx::test(migrations = "./migrations")]
async fn fingerprint_of_other_account_gets_new_id(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let bob = app.register_and_login("bob").await;
    let a = register_ok(&app, &alice, &fingerprint(1), None).await;
    let b = register_ok(&app, &bob, &fingerprint(1), None).await;
    assert_ne!(a["device_id"], b["device_id"]);
    assert_eq!(b["rebound"], false);
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_same_fingerprint_registers_one_device(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    let fp = fingerprint(1);
    let (a, b) = tokio::join!(
        app.register_device(&token, &fp, "pc", None),
        app.register_device(&token, &fp, "pc", None)
    );
    assert_eq!(a.status(), 200);
    assert_eq!(b.status(), 200);
    let count: i64 = sqlx::query_scalar("select count(*) from devices")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_device_input_400(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    for fp in [
        "abc".to_string(),
        fingerprint(0xabcdef).to_uppercase(),
        "g".repeat(64),
    ] {
        assert_eq!(
            app.register_device(&token, &fp, "pc", None).await.status(),
            400
        );
    }
    assert_eq!(
        app.register_device(&token, &fingerprint(1), "", None)
            .await
            .status(),
        400
    );
    let long = "n".repeat(65);
    assert_eq!(
        app.register_device(&token, &fingerprint(1), &long, None)
            .await
            .status(),
        400
    );
    assert_eq!(
        app.register_device(&token, &fingerprint(1), "pc", Some("12"))
            .await
            .status(),
        400
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn list_devices_only_own(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let bob = app.register_and_login("bob").await;
    let a = register_ok(&app, &alice, &fingerprint(1), None).await;
    register_ok(&app, &bob, &fingerprint(2), None).await;
    let res = app
        .client
        .get(app.url("/v1/devices"))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let list: Value = res.json().await.unwrap();
    assert_eq!(
        list,
        json!([{"device_id": a["device_id"], "name": "pc", "online": false, "last_seen_at": null}])
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_device_owner_only(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let bob = app.register_and_login("bob").await;
    let a = register_ok(&app, &alice, &fingerprint(1), None).await;
    let path = format!("/v1/devices/{}", a["device_id"].as_str().unwrap());
    let res = app
        .client
        .delete(app.url(&path))
        .bearer_auth(&bob)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let res = app
        .client
        .delete(app.url(&path))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    let res = app
        .client
        .delete(app.url(&path))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[sqlx::test(migrations = "./migrations")]
async fn contacts_crud(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let bob = app.register_and_login("bob").await;
    let b = register_ok(&app, &bob, &fingerprint(2), None).await;
    let id = b["device_id"].as_str().unwrap();
    let path = format!("/v1/contacts/{id}");

    let put = |alias: &str| {
        app.client
            .put(app.url(&path))
            .bearer_auth(&alice)
            .json(&json!({"alias": alias}))
            .send()
    };
    assert_eq!(put("Bob's PC").await.unwrap().status(), 204);
    assert_eq!(put("Bob laptop").await.unwrap().status(), 204);
    assert_eq!(put("").await.unwrap().status(), 400);

    let list: Value = app
        .client
        .get(app.url("/v1/contacts"))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        list,
        json!([{"device_id": id, "alias": "Bob laptop", "online": false}])
    );

    let bob_list: Value = app
        .client
        .get(app.url("/v1/contacts"))
        .bearer_auth(&bob)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bob_list, json!([]));

    let res = app
        .client
        .delete(app.url(&path))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    let list: Value = app
        .client
        .get(app.url("/v1/contacts"))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list, json!([]));
}

#[sqlx::test(migrations = "./migrations")]
async fn put_contact_unknown_device_404(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let res = app
        .client
        .put(app.url("/v1/contacts/123456789"))
        .bearer_auth(&alice)
        .json(&json!({"alias": "ghost"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[sqlx::test(migrations = "./migrations")]
async fn presence_query_offline_and_unknown_404(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let a = register_ok(&app, &alice, &fingerprint(1), None).await;
    let id = a["device_id"].as_str().unwrap();
    let res = app
        .client
        .get(app.url(&format!("/v1/presence/{id}")))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body, json!({"device_id": id, "online": false}));
    let res = app
        .client
        .get(app.url("/v1/presence/123456789"))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let res = app
        .client
        .get(app.url("/v1/presence/abc"))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[sqlx::test(migrations = "./migrations")]
async fn device_routes_require_auth(pool: PgPool) {
    let app = common::spawn(pool).await;
    let checks = [
        app.client.get(app.url("/v1/devices")),
        app.client
            .post(app.url("/v1/devices"))
            .json(&json!({"fingerprint_hash": fingerprint(1), "name": "x"})),
        app.client.delete(app.url("/v1/devices/123456789")),
        app.client.get(app.url("/v1/contacts")),
        app.client
            .put(app.url("/v1/contacts/123456789"))
            .json(&json!({"alias": "x"})),
        app.client.delete(app.url("/v1/contacts/123456789")),
        app.client.get(app.url("/v1/presence/123456789")),
    ];
    for req in checks {
        assert_eq!(req.send().await.unwrap().status(), 401);
    }
}

/// Calls `PUT /v1/devices/{id}/public-key` for `token` with `key`.
async fn put_key(app: &TestApp, token: &str, id: &str, key: &str) -> reqwest::Response {
    app.client
        .put(app.url(&format!("/v1/devices/{id}/public-key")))
        .bearer_auth(token)
        .json(&json!({"public_key": key}))
        .send()
        .await
        .unwrap()
}

/// Returns the presence body of device `id` as seen by `token`.
async fn presence_of(app: &TestApp, token: &str, id: &str) -> Value {
    let res = app
        .client
        .get(app.url(&format!("/v1/presence/{id}")))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    res.json().await.unwrap()
}

/// Standard base64 of 32 bytes of `b`.
fn b64_key(b: u8) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode([b; 32])
}

#[sqlx::test(migrations = "./migrations")]
async fn public_key_set_and_returned_on_presence(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let bob = app.register_and_login("bob").await;
    let (id, _) = app.new_device(&alice, &fingerprint(1)).await;
    assert_eq!(put_key(&app, &alice, &id, &b64_key(5)).await.status(), 204);
    assert_eq!(presence_of(&app, &bob, &id).await["public_key"], b64_key(5).as_str());
    assert_eq!(put_key(&app, &alice, &id, &b64_key(6)).await.status(), 204);
    assert_eq!(presence_of(&app, &bob, &id).await["public_key"], b64_key(6).as_str());
}

#[sqlx::test(migrations = "./migrations")]
async fn public_key_rejects_wrong_length(pool: PgPool) {
    use base64::Engine;
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let (id, _) = app.new_device(&alice, &fingerprint(1)).await;
    let short = base64::engine::general_purpose::STANDARD.encode([1u8; 31]);
    assert_eq!(put_key(&app, &alice, &id, &short).await.status(), 400);
    assert_eq!(put_key(&app, &alice, &id, "not base64!").await.status(), 400);
}

#[sqlx::test(migrations = "./migrations")]
async fn public_key_of_other_account_forbidden(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let bob = app.register_and_login("bob").await;
    let (id, _) = app.new_device(&alice, &fingerprint(1)).await;
    assert_eq!(put_key(&app, &bob, &id, &b64_key(5)).await.status(), 403);
    assert_eq!(put_key(&app, &bob, "123456789", &b64_key(5)).await.status(), 404);
    assert!(presence_of(&app, &alice, &id).await.get("public_key").is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn presence_without_key_omits_field(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let (id, _) = app.new_device(&alice, &fingerprint(1)).await;
    let body = presence_of(&app, &alice, &id).await;
    assert!(body.get("public_key").is_none(), "{body}");
}
