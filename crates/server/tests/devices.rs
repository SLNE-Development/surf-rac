//! Device registration tests.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{fingerprint, identity_key, public_key_b64, sign_registration};
use serde_json::{Value, json};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn register_returns_9_digit_id_without_account(pool: PgPool) {
    let app = common::spawn(pool).await;
    let key = identity_key();
    let res = app.register_device(&key, &fingerprint(1), "pc").await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let id = body["device_id"].as_str().unwrap();
    assert_eq!(id.len(), 9);
    assert!(id.bytes().all(|b| b.is_ascii_digit()) && !id.starts_with('0'));
    let (stored_key, fp, name): (Vec<u8>, String, String) =
        sqlx::query_as("select public_key, fingerprint_hash, name from devices")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(stored_key, key.verifying_key().as_bytes());
    assert_eq!(fp, fingerprint(1));
    assert_eq!(name, "pc");
}

#[sqlx::test(migrations = "./migrations")]
async fn distinct_keys_get_distinct_ids(pool: PgPool) {
    let app = common::spawn(pool).await;
    let a = app.new_device(1).await;
    let b = app.new_device(1).await;
    assert_ne!(a.id, b.id);
}

#[sqlx::test(migrations = "./migrations")]
async fn same_key_and_fingerprint_returns_existing_id_and_updates_name(pool: PgPool) {
    let app = common::spawn(pool).await;
    let key = identity_key();
    let first: Value = app
        .register_device(&key, &fingerprint(1), "old name")
        .await
        .json()
        .await
        .unwrap();
    let res = app.register_device(&key, &fingerprint(1), "new name").await;
    assert_eq!(res.status(), 200);
    let second: Value = res.json().await.unwrap();
    assert_eq!(first["device_id"], second["device_id"]);
    let rows: Vec<(String,)> = sqlx::query_as("select name from devices")
        .fetch_all(&app.pool)
        .await
        .unwrap();
    assert_eq!(rows, vec![("new name".to_owned(),)]);
}

#[sqlx::test(migrations = "./migrations")]
async fn same_key_other_fingerprint_is_clone_detected_and_never_rebinds(pool: PgPool) {
    let app = common::spawn(pool).await;
    let key = identity_key();
    let first: Value = app
        .register_device(&key, &fingerprint(1), "pc")
        .await
        .json()
        .await
        .unwrap();
    let res = app.register_device(&key, &fingerprint(2), "clone").await;
    assert_eq!(res.status(), 409);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "clone_detected");
    let rows: Vec<(i64, String, String)> =
        sqlx::query_as("select id, fingerprint_hash, name from devices")
            .fetch_all(&app.pool)
            .await
            .unwrap();
    let id: i64 = first["device_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(rows, vec![(id, fingerprint(1), "pc".to_owned())]);
}

#[sqlx::test(migrations = "./migrations")]
async fn wrong_protocol_version_is_update_required(pool: PgPool) {
    let app = common::spawn(pool).await;
    let key = identity_key();
    for version in [1, 3] {
        let res = app
            .register_device_raw(json!({
                "public_key": public_key_b64(&key),
                "fingerprint_hash": fingerprint(1),
                "name": "pc",
                "signature": sign_registration(&key, &key, &fingerprint(1), "pc"),
                "protocol_version": version,
            }))
            .await;
        assert_eq!(res.status(), 426, "version {version}");
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["error"], "update_required");
    }
    let count: i64 = sqlx::query_scalar("select count(*) from devices")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_registration_input_400(pool: PgPool) {
    let app = common::spawn(pool).await;
    let good_key = public_key_b64(&identity_key());
    let weak_key = STANDARD.encode([0u8; 32]);
    let short_key = STANDARD.encode([7u8; 31]);
    let sig = STANDARD.encode([1u8; 64]);
    let cases = [
        json!({"public_key": good_key, "fingerprint_hash": "xyz", "name": "pc", "signature": sig, "protocol_version": 2}),
        json!({"public_key": good_key, "fingerprint_hash": "AB".repeat(32), "name": "pc", "signature": sig, "protocol_version": 2}),
        json!({"public_key": good_key, "fingerprint_hash": fingerprint(1), "name": "", "signature": sig, "protocol_version": 2}),
        json!({"public_key": good_key, "fingerprint_hash": fingerprint(1), "name": "x".repeat(65), "signature": sig, "protocol_version": 2}),
        json!({"public_key": "not base64!", "fingerprint_hash": fingerprint(1), "name": "pc", "signature": sig, "protocol_version": 2}),
        json!({"public_key": short_key, "fingerprint_hash": fingerprint(1), "name": "pc", "signature": sig, "protocol_version": 2}),
        json!({"public_key": weak_key, "fingerprint_hash": fingerprint(1), "name": "pc", "signature": sig, "protocol_version": 2}),
        json!({"fingerprint_hash": fingerprint(1), "name": "pc", "signature": sig, "protocol_version": 2}),
    ];
    for body in cases {
        let res = app.register_device_raw(body.clone()).await;
        assert_eq!(res.status(), 400, "{body}");
        let err: Value = res.json().await.unwrap();
        assert_eq!(err["error"], "bad_request", "{body}");
    }
    let count: i64 = sqlx::query_scalar("select count(*) from devices")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_registration_of_one_key_creates_one_device(pool: PgPool) {
    let app = common::spawn(pool).await;
    let key = identity_key();
    let fp = fingerprint(1);
    let (a, b) = tokio::join!(
        app.register_device(&key, &fp, "pc"),
        app.register_device(&key, &fp, "pc"),
    );
    assert_eq!(a.status(), 200);
    assert_eq!(b.status(), 200);
    let a: Value = a.json().await.unwrap();
    let b: Value = b.json().await.unwrap();
    assert_eq!(a["device_id"], b["device_id"]);
    let count: i64 = sqlx::query_scalar("select count(*) from devices")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn identity_key_lookup_returns_registered_key(pool: PgPool) {
    let app = common::spawn(pool).await;
    let dev = app.new_device(1).await;
    let id: surf_rac_protocol::DeviceId = dev.id.parse().unwrap();
    let key = surf_rac_server::devices::identity_key(&app.pool, id)
        .await
        .unwrap();
    assert_eq!(key, Some(*dev.key.verifying_key().as_bytes()));
    let unknown = surf_rac_server::devices::identity_key(
        &app.pool,
        surf_rac_protocol::DeviceId::new(123_456_789).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(unknown, None);
}

/// Counts the rows of the devices table.
async fn device_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("select count(*) from devices")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn registration_without_signature_is_unauthorized_and_writes_nothing(pool: PgPool) {
    let app = common::spawn(pool).await;
    let key = identity_key();
    let res = app
        .register_device_raw(json!({
            "public_key": public_key_b64(&key),
            "fingerprint_hash": fingerprint(1),
            "name": "pc",
            "protocol_version": surf_rac_protocol::PROTOCOL_VERSION,
        }))
        .await;
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "bad_signature");
    assert_eq!(device_count(&app.pool).await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn registration_with_wrong_signature_is_unauthorized_and_writes_nothing(pool: PgPool) {
    let app = common::spawn(pool).await;
    let key = identity_key();
    let other = identity_key();
    let fp = fingerprint(1);
    let by_other_key = sign_registration(&other, &key, &fp, "pc");
    let over_other_name = sign_registration(&key, &key, &fp, "other");
    let over_other_fingerprint = sign_registration(&key, &key, &fingerprint(2), "pc");
    let malformed = STANDARD.encode([1u8; 10]);
    for signature in [
        by_other_key,
        over_other_name,
        over_other_fingerprint,
        malformed,
    ] {
        let res = app
            .register_device_signed(&key, &fp, "pc", &signature)
            .await;
        assert_eq!(res.status(), 401, "{signature}");
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["error"], "bad_signature");
    }
    assert_eq!(device_count(&app.pool).await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn renaming_needs_a_valid_signature(pool: PgPool) {
    let app = common::spawn(pool).await;
    let key = identity_key();
    let fp = fingerprint(1);
    assert_eq!(app.register_device(&key, &fp, "old").await.status(), 200);
    let forged = sign_registration(&identity_key(), &key, &fp, "new");
    let res = app.register_device_signed(&key, &fp, "new", &forged).await;
    assert_eq!(res.status(), 401);
    let reused = sign_registration(&key, &key, &fp, "old");
    let res = app.register_device_signed(&key, &fp, "new", &reused).await;
    assert_eq!(res.status(), 401);
    let name: String = sqlx::query_scalar("select name from devices")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(name, "old");
    assert_eq!(app.register_device(&key, &fp, "new").await.status(), 200);
    let name: String = sqlx::query_scalar("select name from devices")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(name, "new");
}

#[sqlx::test(migrations = "./migrations")]
async fn registration_is_limited_per_ip_including_re_registration(pool: PgPool) {
    let app = common::spawn(pool).await;
    let key = identity_key();
    for i in 0..5 {
        let res = app
            .register_device_from(&key, &fingerprint(1), &format!("pc{i}"), "10.9.0.1")
            .await;
        assert_eq!(res.status(), 200, "attempt {i}");
    }
    let res = app
        .register_device_from(&key, &fingerprint(1), "pc", "10.9.0.1")
        .await;
    assert_eq!(res.status(), 429);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "rate_limited");
    let other = app
        .register_device_from(&identity_key(), &fingerprint(2), "pc", "10.9.0.2")
        .await;
    assert_eq!(other.status(), 200);
}

#[sqlx::test(migrations = "./migrations")]
async fn registration_limit_shares_one_ipv6_64_prefix(pool: PgPool) {
    let app = common::spawn(pool).await;
    for i in 0..5 {
        let ip = format!("2001:db8:1:2::{}", i + 1);
        let res = app
            .register_device_from(&identity_key(), &fingerprint(i), "pc", &ip)
            .await;
        assert_eq!(res.status(), 200);
    }
    let res = app
        .register_device_from(
            &identity_key(),
            &fingerprint(9),
            "pc",
            "2001:db8:1:2:ffff::9",
        )
        .await;
    assert_eq!(res.status(), 429);
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_registration_bodies_do_not_use_the_limit(pool: PgPool) {
    let app = common::spawn(pool).await;
    for _ in 0..8 {
        let res = app
            .register_device_from(&identity_key(), "not-a-fingerprint", "pc", "10.9.0.3")
            .await;
        assert_eq!(res.status(), 400);
    }
    let res = app
        .register_device_from(&identity_key(), &fingerprint(1), "pc", "10.9.0.3")
        .await;
    assert_eq!(res.status(), 200);
}
