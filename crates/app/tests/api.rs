//! The app's API client against an in-process signaling server.

#[path = "../../session/tests/common/mod.rs"]
mod common;

use common::TestEnv;
use sqlx::PgPool;
use surf_rac_app::api::{Api, ApiError};
use surf_rac_protocol::DeviceId;

/// Creates a single-use invite code in the test database.
async fn invite(env: &TestEnv) -> String {
    surf_rac_server::accounts::create_invite(&env.pool, "test", chrono::Duration::hours(1))
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../server/migrations")]
async fn account_device_and_contacts(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let api = Api::new(&env.http);

    let code = invite(&env).await;
    api.register(&code, "alice", "correct horse battery").await.unwrap();
    assert!(matches!(
        api.register(&code, "alice2", "correct horse battery").await,
        Err(ApiError::Invalid(_) | ApiError::Unauthorized | ApiError::Conflict(_))
    ));
    assert_eq!(api.login("alice", "wrong password!").await, Err(ApiError::Unauthorized));
    let token = api.login("alice", "correct horse battery").await.unwrap();
    let api = api.with_token(Some(token));

    let fingerprint = format!("{:064x}", 7);
    let device = api.register_device(&fingerprint, "laptop", None).await.unwrap();
    assert!(!device.rebound);
    let again = api
        .register_device(&fingerprint, "laptop", Some(device.device_id))
        .await
        .unwrap();
    assert_eq!(again.device_id, device.device_id);

    let key = surf_rac_session::DeviceKeys::generate().public_key().to_base64();
    api.put_public_key(device.device_id, &key).await.unwrap();
    let presence = api.presence(device.device_id).await.unwrap();
    assert_eq!(presence.public_key.as_deref(), Some(key.as_str()));

    let devices = api.devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, "laptop");

    let other = env.device("bob", 2).await;
    api.put_contact(other.id, "Bob's PC").await.unwrap();
    let contacts = api.contacts().await.unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].alias, "Bob's PC");
    assert!(contacts[0].online);
    api.delete_contact(other.id).await.unwrap();
    assert!(api.contacts().await.unwrap().is_empty());

    let unknown = DeviceId::new(999_999_998).unwrap();
    assert!(api.presence(unknown).await.is_err());

    api.logout().await.unwrap();
    assert_eq!(api.devices().await, Err(ApiError::Unauthorized));
}
