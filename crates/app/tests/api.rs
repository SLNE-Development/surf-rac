//! The app's installation registration, API client and account linking
//! against an in-process signaling server.

#[allow(clippy::collapsible_if)]
#[path = "../../session/tests/common/mod.rs"]
mod common;

use std::sync::Mutex;

use common::TestEnv;
use sqlx::PgPool;
use surf_rac_app::api::{Api, ApiError};
use surf_rac_app::installation::InstallationStore;
use surf_rac_app::runtime::account;
use surf_rac_app::runtime::identity;
use surf_rac_app::store::InstallationState;
use surf_rac_protocol::DeviceId;
use surf_rac_session::signaling::SignalingClient;

/// An installation store held in memory.
#[derive(Default)]
struct MemoryStore(Mutex<Option<InstallationState>>);

impl InstallationStore for MemoryStore {
    /// Returns the held installation.
    fn load(&self) -> Option<InstallationState> {
        self.0.lock().unwrap().clone()
    }
    /// Replaces the held installation.
    fn save(&self, state: &InstallationState) -> std::io::Result<()> {
        *self.0.lock().unwrap() = Some(state.clone());
        Ok(())
    }
    /// Drops the held installation.
    fn clear(&self) -> std::io::Result<()> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

const FINGERPRINT: &str = "00000000000000000000000000000000000000000000000000000000000000a7";

#[sqlx::test(migrations = "../server/migrations")]
async fn installation_links_to_an_account_and_unlinks_on_sign_out(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let api = Api::new(&env.http);

    let store = MemoryStore::default();
    let me = identity::ensure(&store, &api, FINGERPRINT, "laptop")
        .await
        .unwrap();
    let again = identity::ensure(&store, &api, FINGERPRINT, "laptop")
        .await
        .unwrap();
    assert_eq!(again.id, me.id);

    let signaling = SignalingClient::connect(&api.ws_url(), me.id, &me.key, FINGERPRINT)
        .await
        .expect("connect without an account");

    api.register("alice", "correct horse battery")
        .await
        .unwrap();
    assert!(matches!(
        api.register("alice", "correct horse battery").await,
        Err(ApiError::Conflict(_))
    ));
    assert_eq!(
        api.login("alice", "wrong password!").await,
        Err(ApiError::Unauthorized)
    );
    let token = api.login("alice", "correct horse battery").await.unwrap();
    let alice = api.with_token(Some(token.clone()));

    assert_eq!(
        account::link(&signaling, "not-a-token").await,
        Err(account::LinkError::Rejected)
    );
    assert_eq!(account::link(&signaling, &token).await, Ok("alice".into()));
    let devices = alice.my_devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, me.id);
    assert_eq!(devices[0].name, "laptop");
    assert!(devices[0].online);

    let other = env.device("bob", 2).await;
    alice.put_contact(other.id, "Bob's PC").await.unwrap();
    let contacts = alice.contacts().await.unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].alias, "Bob's PC");
    assert!(contacts[0].online);
    assert!(alice.presence(other.id).await.unwrap().online);
    alice.delete_contact(other.id).await.unwrap();
    assert!(alice.contacts().await.unwrap().is_empty());
    let unknown = DeviceId::new(999_999_998).unwrap();
    assert!(alice.presence(unknown).await.is_err());

    account::sign_out(Some(&signaling), &alice).await;
    assert_eq!(alice.my_devices().await, Err(ApiError::Unauthorized));
    let token = api.login("alice", "correct horse battery").await.unwrap();
    let alice = api.with_token(Some(token));
    assert!(alice.my_devices().await.unwrap().is_empty());

    assert!(matches!(
        alice.delete_account("wrong password!").await,
        Err(ApiError::Unauthorized)
    ));
    alice.delete_account("correct horse battery").await.unwrap();
    assert_eq!(
        api.login("alice", "correct horse battery").await,
        Err(ApiError::Unauthorized)
    );
}

#[sqlx::test(migrations = "../server/migrations")]
async fn unknown_device_is_renewed_with_a_fresh_registration(pool: PgPool) {
    let env = TestEnv::start(pool.clone()).await;
    let api = Api::new(&env.http);
    let store = MemoryStore::default();
    let me = identity::ensure(&store, &api, FINGERPRINT, "laptop")
        .await
        .unwrap();
    sqlx::query("delete from devices")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        SignalingClient::connect(&api.ws_url(), me.id, &me.key, FINGERPRINT).await,
        Err(surf_rac_session::signaling::SignalingError::UnknownDevice)
    ));
    let renewed = identity::renew(&store, &api, FINGERPRINT, "laptop")
        .await
        .unwrap();
    assert_ne!(renewed.key.public(), me.key.public());
    SignalingClient::connect(&api.ws_url(), renewed.id, &renewed.key, FINGERPRINT)
        .await
        .expect("renewed installation connects");
}
