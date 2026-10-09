//! This installation's identity: its Ed25519 identity key and the device ID
//! the server bound to it.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use surf_rac_protocol::DeviceId;
use surf_rac_session::IdentityKey;

use crate::api::ApiError;
use crate::installation::InstallationStore;
use crate::store::{InstallationState, Secret};

/// Longest device name the server accepts.
const MAX_NAME_CHARS: usize = 64;

/// A registered installation with its identity key.
#[derive(Clone)]
pub struct Identity {
    /// The device ID the server assigned.
    pub id: DeviceId,
    /// The installation's identity key.
    pub key: Arc<IdentityKey>,
    /// The device name the installation registered with.
    pub name: String,
}

impl std::fmt::Debug for Identity {
    /// Writes the ID, name and public key, never the secret key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("public", &self.key.public())
            .finish()
    }
}

impl Identity {
    /// Restores an identity from its stored installation; `None` when the
    /// stored key is not base64 of 32 bytes.
    pub fn from_installation(state: &InstallationState) -> Option<Identity> {
        let bytes: [u8; 32] = STANDARD
            .decode(state.identity_key.expose())
            .ok()?
            .try_into()
            .ok()?;
        Some(Identity {
            id: state.device_id,
            key: Arc::new(IdentityKey::from_bytes(bytes)),
            name: state.name.clone(),
        })
    }

    /// Returns the installation record that stores this identity.
    pub fn to_installation(&self) -> InstallationState {
        InstallationState {
            device_id: self.id,
            identity_key: Secret::new(STANDARD.encode(self.key.to_bytes())),
            name: self.name.clone(),
        }
    }
}

/// Why no identity could be set up.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The server refused the registration or could not be reached.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// The installation store could not be changed.
    #[error("the installation could not be stored: {0}")]
    Store(String),
}

/// An identity that is ready to use.
#[derive(Debug, Clone)]
pub struct Ready {
    /// The loaded or newly registered identity.
    pub identity: Identity,
    /// Why the installation store could not be written, when the identity was
    /// newly registered but not stored; `None` when it is stored.
    pub unsaved: Option<String>,
}

impl Ready {
    /// Returns a stored identity that is ready to use.
    fn stored(identity: Identity) -> Ready {
        Ready {
            identity,
            unsaved: None,
        }
    }
}

/// Something that registers an installation's identity key with the server.
pub trait Registrar {
    /// Registers `identity` with `fingerprint_hash` and `name` and returns the device ID.
    fn register_device(
        &self,
        identity: &IdentityKey,
        fingerprint_hash: &str,
        name: &str,
    ) -> impl Future<Output = Result<DeviceId, ApiError>> + Send;
}

/// Returns the name this device registers with: the computer name, at most 64 characters.
pub fn device_name() -> String {
    let name = std::env::var("COMPUTERNAME").unwrap_or_default();
    let name: String = name.trim().chars().take(MAX_NAME_CHARS).collect();
    if name.is_empty() {
        "Windows PC".into()
    } else {
        name
    }
}

/// Returns the stored identity, or registers a new installation when none is stored.
///
/// A new installation gets a fresh identity key; it is stored only after the
/// server assigned an ID. A stored installation is used as it is, without
/// contacting the server. A registered identity that could not be stored is
/// still returned, with the reason in [`Ready::unsaved`], so that the caller
/// can use it and store it later with [`save`] instead of registering again.
pub async fn ensure<R: Registrar>(
    store: &dyn InstallationStore,
    registrar: &R,
    fingerprint_hash: &str,
    name: &str,
) -> Result<Ready, IdentityError> {
    if let Some(identity) = store.load().as_ref().and_then(Identity::from_installation) {
        return Ok(Ready::stored(identity));
    }
    register(store, registrar, fingerprint_hash, name).await
}

/// Discards the stored installation and registers a new one with a fresh
/// identity key, as after the server reported a clone or an unknown ID.
///
/// Fails with [`IdentityError::Store`] when the stored installation cannot be
/// removed; a registered identity that cannot be stored is returned as in
/// [`ensure`].
pub async fn renew<R: Registrar>(
    store: &dyn InstallationStore,
    registrar: &R,
    fingerprint_hash: &str,
    name: &str,
) -> Result<Ready, IdentityError> {
    store
        .clear()
        .map_err(|e| IdentityError::Store(e.to_string()))?;
    register(store, registrar, fingerprint_hash, name).await
}

/// Writes `identity` to the installation store.
pub fn save(store: &dyn InstallationStore, identity: &Identity) -> Result<(), IdentityError> {
    store
        .save(&identity.to_installation())
        .map_err(|e| IdentityError::Store(e.to_string()))
}

/// Generates an identity key, registers it and stores the installation.
///
/// When storing fails, the registered identity is returned with the reason in
/// [`Ready::unsaved`].
async fn register<R: Registrar>(
    store: &dyn InstallationStore,
    registrar: &R,
    fingerprint_hash: &str,
    name: &str,
) -> Result<Ready, IdentityError> {
    let key = IdentityKey::generate();
    let id = registrar
        .register_device(&key, fingerprint_hash, name)
        .await?;
    let identity = Identity {
        id,
        key: Arc::new(key),
        name: name.to_string(),
    };
    tracing::info!(device_id = %id, "installation registered");
    if let Err(IdentityError::Store(reason)) = save(store, &identity) {
        tracing::error!(device_id = %id, error = %reason, "registered installation not stored");
        return Ok(Ready {
            identity,
            unsaved: Some(reason),
        });
    }
    Ok(Ready::stored(identity))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::installation::InstallationStore;
    use crate::store::InstallationState;

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

    /// A registrar that hands out IDs from 100000001 upwards and records each key it saw.
    #[derive(Default)]
    struct MockRegistrar {
        /// Public key, fingerprint hash and name of every registration.
        seen: Mutex<Vec<([u8; 32], String, String)>>,
    }

    impl Registrar for MockRegistrar {
        /// Records the registration and answers with the next ID.
        fn register_device(
            &self,
            identity: &IdentityKey,
            fingerprint_hash: &str,
            name: &str,
        ) -> impl Future<Output = Result<DeviceId, ApiError>> + Send {
            let mut seen = self.seen.lock().unwrap();
            seen.push((
                identity.public().to_bytes(),
                fingerprint_hash.to_string(),
                name.to_string(),
            ));
            let id = DeviceId::new(100_000_000 + seen.len() as u32).unwrap();
            async move { Ok(id) }
        }
    }

    const FINGERPRINT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[tokio::test]
    async fn ensure_registers_when_no_installation_is_stored() {
        let store = MemoryStore::default();
        let registrar = MockRegistrar::default();
        let identity = ensure(&store, &registrar, FINGERPRINT, "laptop")
            .await
            .unwrap()
            .identity;
        let seen = registrar.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, identity.key.public().to_bytes());
        assert_eq!(seen[0].1, FINGERPRINT);
        assert_eq!(seen[0].2, "laptop");
        let stored = store.load().unwrap();
        assert_eq!(stored.device_id, identity.id);
        assert_eq!(stored.name, "laptop");
        let restored = Identity::from_installation(&stored).unwrap();
        assert_eq!(restored.key.public(), identity.key.public());
    }

    #[tokio::test]
    async fn ensure_reuses_a_stored_installation_without_registering() {
        let store = MemoryStore::default();
        let registrar = MockRegistrar::default();
        let first = ensure(&store, &registrar, FINGERPRINT, "laptop")
            .await
            .unwrap()
            .identity;
        let second = ensure(&store, &registrar, FINGERPRINT, "laptop")
            .await
            .unwrap()
            .identity;
        assert_eq!(registrar.seen.lock().unwrap().len(), 1);
        assert_eq!(second.id, first.id);
        assert_eq!(second.key.public(), first.key.public());
    }

    #[tokio::test]
    async fn renew_discards_the_installation_and_registers_a_new_key() {
        let store = MemoryStore::default();
        let registrar = MockRegistrar::default();
        let old = ensure(&store, &registrar, FINGERPRINT, "laptop")
            .await
            .unwrap()
            .identity;
        let new = renew(&store, &registrar, FINGERPRINT, "laptop")
            .await
            .unwrap()
            .identity;
        assert_eq!(registrar.seen.lock().unwrap().len(), 2);
        assert_ne!(new.id, old.id);
        assert_ne!(new.key.public(), old.key.public());
        assert_eq!(store.load().unwrap().device_id, new.id);
    }

    #[tokio::test]
    async fn failed_registration_leaves_no_installation() {
        /// A registrar that refuses every registration.
        struct Refusing;
        impl Registrar for Refusing {
            /// Refuses every registration as from an outdated client.
            async fn register_device(
                &self,
                _identity: &IdentityKey,
                _fingerprint_hash: &str,
                _name: &str,
            ) -> Result<DeviceId, ApiError> {
                Err(ApiError::UpdateRequired)
            }
        }
        let store = MemoryStore::default();
        assert_eq!(
            ensure(&store, &Refusing, FINGERPRINT, "laptop").await.err(),
            Some(IdentityError::Api(ApiError::UpdateRequired))
        );
        assert!(store.load().is_none());
    }

    /// An installation store whose first `failures` writes fail.
    struct FailingStore {
        /// The installation that was written last.
        inner: MemoryStore,
        /// Writes that still fail.
        failures: Mutex<u32>,
    }

    impl InstallationStore for FailingStore {
        /// Returns the held installation.
        fn load(&self) -> Option<InstallationState> {
            self.inner.load()
        }
        /// Fails while failures remain, then replaces the held installation.
        fn save(&self, state: &InstallationState) -> std::io::Result<()> {
            let mut failures = self.failures.lock().unwrap();
            if *failures > 0 {
                *failures -= 1;
                return Err(std::io::Error::other("disk full"));
            }
            self.inner.save(state)
        }
        /// Drops the held installation.
        fn clear(&self) -> std::io::Result<()> {
            self.inner.clear()
        }
    }

    #[tokio::test]
    async fn registered_identity_that_cannot_be_stored_is_kept_and_saved_later() {
        let store = FailingStore {
            inner: MemoryStore::default(),
            failures: Mutex::new(3),
        };
        let registrar = MockRegistrar::default();
        let ready = ensure(&store, &registrar, FINGERPRINT, "laptop")
            .await
            .unwrap();
        assert!(ready.unsaved.as_deref().unwrap().contains("disk full"));
        assert!(store.load().is_none());
        for _ in 0..2 {
            assert!(matches!(
                save(&store, &ready.identity),
                Err(IdentityError::Store(_))
            ));
        }
        save(&store, &ready.identity).unwrap();
        assert_eq!(registrar.seen.lock().unwrap().len(), 1);
        let stored = Identity::from_installation(&store.load().unwrap()).unwrap();
        assert_eq!(stored.id, ready.identity.id);
        assert_eq!(stored.key.public(), ready.identity.key.public());
        let again = ensure(&store, &registrar, FINGERPRINT, "laptop")
            .await
            .unwrap();
        assert!(again.unsaved.is_none());
        assert_eq!(again.identity.id, ready.identity.id);
        assert_eq!(registrar.seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn stored_key_that_is_not_32_bytes_is_no_identity() {
        let state = InstallationState {
            device_id: DeviceId::new(123_456_789).unwrap(),
            identity_key: crate::store::Secret::new("AAAA"),
            name: "laptop".into(),
        };
        assert!(Identity::from_installation(&state).is_none());
    }

    #[test]
    fn device_name_is_bounded() {
        let name = device_name();
        assert!(!name.is_empty());
        assert!(name.chars().count() <= MAX_NAME_CHARS);
    }
}
