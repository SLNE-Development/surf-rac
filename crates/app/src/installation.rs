//! Where an installation keeps its device ID, identity key and device name.

use std::io;

use crate::store::{InstallationState, Store};

/// Storage of this installation's registration.
///
/// A portable copy keeps it in the per-user state file ([`PortableStore`]).
pub trait InstallationStore: Send + Sync {
    /// Returns the stored installation, or `None` when there is none or it cannot be read.
    fn load(&self) -> Option<InstallationState>;

    /// Stores `state`, replacing any stored installation.
    fn save(&self, state: &InstallationState) -> io::Result<()>;

    /// Removes the stored installation.
    fn clear(&self) -> io::Result<()>;
}

/// An installation store in the per-user state file, protected with the
/// data protection API in user scope.
#[derive(Debug, Clone)]
pub struct PortableStore {
    /// The state file holding the installation.
    store: Store,
}

impl PortableStore {
    /// Creates a store that keeps the installation in `store`'s state file.
    pub fn new(store: Store) -> PortableStore {
        PortableStore { store }
    }
}

impl InstallationStore for PortableStore {
    /// Returns the installation of the state file.
    fn load(&self) -> Option<InstallationState> {
        self.store.state().installation
    }

    /// Writes `state` into the state file.
    fn save(&self, state: &InstallationState) -> io::Result<()> {
        self.store.update(|s| s.installation = Some(state.clone()))
    }

    /// Removes the installation from the state file.
    fn clear(&self) -> io::Result<()> {
        self.store.update(|s| s.installation = None)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use surf_rac_protocol::DeviceId;

    use super::*;
    use crate::store::{InstallationState, Secret, Store};

    /// Returns a fresh, empty directory for one test.
    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "surf-rac-inst-{name}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Returns an installation with fixed test values.
    fn installation() -> InstallationState {
        InstallationState {
            device_id: DeviceId::new(123_456_789).unwrap(),
            identity_key: Secret::new("key"),
            name: "laptop".into(),
        }
    }

    #[test]
    fn portable_store_saves_loads_and_clears_through_the_state_file() {
        let dir = temp_dir("portable");
        let store = Store::open(dir.clone());
        store.update(|s| s.settings.unattended = true).unwrap();
        let portable = PortableStore::new(store.clone());
        assert!(portable.load().is_none());
        portable.save(&installation()).unwrap();
        assert_eq!(portable.load(), Some(installation()));
        assert_eq!(
            PortableStore::new(Store::open(dir.clone())).load(),
            Some(installation())
        );
        portable.clear().unwrap();
        assert!(portable.load().is_none());
        let reloaded = Store::open(dir);
        assert!(reloaded.state().installation.is_none());
        assert!(reloaded.state().settings.unattended);
    }
}
