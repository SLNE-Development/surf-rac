//! Trust-on-first-use pinning of peer identity keys.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use surf_rac_protocol::DeviceId;

use crate::crypto::IdentityPublic;

/// The identity keys this device has pinned for its peers; serializable for storage.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnownKeys {
    /// Pinned key per peer device.
    keys: BTreeMap<DeviceId, IdentityPublic>,
}

/// A peer presented an identity key that differs from the pinned one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("identity key of device {device_id} changed")]
pub struct KeyChanged {
    /// The peer device.
    pub device_id: DeviceId,
    /// Fingerprint of the pinned key.
    pub old_fingerprint: String,
    /// Fingerprint of the presented key.
    pub new_fingerprint: String,
}

impl KnownKeys {
    /// Accepts `key` for `device` if it matches the pinned key, pinning it on first contact.
    ///
    /// Returns [`KeyChanged`] when a different key is pinned; the pin is left unchanged.
    pub fn check(&mut self, device: DeviceId, key: &IdentityPublic) -> Result<(), KeyChanged> {
        match self.keys.get(&device) {
            None => {
                self.keys.insert(device, *key);
                Ok(())
            }
            Some(pinned) if pinned == key => Ok(()),
            Some(pinned) => Err(KeyChanged {
                device_id: device,
                old_fingerprint: pinned.fingerprint(),
                new_fingerprint: key.fingerprint(),
            }),
        }
    }

    /// Pins `key` for `device`, replacing any earlier pin.
    pub fn trust_key(&mut self, device: DeviceId, key: IdentityPublic) {
        self.keys.insert(device, key);
    }

    /// Returns every pinned device and its key.
    pub fn entries(&self) -> impl Iterator<Item = (DeviceId, IdentityPublic)> + '_ {
        self.keys.iter().map(|(device, key)| (*device, *key))
    }

    /// Returns the key pinned for `device`, if any.
    pub fn get(&self, device: DeviceId) -> Option<&IdentityPublic> {
        self.keys.get(&device)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentityKey;

    /// Returns a fixed test device ID.
    fn id() -> DeviceId {
        DeviceId::new(123_456_789).unwrap()
    }

    /// The first key seen for a device is pinned, a different key is reported as a
    /// change with both fingerprints, and after trusting the new key the old one is
    /// refused.
    #[test]
    fn pinning_tofu_then_change_then_trust() {
        let mut known = KnownKeys::default();
        let (k1, k2) = (
            IdentityKey::generate().public(),
            IdentityKey::generate().public(),
        );
        known.check(id(), &k1).unwrap();
        known.check(id(), &k1).unwrap();
        let err = known.check(id(), &k2).unwrap_err();
        assert_eq!(err.device_id, id());
        assert_eq!(err.old_fingerprint, k1.fingerprint());
        assert_eq!(err.new_fingerprint, k2.fingerprint());
        assert_eq!(known.get(id()), Some(&k1));
        known.trust_key(id(), k2);
        known.check(id(), &k2).unwrap();
        assert!(known.check(id(), &k1).is_err());
    }

    /// Pinned keys survive a JSON round trip.
    #[test]
    fn known_keys_serde_round_trip() {
        let mut known = KnownKeys::default();
        known.trust_key(id(), IdentityKey::generate().public());
        let json = serde_json::to_string(&known).unwrap();
        let back: KnownKeys = serde_json::from_str(&json).unwrap();
        assert_eq!(back, known);
    }
}
