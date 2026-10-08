//! Trust-on-first-use pinning of peer device public keys.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use surf_rac_protocol::DeviceId;

use crate::crypto::PublicKey;

/// The public keys this device has pinned for its peers; serializable for storage.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnownKeys {
    /// Pinned key per peer device.
    keys: BTreeMap<DeviceId, PublicKey>,
}

/// A peer presented a public key that differs from the pinned one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("public key of device {device_id} changed")]
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
    pub fn check(&mut self, device: DeviceId, key: &PublicKey) -> Result<(), KeyChanged> {
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
    pub fn trust_key(&mut self, device: DeviceId, key: PublicKey) {
        self.keys.insert(device, key);
    }

    /// Returns the key pinned for `device`, if any.
    pub fn get(&self, device: DeviceId) -> Option<&PublicKey> {
        self.keys.get(&device)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DeviceKeys;

    fn id() -> DeviceId {
        DeviceId::new(123_456_789).unwrap()
    }

    #[test]
    fn pinning_tofu_then_change_then_trust() {
        let mut known = KnownKeys::default();
        let (k1, k2) = (
            DeviceKeys::generate().public_key(),
            DeviceKeys::generate().public_key(),
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

    #[test]
    fn known_keys_serde_round_trip() {
        let mut known = KnownKeys::default();
        known.trust_key(id(), DeviceKeys::generate().public_key());
        let json = serde_json::to_string(&known).unwrap();
        let back: KnownKeys = serde_json::from_str(&json).unwrap();
        assert_eq!(back, known);
    }
}
