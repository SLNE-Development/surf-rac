//! This device's identity: its registration with the server and its X25519 key.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use surf_rac_protocol::DeviceId;
use surf_rac_session::DeviceKeys;

use crate::api::{Api, ApiError};
use crate::fingerprint;
use crate::store::{Secret, State};

/// Longest device name the server accepts.
const MAX_NAME_CHARS: usize = 64;

/// A registered device with its secret and key pair.
#[derive(Clone)]
pub struct Identity {
    /// The device ID.
    pub id: DeviceId,
    /// The device secret for the WebSocket.
    pub secret: Secret,
    /// The device's key pair.
    pub keys: Arc<DeviceKeys>,
}

impl Identity {
    /// Returns the stored identity when the state holds a complete one.
    pub fn from_state(state: &State) -> Option<Identity> {
        Some(Identity {
            id: state.device_id?,
            secret: state.device_secret.clone()?,
            keys: Arc::new(keys_from(state.device_key.as_ref()?)?),
        })
    }

    /// Writes the identity into `state`.
    pub fn store(&self, state: &mut State) {
        state.device_id = Some(self.id);
        state.device_secret = Some(self.secret.clone());
        state.device_key = Some(Secret::new(STANDARD.encode(self.keys.secret_bytes())));
    }
}

/// Restores a key pair from its stored base64 secret.
fn keys_from(secret: &Secret) -> Option<DeviceKeys> {
    let bytes: [u8; 32] = STANDARD.decode(secret.expose()).ok()?.try_into().ok()?;
    Some(DeviceKeys::from_secret_bytes(bytes))
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

/// Registers this machine with the account behind `api`, re-binding the
/// stored device ID when there is one, and publishes the device's public key.
///
/// The stored key pair is kept; a new one is generated when none is stored.
/// When the stored ID cannot be re-bound, a new device is registered.
pub async fn register(api: &Api, state: &State) -> Result<Identity, String> {
    let fingerprint = fingerprint::fingerprint_hash().map_err(|e| e.to_string())?;
    let name = device_name();
    let response = match api
        .register_device(&fingerprint, &name, state.device_id)
        .await
    {
        Err(ApiError::NotFound | ApiError::Invalid(_)) if state.device_id.is_some() => {
            api.register_device(&fingerprint, &name, None).await
        }
        other => other,
    }
    .map_err(|e| e.user_message())?;
    let keys = state
        .device_key
        .as_ref()
        .and_then(keys_from)
        .unwrap_or_else(DeviceKeys::generate);
    api.put_public_key(response.device_id, &keys.public_key().to_base64())
        .await
        .map_err(|e| e.user_message())?;
    Ok(Identity {
        id: response.device_id,
        secret: Secret::new(response.device_secret),
        keys: Arc::new(keys),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trips_through_state() {
        let identity = Identity {
            id: DeviceId::new(123_456_789).unwrap(),
            secret: Secret::new("s3cret"),
            keys: Arc::new(DeviceKeys::generate()),
        };
        let mut state = State::default();
        assert!(Identity::from_state(&state).is_none());
        identity.store(&mut state);
        let restored = Identity::from_state(&state).unwrap();
        assert_eq!(restored.id, identity.id);
        assert_eq!(restored.secret, identity.secret);
        assert_eq!(restored.keys.public_key(), identity.keys.public_key());
    }

    #[test]
    fn device_name_is_bounded() {
        let name = device_name();
        assert!(!name.is_empty());
        assert!(name.chars().count() <= MAX_NAME_CHARS);
    }
}
