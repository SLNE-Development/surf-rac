//! Pushing online/offline changes to the devices that watch a device.

use surf_rac_protocol::{DeviceId, ServerMessage};

use crate::contacts;
use crate::devices::device_id;
use crate::state::AppState;

/// Sends `presence` for `device` to every online device linked to one of its watchers.
///
/// Watchers are the accounts linked to the device and every account that has
/// it as a contact. Each receiving device gets the message once, even when it
/// is linked to several watchers; the device itself is skipped. Database
/// errors are logged and the broadcast is dropped.
pub async fn broadcast(state: &AppState, device: DeviceId, online: bool) {
    let targets = match contacts::watcher_devices(&state.db, device).await {
        Ok(t) => t,
        Err(err) => {
            tracing::warn!(error = %err, device_id = %device, "presence broadcast skipped");
            return;
        }
    };
    for target in targets {
        state.hub.send(
            device_id(target),
            ServerMessage::Presence {
                device_id: device,
                online,
            },
        );
    }
}

/// Runs [`broadcast`] in the background.
pub fn spawn_broadcast(state: &AppState, device: DeviceId, online: bool) {
    let state = state.clone();
    tokio::spawn(async move { broadcast(&state, device, online).await });
}
