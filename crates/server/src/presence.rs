//! Pushing online/offline changes to the devices that watch a device.

use surf_rac_protocol::{DeviceId, ServerMessage};

use crate::contacts;
use crate::devices::{self, device_id};
use crate::state::AppState;

/// Sends `presence` for `device` to every online device of its watchers.
///
/// Watchers are the device's owner and every account that has it as a
/// contact; the device itself is skipped. Database errors are logged and the
/// broadcast is dropped.
pub async fn broadcast(state: &AppState, device: DeviceId, online: bool) {
    let watchers = match contacts::watchers(&state.db, device).await {
        Ok(w) => w,
        Err(err) => {
            tracing::warn!(error = %err, device_id = %device, "presence broadcast skipped");
            return;
        }
    };
    broadcast_to(state, &watchers, device, online).await;
}

/// Sends `presence` for `device` to every online device of the users in `watchers`.
///
/// Used when the watchers must be read before the device is deleted.
pub async fn broadcast_to(state: &AppState, watchers: &[i64], device: DeviceId, online: bool) {
    for &user_id in watchers {
        let rows = match devices::list(&state.db, user_id).await {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!(error = %err, "presence broadcast partly skipped");
                continue;
            }
        };
        for row in rows {
            let target = device_id(row.id);
            if target != device {
                state.hub.send(
                    target,
                    ServerMessage::Presence {
                        device_id: device,
                        online,
                    },
                );
            }
        }
    }
}

/// Runs [`broadcast`] in the background.
pub fn spawn_broadcast(state: &AppState, device: DeviceId, online: bool) {
    let state = state.clone();
    tokio::spawn(async move { broadcast(&state, device, online).await });
}
