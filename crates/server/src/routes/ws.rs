//! WebSocket upgrade route.

use axum::extract::{State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::Response;
use surf_rac_protocol::{DeviceId, HEADER_DEVICE_ID, HEADER_DEVICE_SECRET, MAX_WS_MESSAGE_BYTES};

use crate::auth::bearer_token;
use crate::devices;
use crate::error::ApiError;
use crate::sessions;
use crate::state::AppState;
use crate::ws;

/// Returns the value of header `name` as a string, if present and valid UTF-8.
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

/// `GET /v1/ws`: authenticates token, device ID and device secret, then upgrades.
///
/// Every authentication failure is a 401 before the upgrade.
pub async fn upgrade(
    State(state): State<AppState>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let token = bearer_token(&headers).ok_or_else(ApiError::unauthorized)?;
    let user = sessions::authenticate(&state.db, token)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    let device: DeviceId = header(&headers, HEADER_DEVICE_ID)
        .and_then(|v| v.parse().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let secret = header(&headers, HEADER_DEVICE_SECRET)
        .ok_or_else(ApiError::unauthorized)?
        .to_owned();
    if !devices::authenticate(&state.db, user.user_id, device, &secret).await? {
        return Err(ApiError::unauthorized());
    }
    Ok(upgrade
        .max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| ws::run(state, socket, user, device, secret)))
}
