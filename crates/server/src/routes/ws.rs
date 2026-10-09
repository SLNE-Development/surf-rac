//! WebSocket upgrade route.

use axum::extract::{State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::Response;
use surf_rac_protocol::{
    DeviceId, HEADER_DEVICE_ID, HEADER_PROTOCOL_VERSION, MAX_WS_MESSAGE_BYTES, PROTOCOL_VERSION,
};

use crate::devices::{self, DeviceError};
use crate::error::ApiError;
use crate::state::AppState;
use crate::ws;

/// Returns the value of header `name` as a string, if present and valid UTF-8.
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

/// `GET /v1/ws`: checks the protocol version and device ID, then upgrades.
///
/// A missing or different protocol version is a 426 `update_required`. A
/// missing or malformed device ID is a 401 `unauthorized`, an unknown one a 404
/// `unknown_device` and a disabled one a 403 `device_disabled`. After the
/// upgrade the device must answer the challenge before it is connected.
pub async fn upgrade(
    State(state): State<AppState>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let version = header(&headers, HEADER_PROTOCOL_VERSION).and_then(|v| v.parse::<u32>().ok());
    if version != Some(PROTOCOL_VERSION) {
        return Err(ApiError::update_required());
    }
    let device: DeviceId = header(&headers, HEADER_DEVICE_ID)
        .and_then(|v| v.parse().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let identity = devices::connect_identity(&state.db, device)
        .await
        .map_err(|err| match err {
            DeviceError::NotFound => ApiError::unknown_device(),
            DeviceError::Disabled => ApiError::device_disabled(),
            DeviceError::Db(e) => e.into(),
            other => ApiError::internal(other),
        })?;
    Ok(upgrade
        .max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| ws::run(state, socket, device, identity)))
}
