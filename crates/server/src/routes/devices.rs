//! Device, contact and presence routes.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use surf_rac_protocol::{
    ContactInfo, DeviceId, DeviceInfo, PresenceInfo, PutContactRequest, PutPublicKeyRequest,
    RegisterDeviceRequest, RegisterDeviceResponse,
};

use crate::contacts;
use crate::devices::{self, DeviceError, device_id};
use crate::error::ApiError;
use crate::extract::JsonBody;
use crate::presence;
use crate::sessions::AuthUser;
use crate::state::AppState;

/// Parses a device ID path segment; malformed IDs are a 400.
fn parse_id(raw: &str) -> Result<DeviceId, ApiError> {
    raw.parse()
        .map_err(|_| ApiError::bad_request("device id must be 9 digits"))
}

/// `POST /v1/devices`: registers a device or re-binds an existing one.
///
/// A re-bind closes the device's live connection, which held the old secret,
/// and tells the device's watchers it went offline.
pub async fn register(
    State(state): State<AppState>,
    user: AuthUser,
    JsonBody(req): JsonBody<RegisterDeviceRequest>,
) -> Result<Json<RegisterDeviceResponse>, ApiError> {
    if !devices::valid_fingerprint(&req.fingerprint_hash) {
        return Err(ApiError::bad_request(
            "fingerprint_hash must be 64 lowercase hex characters",
        ));
    }
    if !devices::valid_name(&req.name) {
        return Err(ApiError::bad_request("name must be 1 to 64 characters"));
    }
    let registered = devices::register(
        &state.db,
        user.user_id,
        &req.fingerprint_hash,
        &req.name,
        req.device_id,
    )
    .await
    .map_err(|err| match err {
        DeviceError::NotFound => ApiError::not_found(),
        DeviceError::Forbidden => ApiError::forbidden(),
        DeviceError::FingerprintInUse => ApiError::conflict(err.to_string()),
        DeviceError::IdExhausted => ApiError::internal(err),
        DeviceError::Db(e) => e.into(),
    })?;
    if registered.rebound && state.hub.disconnect(registered.device_id) {
        presence::spawn_broadcast(&state, registered.device_id, false);
    }
    tracing::info!(
        username = %user.username,
        device_id = %registered.device_id,
        rebound = registered.rebound,
        "device registered"
    );
    Ok(Json(RegisterDeviceResponse {
        device_id: registered.device_id,
        device_secret: registered.secret,
        rebound: registered.rebound,
    }))
}

/// `GET /v1/devices`: lists the caller's devices with their online state.
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<DeviceInfo>>, ApiError> {
    let rows = devices::list(&state.db, user.user_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| {
                let id = device_id(r.id);
                DeviceInfo {
                    device_id: id,
                    name: r.name,
                    online: state.hub.is_online(id),
                    last_seen_at: r.last_seen_at,
                }
            })
            .collect(),
    ))
}

/// `DELETE /v1/devices/{id}`: deletes one of the caller's devices and closes its connection.
///
/// Watchers of a device that was online are told it went offline.
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(raw): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id = parse_id(&raw)?;
    let watchers = contacts::watchers(&state.db, id).await?;
    if !devices::delete(&state.db, user.user_id, id).await? {
        return Err(ApiError::not_found());
    }
    if state.hub.disconnect(id) {
        presence::broadcast_to(&state, &watchers, id, false).await;
    }
    tracing::info!(username = %user.username, device_id = %id, "device deleted");
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /v1/devices/{id}/public-key`: sets the X25519 public key of one of the caller's devices.
pub async fn put_public_key(
    State(state): State<AppState>,
    user: AuthUser,
    Path(raw): Path<String>,
    JsonBody(req): JsonBody<PutPublicKeyRequest>,
) -> Result<StatusCode, ApiError> {
    let id = parse_id(&raw)?;
    let key: [u8; 32] = STANDARD
        .decode(&req.public_key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ApiError::bad_request("public_key must be base64 of 32 bytes"))?;
    match devices::owner(&state.db, id).await? {
        None => return Err(ApiError::not_found()),
        Some(owner) if owner != user.user_id => return Err(ApiError::forbidden()),
        Some(_) => {}
    }
    if !devices::set_public_key(&state.db, user.user_id, id, &key).await? {
        return Err(ApiError::not_found());
    }
    tracing::info!(username = %user.username, device_id = %id, "device public key set");
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/contacts`: lists the caller's contacts with their online state.
pub async fn list_contacts(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<ContactInfo>>, ApiError> {
    let rows = contacts::list(&state.db, user.user_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| {
                let id = device_id(r.device_id);
                ContactInfo {
                    device_id: id,
                    alias: r.alias,
                    online: state.hub.is_online(id),
                }
            })
            .collect(),
    ))
}

/// `PUT /v1/contacts/{id}`: adds a device to the caller's contacts or renames it.
pub async fn put_contact(
    State(state): State<AppState>,
    user: AuthUser,
    Path(raw): Path<String>,
    JsonBody(req): JsonBody<PutContactRequest>,
) -> Result<StatusCode, ApiError> {
    let id = parse_id(&raw)?;
    if !devices::valid_name(&req.alias) {
        return Err(ApiError::bad_request("alias must be 1 to 64 characters"));
    }
    if !contacts::put(&state.db, user.user_id, id, &req.alias).await? {
        return Err(ApiError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/contacts/{id}`: removes a device from the caller's contacts.
pub async fn delete_contact(
    State(state): State<AppState>,
    user: AuthUser,
    Path(raw): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id = parse_id(&raw)?;
    contacts::delete(&state.db, user.user_id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/presence/{id}`: reports whether a device is online and its public key.
pub async fn presence(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(raw): Path<String>,
) -> Result<Json<PresenceInfo>, ApiError> {
    let id = parse_id(&raw)?;
    if !devices::exists(&state.db, id).await? {
        return Err(ApiError::not_found());
    }
    let public_key = devices::public_key(&state.db, id).await?;
    Ok(Json(PresenceInfo {
        device_id: id,
        online: state.hub.is_online(id),
        public_key: public_key.map(|k| STANDARD.encode(k)),
    }))
}
