//! Device registration, My devices, contact and presence routes.

use axum::Json;
use std::net::SocketAddr;
use std::time::Instant;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use surf_rac_protocol::{
    ContactInfo, DeviceId, MyDeviceInfo, PROTOCOL_VERSION, PresenceInfo, PutContactRequest,
    RegisterDeviceRequest, RegisterDeviceResponse,
};

use crate::client_ip::client_ip;
use crate::contacts;
use crate::devices::{self, DeviceError, device_id};
use crate::error::ApiError;
use crate::extract::JsonBody;
use crate::limits::rate_key;
use crate::sessions::AuthUser;
use crate::state::AppState;

/// Parses a device ID path segment; malformed IDs are a 400.
fn parse_id(raw: &str) -> Result<DeviceId, ApiError> {
    raw.parse()
        .map_err(|_| ApiError::bad_request("device id must be 9 digits"))
}

/// `POST /v1/devices`: registers an installation by its identity key, without an account.
///
/// A different protocol version is a 426 `update_required`. A key registered
/// with a different fingerprint is a 409 `clone_detected`. A key registered
/// with the same fingerprint returns its existing ID and takes the new name.
/// A missing or invalid registration signature is a 401 `bad_signature` and
/// nothing is written.
///
/// Every request with a well-formed body counts against the per-client-address
/// registration limit, including repeated registrations of a known key; over
/// the limit the response is a 429 `rate_limited`.
pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<RegisterDeviceRequest>,
) -> Result<Json<RegisterDeviceResponse>, ApiError> {
    if req.protocol_version != PROTOCOL_VERSION {
        return Err(ApiError::update_required());
    }
    let public_key: [u8; 32] = STANDARD
        .decode(&req.public_key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .filter(devices::valid_public_key)
        .ok_or_else(|| {
            ApiError::bad_request("public_key must be base64 of a valid 32-byte Ed25519 key")
        })?;
    if !devices::valid_fingerprint(&req.fingerprint_hash) {
        return Err(ApiError::bad_request(
            "fingerprint_hash must be 64 lowercase hex characters",
        ));
    }
    if !devices::valid_name(&req.name) {
        return Err(ApiError::bad_request("name must be 1 to 64 characters"));
    }
    let ip = client_ip(&headers, peer, state.config.trust_forwarded_for);
    if !state
        .limits
        .device_register_ip
        .check(&rate_key(ip), Instant::now())
    {
        return Err(ApiError::rate_limited());
    }
    let signature: [u8; 64] = STANDARD
        .decode(&req.signature)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(ApiError::bad_signature)?;
    devices::verify_registration(&public_key, &req.fingerprint_hash, &req.name, &signature)
        .map_err(|_| ApiError::bad_signature())?;
    let id = devices::register(&state.db, &public_key, &req.fingerprint_hash, &req.name)
        .await
        .map_err(|err| match err {
            DeviceError::CloneDetected => ApiError::clone_detected(),
            DeviceError::Db(e) => e.into(),
            other => ApiError::internal(other),
        })?;
    tracing::info!(device_id = %id, "device registered");
    Ok(Json(RegisterDeviceResponse { device_id: id }))
}

/// `GET /v1/my-devices`: lists the devices linked to the caller's account with their online state.
pub async fn my_devices(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<MyDeviceInfo>>, ApiError> {
    let rows = devices::list(&state.db, user.user_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| {
                let id = device_id(r.id);
                MyDeviceInfo {
                    device_id: id,
                    name: r.name,
                    online: state.hub.is_online(id),
                    last_seen_at: r.last_seen_at,
                }
            })
            .collect(),
    ))
}

/// `DELETE /v1/my-devices/{id}`: removes the link between the caller's account and a device.
///
/// The device stays registered and connected; a device that is not linked
/// to the caller is a 404.
pub async fn unlink_my_device(
    State(state): State<AppState>,
    user: AuthUser,
    Path(raw): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id = parse_id(&raw)?;
    if !devices::unlink(&state.db, user.user_id, id).await? {
        return Err(ApiError::not_found());
    }
    tracing::info!(username = %user.username, device_id = %id, "device unlinked");
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

/// `PUT /v1/contacts/{id}`: adds a device ID to the caller's contacts or renames it.
///
/// The ID does not have to be registered.
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
    contacts::put(&state.db, user.user_id, id, &req.alias).await?;
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

/// `GET /v1/presence/{id}`: reports whether a registered device is online; needs an account session.
pub async fn presence(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(raw): Path<String>,
) -> Result<Json<PresenceInfo>, ApiError> {
    let id = parse_id(&raw)?;
    if !devices::exists(&state.db, id).await? {
        return Err(ApiError::not_found());
    }
    Ok(Json(PresenceInfo {
        device_id: id,
        online: state.hub.is_online(id),
    }))
}
