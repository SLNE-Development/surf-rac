//! Registration, login, logout and account deletion routes.

use std::net::SocketAddr;
use std::time::Instant;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use surf_rac_protocol::{
    DeleteAccountRequest, LoginRequest, LoginResponse, RegisterRequest, RegisterResponse,
};

use crate::accounts::{self, RegisterError};
use crate::client_ip::client_ip;
use crate::crypto;
use crate::error::ApiError;
use crate::extract::JsonBody;
use crate::limits::rate_key;
use crate::sessions::{self, AuthUser};
use crate::state::AppState;

/// `POST /v1/register`: creates an account; anyone may register.
///
/// Limited per client address. The username must be 3 to 32 characters of
/// `[a-z0-9._-]` and the password 10 to 256 characters; a taken username is a 409.
pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    let ip = client_ip(&headers, peer, state.config.trust_forwarded_for);
    if !state
        .limits
        .register_ip
        .check(&rate_key(ip), Instant::now())
    {
        return Err(ApiError::rate_limited());
    }
    if !accounts::valid_username(&req.username) {
        return Err(ApiError::bad_request(
            "username must be 3 to 32 characters of a-z, 0-9, '.', '_' or '-'",
        ));
    }
    if !accounts::valid_password(&req.password) {
        return Err(ApiError::bad_request(
            "password must be 10 to 256 characters",
        ));
    }
    let password_hash = hash_password(req.password).await?;
    match accounts::create_user(&state.db, &req.username, &password_hash, false).await {
        Ok(_) => {
            tracing::info!(username = %req.username, "account registered");
            Ok((
                StatusCode::CREATED,
                Json(RegisterResponse {
                    username: req.username,
                }),
            ))
        }
        Err(RegisterError::UsernameTaken) => Err(ApiError::conflict("username already taken")),
        Err(RegisterError::Db(err)) => Err(err.into()),
    }
}

/// `POST /v1/login`: checks credentials and issues a session token.
///
/// Applies the per-address limit first. Credentials that cannot match any
/// account (malformed username or out-of-range password length) are refused
/// without touching the lockout. Otherwise an attempt is reserved against the
/// per-account lockout. Every refusal produces the same response and runs
/// one password check.
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let now = Instant::now();
    let ip = client_ip(&headers, peer, state.config.trust_forwarded_for);
    if !state.limits.login_ip.check(&rate_key(ip), now) {
        return Err(ApiError::rate_limited());
    }
    let password = req.password;
    if !accounts::valid_username(&req.username) || !accounts::valid_password(&password) {
        tokio::task::spawn_blocking(move || crypto::verify_dummy(&password))
            .await
            .map_err(ApiError::internal)?;
        return Err(ApiError::invalid_credentials());
    }
    let user = accounts::find_user_by_name(&state.db, &req.username).await?;
    let lockout = if user.is_some() {
        &state.limits.account_lockout
    } else {
        &state.limits.unknown_lockout
    };
    if let Err(remaining) = lockout.try_attempt(&req.username, now) {
        return Err(ApiError::locked(remaining.as_secs()));
    }
    let user = tokio::task::spawn_blocking(move || match user {
        Some(u) => {
            let matches = crypto::verify_password(&password, &u.password_hash);
            (matches && !u.disabled).then_some(u)
        }
        None => {
            crypto::verify_dummy(&password);
            None
        }
    })
    .await
    .map_err(ApiError::internal)?;
    let Some(user) = user else {
        tracing::info!(username = %req.username, %ip, "login failed");
        return Err(ApiError::invalid_credentials());
    };
    state.limits.account_lockout.record_success(&req.username);
    let (token, expires_at) = sessions::create(&state.db, user.id).await?;
    tracing::info!(username = %user.username, "login");
    Ok(Json(LoginResponse { token, expires_at }))
}

/// `POST /v1/logout`: revokes the session used for this request.
pub async fn logout(State(state): State<AppState>, user: AuthUser) -> Result<StatusCode, ApiError> {
    sessions::revoke(&state.db, &user.token_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/account`: deletes the caller's account after checking its password.
///
/// The password check counts against the per-account login lockout. The
/// account's sessions, contacts and device links are removed with it; its
/// devices stay registered and stay linked to other accounts.
pub async fn delete_account(
    State(state): State<AppState>,
    user: AuthUser,
    JsonBody(req): JsonBody<DeleteAccountRequest>,
) -> Result<StatusCode, ApiError> {
    let now = Instant::now();
    if let Err(remaining) = state
        .limits
        .account_lockout
        .try_attempt(&user.username, now)
    {
        return Err(ApiError::locked(remaining.as_secs()));
    }
    let hash = accounts::password_hash(&state.db, user.user_id)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    let password = req.password;
    let matches = tokio::task::spawn_blocking(move || crypto::verify_password(&password, &hash))
        .await
        .map_err(ApiError::internal)?;
    if !matches {
        tracing::info!(username = %user.username, "account deletion refused");
        return Err(ApiError::invalid_credentials());
    }
    state.limits.account_lockout.record_success(&user.username);
    accounts::delete_user(&state.db, user.user_id).await?;
    tracing::info!(username = %user.username, "account deleted");
    Ok(StatusCode::NO_CONTENT)
}

/// Hashes `password` on the blocking thread pool.
pub async fn hash_password(password: String) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || crypto::hash_password(&password))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)
}
