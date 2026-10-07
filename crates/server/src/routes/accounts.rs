//! Registration, login and logout routes.

use std::net::SocketAddr;
use std::time::Instant;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use surf_rac_protocol::{LoginRequest, LoginResponse, RegisterRequest, RegisterResponse};

use crate::accounts::{self, RegisterError};
use crate::client_ip::client_ip;
use crate::crypto;
use crate::error::ApiError;
use crate::extract::JsonBody;
use crate::sessions::{self, AuthUser};
use crate::state::AppState;

/// `POST /v1/register`: redeems an invite and creates an account.
pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    let ip = client_ip(&headers, peer, state.config.trust_forwarded_for);
    if !state.limits.register_ip.check(&ip.to_string(), Instant::now()) {
        return Err(ApiError::rate_limited());
    }
    if !accounts::valid_username(&req.username) {
        return Err(ApiError::bad_request(
            "username must be 3 to 32 characters of a-z, 0-9, '.', '_' or '-'",
        ));
    }
    if !accounts::valid_password(&req.password) {
        return Err(ApiError::bad_request("password must be 10 to 256 characters"));
    }
    if req.invite_code.is_empty() {
        return Err(ApiError::bad_request("invalid or expired invite"));
    }
    let password_hash = hash_password(req.password).await?;
    match accounts::redeem_invite_and_create_user(
        &state.db,
        &req.invite_code,
        &req.username,
        &password_hash,
    )
    .await
    {
        Ok(_) => {
            tracing::info!(username = %req.username, "account registered");
            Ok((
                StatusCode::CREATED,
                Json(RegisterResponse {
                    username: req.username,
                }),
            ))
        }
        Err(RegisterError::InvalidInvite) => Err(ApiError::bad_request("invalid or expired invite")),
        Err(RegisterError::UsernameTaken) => Err(ApiError::conflict("username already taken")),
        Err(RegisterError::Db(err)) => Err(err.into()),
    }
}

/// `POST /v1/login`: checks credentials and issues a session token.
///
/// Applies the per-IP limit first, then reserves an attempt against the
/// per-account lockout. Wrong usernames, wrong passwords and disabled
/// accounts produce the same response, and each runs one password check.
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let now = Instant::now();
    let ip = client_ip(&headers, peer, state.config.trust_forwarded_for);
    if !state.limits.login_ip.check(&ip.to_string(), now) {
        return Err(ApiError::rate_limited());
    }
    if let Err(remaining) = state.limits.lockout.try_attempt(&req.username, now) {
        return Err(ApiError::locked(remaining.as_secs()));
    }
    let user = accounts::find_user_by_name(&state.db, &req.username).await?;
    let password = req.password;
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
    state.limits.lockout.record_success(&req.username);
    let (token, expires_at) = sessions::create(&state.db, user.id).await?;
    tracing::info!(username = %user.username, "login");
    Ok(Json(LoginResponse { token, expires_at }))
}

/// `POST /v1/logout`: revokes the session used for this request.
pub async fn logout(State(state): State<AppState>, user: AuthUser) -> Result<StatusCode, ApiError> {
    sessions::revoke(&state.db, &user.token_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Hashes `password` on the blocking thread pool.
pub async fn hash_password(password: String) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || crypto::hash_password(&password))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)
}
