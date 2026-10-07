//! Bearer-token authentication of HTTP requests.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use crate::error::ApiError;
use crate::sessions::{self, AuthUser};
use crate::state::AppState;

/// Returns the token of an `Authorization: Bearer <token>` header, if present.
pub fn bearer_token(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    /// Authenticates the request's bearer token; rejects with 401 when missing or invalid.
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = bearer_token(parts).ok_or_else(ApiError::unauthorized)?;
        sessions::authenticate(&state.db, token)
            .await?
            .ok_or_else(ApiError::unauthorized)
    }
}
