//! Health check route.

use axum::extract::State;
use axum::http::StatusCode;

use crate::error::ApiError;
use crate::state::AppState;

/// Returns 200 when the database answers a trivial query, otherwise 503.
pub async fn healthz(State(state): State<AppState>) -> Result<StatusCode, ApiError> {
    sqlx::query("select 1")
        .execute(&state.db)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "health check failed");
            ApiError::unavailable()
        })?;
    Ok(StatusCode::OK)
}
