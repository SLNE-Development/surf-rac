//! HTTP routes.

mod health;

use axum::Router;
use axum::routing::get;

use crate::state::AppState;

/// Builds the router with every route of the server.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health::healthz))
        .with_state(state)
}
