//! HTTP routes.

mod accounts;
mod health;

use axum::Router;
use axum::routing::{get, post};

use crate::state::AppState;

/// Builds the router with every route of the server.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health::healthz))
        .route("/v1/register", post(accounts::register))
        .route("/v1/login", post(accounts::login))
        .route("/v1/logout", post(accounts::logout))
        .with_state(state)
}
