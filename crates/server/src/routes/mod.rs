//! HTTP routes.

mod accounts;
mod devices;
mod health;
mod ws;

use axum::Router;
use axum::routing::{delete, get, post, put};

use crate::state::AppState;

/// Builds the router with every route of the server.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health::healthz))
        .route("/v1/register", post(accounts::register))
        .route("/v1/login", post(accounts::login))
        .route("/v1/logout", post(accounts::logout))
        .route("/v1/account", delete(accounts::delete_account))
        .route("/v1/devices", post(devices::register))
        .route("/v1/my-devices", get(devices::my_devices))
        .route("/v1/my-devices/{id}", delete(devices::unlink_my_device))
        .route("/v1/contacts", get(devices::list_contacts))
        .route(
            "/v1/contacts/{id}",
            put(devices::put_contact).delete(devices::delete_contact),
        )
        .route("/v1/presence/{id}", get(devices::presence))
        .route("/v1/ws", get(ws::upgrade))
        .with_state(state)
}
