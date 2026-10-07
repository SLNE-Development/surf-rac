//! State shared by all request handlers.

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;

use crate::config::Config;
use crate::hub::Hub;
use crate::limits::Limits;

/// Handles to everything a request handler needs; cheap to clone.
#[derive(Clone)]
pub struct AppState {
    /// Postgres connection pool.
    pub db: PgPool,
    /// Server configuration.
    pub config: Arc<Config>,
    /// Rate limiters and login lockout.
    pub limits: Arc<Limits>,
    /// Online devices and their connections.
    pub hub: Hub,
    /// How often a WebSocket re-checks its session, user and device secret.
    pub ws_revalidate_interval: Duration,
}

impl AppState {
    /// Creates the state from a connected pool and the configuration.
    pub fn new(db: PgPool, config: Arc<Config>) -> Self {
        Self {
            db,
            config,
            limits: Arc::new(Limits::default()),
            hub: Hub::default(),
            ws_revalidate_interval: Duration::from_secs(60),
        }
    }
}
