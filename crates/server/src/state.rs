//! State shared by all request handlers.

use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Config;
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
}

impl AppState {
    /// Creates the state from a connected pool and the configuration.
    pub fn new(db: PgPool, config: Arc<Config>) -> Self {
        Self {
            db,
            config,
            limits: Arc::new(Limits::default()),
        }
    }
}
