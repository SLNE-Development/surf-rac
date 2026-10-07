//! Shared helpers for the server integration tests.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use sqlx::PgPool;
use surf_rac_server::config::Config;
use surf_rac_server::state::AppState;

/// TURN shared secret used by every test server.
pub const TEST_TURN_SECRET: &str = "test-turn-secret-0123";

/// A running test server bound to a random local port.
pub struct TestApp {
    /// Address the server listens on.
    pub addr: SocketAddr,
    /// Base URL, e.g. `http://127.0.0.1:1234`.
    pub base: String,
    /// Pool connected to this test's database.
    pub pool: PgPool,
    /// HTTP client for requests against the server.
    pub client: reqwest::Client,
    /// State shared with the server, for direct inspection.
    pub state: AppState,
}

/// Returns the configuration every test server uses.
pub fn test_config() -> Config {
    Config {
        database_url: String::new(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        turn_secret: TEST_TURN_SECRET.into(),
        turn_urls: vec!["turn:turn.example:3478".into()],
        turn_ttl_secs: 3600,
        trust_forwarded_for: true,
        log_json: false,
    }
}

/// Starts a server on a random port backed by `pool`.
pub async fn spawn(pool: PgPool) -> TestApp {
    let state = AppState::new(pool.clone(), Arc::new(test_config()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let served = state.clone();
    tokio::spawn(async move {
        surf_rac_server::serve(listener, served).await.unwrap();
    });
    TestApp {
        addr,
        base: format!("http://{addr}"),
        pool,
        client: reqwest::Client::new(),
        state,
    }
}

impl TestApp {
    /// Builds a URL for `path` on this server.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }
}
