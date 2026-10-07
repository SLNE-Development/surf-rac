//! The surf-rac signaling and account server.

pub mod accounts;
pub mod admin;
pub mod auth;
pub mod client_ip;
pub mod config;
pub mod contacts;
pub mod crypto;
pub mod devices;
pub mod error;
pub mod extract;
pub mod hub;
pub mod limits;
pub mod presence;
pub mod sessions;
pub mod routes;
pub mod state;
pub mod telemetry;
pub mod turn;
pub mod ws;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;

use crate::config::Config;
use crate::state::AppState;

/// Connects to Postgres and applies all pending migrations.
pub async fn connect_and_migrate(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// Serves the router on `listener` until the process receives Ctrl-C or SIGTERM.
pub async fn serve(listener: TcpListener, state: AppState) -> std::io::Result<()> {
    let app = routes::router(state);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
}

/// Connects, migrates, binds `config.bind_addr` and serves until shutdown.
pub async fn run(config: Config) -> anyhow::Result<()> {
    let pool = connect_and_migrate(&config.database_url).await?;
    let listener = TcpListener::bind(config.bind_addr).await?;
    tracing::info!(addr = %config.bind_addr, "listening");
    let state = AppState::new(pool, Arc::new(config));
    serve(listener, state).await?;
    tracing::info!("shut down");
    Ok(())
}

/// Resolves when the process receives Ctrl-C or, on Unix, SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
