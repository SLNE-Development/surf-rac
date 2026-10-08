//! Logging to a daily file under `%LOCALAPPDATA%\surf-rac\logs`, and to stderr in debug builds.

use std::path::PathBuf;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::MakeWriterExt;

/// Returns the log directory.
pub fn log_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("surf-rac")
        .join("logs")
}

/// Starts logging; the returned guard flushes the file when dropped.
///
/// The level comes from `RUST_LOG`, `info` by default.
pub fn init() -> WorkerGuard {
    let appender = tracing_appender::rolling::daily(log_dir(), "surf-rac.log");
    let (file, guard) = tracing_appender::non_blocking(appender);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false);
    let result = if cfg!(debug_assertions) {
        builder.with_writer(file.and(std::io::stderr)).try_init()
    } else {
        builder.with_writer(file).try_init()
    };
    if let Err(e) = result {
        eprintln!("logging not started: {e}");
    }
    guard
}
