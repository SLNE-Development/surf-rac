//! Logging setup.

use tracing_subscriber::EnvFilter;

/// Installs the global tracing subscriber, as JSON or human-readable lines.
///
/// The filter comes from `RUST_LOG` and defaults to `info`.
pub fn init(json: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    let result = if json {
        builder.json().try_init()
    } else {
        builder.try_init()
    };
    if let Err(err) = result {
        eprintln!("logging already initialised: {err}");
    }
}
