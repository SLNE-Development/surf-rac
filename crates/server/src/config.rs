//! Server configuration read from environment variables.

use std::net::SocketAddr;

/// Minimum length of the TURN shared secret.
const MIN_TURN_SECRET_LEN: usize = 16;

/// Runtime configuration of the server.
#[derive(Debug, Clone)]
pub struct Config {
    /// Postgres connection URL (`DATABASE_URL`).
    pub database_url: String,
    /// Address the HTTP server binds to (`BIND_ADDR`, default `0.0.0.0:8080`).
    pub bind_addr: SocketAddr,
    /// Shared secret with coturn for TURN credentials (`TURN_SECRET`).
    pub turn_secret: String,
    /// TURN server URLs handed to clients (`TURN_URLS`, comma-separated).
    pub turn_urls: Vec<String>,
    /// Lifetime of issued TURN credentials (`TURN_TTL_SECS`, default 3600).
    pub turn_ttl_secs: u64,
    /// Whether the right-most `X-Forwarded-For` entry is the client IP (`TRUST_FORWARDED_FOR`).
    pub trust_forwarded_for: bool,
    /// Whether logs are JSON (`LOG_FORMAT=json`, the default) or human-readable (`pretty`).
    pub log_json: bool,
}

/// A configuration value is missing or invalid.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required variable is not set or empty.
    #[error("{0} is required")]
    Missing(&'static str),
    /// A variable is set but cannot be used.
    #[error("{name} is invalid: {reason}")]
    Invalid {
        /// The variable name.
        name: &'static str,
        /// Why the value was rejected.
        reason: String,
    },
}

impl Config {
    /// Reads the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_vars(|k| std::env::var(k).ok())
    }

    /// Reads the configuration through `get`, which returns a variable's value by name.
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |k: &str| {
            get(k)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let required = |k: &'static str| get(k).ok_or(ConfigError::Missing(k));

        let database_url = required("DATABASE_URL")?;
        let bind_addr = match get("BIND_ADDR") {
            Some(v) => v.parse().map_err(|e| invalid("BIND_ADDR", e))?,
            None => SocketAddr::from(([0, 0, 0, 0], 8080)),
        };
        let turn_secret = required("TURN_SECRET")?;
        if turn_secret.len() < MIN_TURN_SECRET_LEN {
            return Err(invalid(
                "TURN_SECRET",
                format!("must be at least {MIN_TURN_SECRET_LEN} characters"),
            ));
        }
        let turn_urls: Vec<String> = required("TURN_URLS")?
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if turn_urls.is_empty() {
            return Err(invalid("TURN_URLS", "must list at least one URL"));
        }
        let turn_ttl_secs = match get("TURN_TTL_SECS") {
            Some(v) => match v.parse::<u64>() {
                Ok(n) if n > 0 => n,
                _ => return Err(invalid("TURN_TTL_SECS", "must be a positive integer")),
            },
            None => 3600,
        };
        let trust_forwarded_for = match get("TRUST_FORWARDED_FOR").as_deref() {
            None | Some("false") | Some("0") => false,
            Some("true") | Some("1") => true,
            Some(_) => return Err(invalid("TRUST_FORWARDED_FOR", "must be true or false")),
        };
        let log_json = match get("LOG_FORMAT").as_deref() {
            None | Some("json") => true,
            Some("pretty") => false,
            Some(_) => return Err(invalid("LOG_FORMAT", "must be json or pretty")),
        };

        Ok(Config {
            database_url,
            bind_addr,
            turn_secret,
            turn_urls,
            turn_ttl_secs,
            trust_forwarded_for,
            log_json,
        })
    }
}

/// Builds an [`ConfigError::Invalid`] for `name` with `reason`.
fn invalid(name: &'static str, reason: impl ToString) -> ConfigError {
    ConfigError::Invalid {
        name,
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    const BASE: &[(&str, &str)] = &[
        ("DATABASE_URL", "postgres://x"),
        ("TURN_SECRET", "0123456789abcdef"),
        ("TURN_URLS", "turn:a:3478, turns:b:5349"),
    ];

    #[test]
    fn config_requires_database_url() {
        let err = Config::from_vars(vars(&BASE[1..])).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("DATABASE_URL")));
    }

    #[test]
    fn config_rejects_short_turn_secret() {
        let mut v = BASE.to_vec();
        v[1] = ("TURN_SECRET", "short");
        let err = Config::from_vars(vars(&v)).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                name: "TURN_SECRET",
                ..
            }
        ));
    }

    #[test]
    fn config_requires_turn_urls() {
        let mut v = BASE.to_vec();
        v[2] = ("TURN_URLS", " , ");
        let err = Config::from_vars(vars(&v)).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                name: "TURN_URLS",
                ..
            }
        ));
    }

    #[test]
    fn config_defaults_bind_and_ttl() {
        let c = Config::from_vars(vars(BASE)).unwrap();
        assert_eq!(c.bind_addr.to_string(), "0.0.0.0:8080");
        assert_eq!(c.turn_ttl_secs, 3600);
        assert!(!c.trust_forwarded_for);
        assert!(c.log_json);
        assert_eq!(c.turn_urls, vec!["turn:a:3478", "turns:b:5349"]);
    }

    #[test]
    fn config_parses_overrides() {
        let mut v = BASE.to_vec();
        v.push(("BIND_ADDR", "127.0.0.1:9000"));
        v.push(("TURN_TTL_SECS", "600"));
        v.push(("TRUST_FORWARDED_FOR", "true"));
        v.push(("LOG_FORMAT", "pretty"));
        let c = Config::from_vars(vars(&v)).unwrap();
        assert_eq!(c.bind_addr.port(), 9000);
        assert_eq!(c.turn_ttl_secs, 600);
        assert!(c.trust_forwarded_for);
        assert!(!c.log_json);
    }

    #[test]
    fn config_rejects_bad_bool_and_ttl() {
        let mut v = BASE.to_vec();
        v.push(("TRUST_FORWARDED_FOR", "yes please"));
        assert!(Config::from_vars(vars(&v)).is_err());
        let mut v = BASE.to_vec();
        v.push(("TURN_TTL_SECS", "0"));
        assert!(Config::from_vars(vars(&v)).is_err());
    }
}
