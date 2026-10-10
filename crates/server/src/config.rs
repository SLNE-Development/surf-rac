//! Server configuration read from environment variables.

use std::net::SocketAddr;

/// Minimum length of the TURN shared secret.
const MIN_TURN_SECRET_LEN: usize = 16;

/// Minimum length of the LiveKit API secret.
const MIN_LIVEKIT_SECRET_LEN: usize = 32;

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
    /// LiveKit server URL handed to clients (`LIVEKIT_URL`, `ws://` or `wss://`).
    pub livekit_url: String,
    /// LiveKit API key that issues join tokens (`LIVEKIT_API_KEY`).
    pub livekit_api_key: String,
    /// LiveKit API secret that signs join tokens (`LIVEKIT_API_SECRET`).
    pub livekit_api_secret: String,
    /// Whether the right-most `X-Forwarded-For` entry is the client IP (`TRUST_FORWARDED_FOR`).
    pub trust_forwarded_for: bool,
    /// Whether logs are JSON (`LOG_FORMAT=json`, the default) or human-readable (`pretty`).
    pub log_json: bool,
    /// Device registrations allowed per client address block per hour (`REGISTER_PER_HOUR`, default 5).
    pub register_per_hour: u32,
    /// Session requests allowed per target device per minute (`SESSION_REQUESTS_PER_MINUTE`, default 10).
    pub session_requests_per_minute: u32,
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
        let livekit_url = required("LIVEKIT_URL")?;
        if !(livekit_url.starts_with("ws://") || livekit_url.starts_with("wss://")) {
            return Err(invalid("LIVEKIT_URL", "must start with ws:// or wss://"));
        }
        let livekit_api_key = required("LIVEKIT_API_KEY")?;
        let livekit_api_secret = required("LIVEKIT_API_SECRET")?;
        if livekit_api_secret.len() < MIN_LIVEKIT_SECRET_LEN {
            return Err(invalid(
                "LIVEKIT_API_SECRET",
                format!("must be at least {MIN_LIVEKIT_SECRET_LEN} characters"),
            ));
        }
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

        let register_per_hour = positive_u32(&get, "REGISTER_PER_HOUR", 5)?;
        let session_requests_per_minute = positive_u32(&get, "SESSION_REQUESTS_PER_MINUTE", 10)?;

        Ok(Config {
            database_url,
            bind_addr,
            turn_secret,
            turn_urls,
            turn_ttl_secs,
            livekit_url,
            livekit_api_key,
            livekit_api_secret,
            trust_forwarded_for,
            log_json,
            register_per_hour,
            session_requests_per_minute,
        })
    }
}

/// Reads the positive integer variable `name` through `get`, or returns `default` when it is unset.
fn positive_u32(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: u32,
) -> Result<u32, ConfigError> {
    match get(name) {
        Some(v) => match v.parse::<u32>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(invalid(name, "must be a positive integer")),
        },
        None => Ok(default),
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

    /// Returns a variable lookup function that answers from the given key/value pairs.
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
        ("LIVEKIT_URL", "wss://lk.example"),
        ("LIVEKIT_API_KEY", "key"),
        ("LIVEKIT_API_SECRET", "0123456789abcdef0123456789abcdef"),
    ];

    /// Returns `BASE` with `name` replaced by `value`, or removed when `value` is `None`.
    fn with(name: &str, value: Option<&'static str>) -> Vec<(&'static str, &'static str)> {
        let mut v: Vec<_> = BASE.iter().copied().filter(|(k, _)| *k != name).collect();
        if let Some(value) = value {
            let key = BASE.iter().find(|(k, _)| *k == name).unwrap().0;
            v.push((key, value));
        }
        v
    }

    /// A missing `LIVEKIT_URL` or `LIVEKIT_API_KEY` is reported as a missing variable.
    #[test]
    fn config_requires_livekit() {
        let err = Config::from_vars(vars(&with("LIVEKIT_URL", None))).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("LIVEKIT_URL")));
        let err = Config::from_vars(vars(&with("LIVEKIT_API_KEY", None))).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("LIVEKIT_API_KEY")));
    }

    /// A LiveKit API secret that is too short is rejected as invalid.
    #[test]
    fn config_rejects_short_livekit_secret() {
        let err = Config::from_vars(vars(&with("LIVEKIT_API_SECRET", Some("short")))).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                name: "LIVEKIT_API_SECRET",
                ..
            }
        ));
    }

    /// A LiveKit URL without a `ws`/`wss` scheme is rejected as invalid.
    #[test]
    fn config_rejects_non_ws_livekit_url() {
        let err = Config::from_vars(vars(&with("LIVEKIT_URL", Some("https://x")))).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                name: "LIVEKIT_URL",
                ..
            }
        ));
    }

    /// The LiveKit URL, API key and API secret are read from their variables.
    #[test]
    fn config_reads_livekit() {
        let c = Config::from_vars(vars(BASE)).unwrap();
        assert_eq!(c.livekit_url, "wss://lk.example");
        assert_eq!(c.livekit_api_key, "key");
        assert_eq!(c.livekit_api_secret, "0123456789abcdef0123456789abcdef");
    }

    /// A missing `DATABASE_URL` is reported as a missing variable.
    #[test]
    fn config_requires_database_url() {
        let err = Config::from_vars(vars(&with("DATABASE_URL", None))).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("DATABASE_URL")));
    }

    /// A TURN secret that is too short is rejected as invalid.
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

    /// A `TURN_URLS` value with no non-empty entries is rejected as invalid.
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

    /// Without overrides the bind address, TURN TTL, forwarding trust and log format take their
    /// defaults, and TURN URLs are split and trimmed.
    #[test]
    fn config_defaults_bind_and_ttl() {
        let c = Config::from_vars(vars(BASE)).unwrap();
        assert_eq!(c.bind_addr.to_string(), "0.0.0.0:8080");
        assert_eq!(c.turn_ttl_secs, 3600);
        assert!(!c.trust_forwarded_for);
        assert!(c.log_json);
        assert_eq!(c.turn_urls, vec!["turn:a:3478", "turns:b:5349"]);
    }

    /// Bind address, TURN TTL, forwarding trust and log format are taken from their variables
    /// when set.
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

    /// An unparsable boolean for `TRUST_FORWARDED_FOR` and a zero TURN TTL are both rejected.
    #[test]
    fn config_rejects_bad_bool_and_ttl() {
        let mut v = BASE.to_vec();
        v.push(("TRUST_FORWARDED_FOR", "yes please"));
        assert!(Config::from_vars(vars(&v)).is_err());
        let mut v = BASE.to_vec();
        v.push(("TURN_TTL_SECS", "0"));
        assert!(Config::from_vars(vars(&v)).is_err());
    }

    /// The registration and session-request rate limits have defaults and are overridden by
    /// their variables.
    #[test]
    fn config_defaults_and_parses_rate_limits() {
        let c = Config::from_vars(vars(BASE)).unwrap();
        assert_eq!(c.register_per_hour, 5);
        assert_eq!(c.session_requests_per_minute, 10);
        let mut v = BASE.to_vec();
        v.push(("REGISTER_PER_HOUR", "20"));
        v.push(("SESSION_REQUESTS_PER_MINUTE", "3"));
        let c = Config::from_vars(vars(&v)).unwrap();
        assert_eq!(c.register_per_hour, 20);
        assert_eq!(c.session_requests_per_minute, 3);
    }

    /// Zero, negative and non-numeric rate limit values are rejected as invalid for the named
    /// variable.
    #[test]
    fn config_rejects_bad_rate_limits() {
        for name in ["REGISTER_PER_HOUR", "SESSION_REQUESTS_PER_MINUTE"] {
            for bad in ["0", "-1", "many"] {
                let mut v = BASE.to_vec();
                v.push((name, bad));
                let err = Config::from_vars(vars(&v)).unwrap_err();
                assert!(matches!(err, ConfigError::Invalid { name: n, .. } if n == name));
            }
        }
    }
}
