//! Session settings and outcomes shared by hosts and viewers.

use std::time::Duration;

/// Most viewers a host room admits at once.
pub const MAX_VIEWERS: usize = 5;

/// Timing and transport settings of a session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// How long a request or token exchange may take before it fails (default 60 s).
    pub request_timeout: Duration,
    /// How long a dropped media connection may take to recover (default 30 s).
    pub reconnect_window: Duration,
    /// Whether media must go through the TURN relay only (default false).
    pub force_relay: bool,
    /// How long a host waits for the unattended password after its password
    /// challenge before it refuses the request (default 30 s).
    pub challenge_timeout: Duration,
}

impl Default for SessionConfig {
    /// Returns the production settings: 60 s request timeout, 30 s reconnect
    /// window, no forced relay and a 30 s password challenge timeout.
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(60),
            reconnect_window: Duration::from_secs(30),
            force_relay: false,
            challenge_timeout: Duration::from_secs(30),
        }
    }
}

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// The peer hung up.
    Hangup,
    /// The media connection did not recover within the reconnect window.
    Timeout,
    /// Too many data messages in a row failed to decrypt.
    CryptoError,
    /// The room closed or the peer left.
    Closed,
}
