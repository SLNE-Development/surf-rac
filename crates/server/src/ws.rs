//! Lifecycle of one device's WebSocket connection.
//!
//! A connection registers in the hub, sends `hello`, then relays signaling
//! until the client leaves, the hub closes it (replacement, re-bind, delete)
//! or a periodic re-validation finds its session, user or secret invalid or
//! cannot reach the database several times in a row.

use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use surf_rac_protocol::{ClientMessage, DeviceId, ServerMessage, WsErrorCode};

use crate::devices;
use crate::presence;
use crate::sessions::{self, AuthUser};
use crate::state::AppState;
use crate::turn;

/// Sustained messages per second a connection may send.
const RATE_PER_SEC: f64 = 50.0;

/// Messages a connection may send in a burst.
const BURST: f64 = 100.0;

/// Interval between server pings.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Consecutive failed re-validations (database errors) after which a socket closes.
const MAX_REVALIDATION_ERRORS: u32 = 3;

/// Longest accepted `session_id`, in characters.
const MAX_SESSION_ID_CHARS: usize = 64;

/// Token bucket refilling at a fixed rate up to a burst size.
pub struct TokenBucket {
    /// Tokens added per second.
    rate: f64,
    /// Maximum number of tokens.
    burst: f64,
    /// Tokens currently available.
    tokens: f64,
    /// When `tokens` was last brought up to date.
    last: Instant,
}

impl TokenBucket {
    /// Creates a full bucket.
    pub fn new(rate: f64, burst: f64, now: Instant) -> Self {
        Self {
            rate,
            burst,
            tokens: burst,
            last: now,
        }
    }

    /// Takes one token at `now`; returns false when none is available.
    pub fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Builds an error message for the client.
fn error(code: WsErrorCode, message: &str) -> ServerMessage {
    ServerMessage::Error {
        code,
        message: message.to_owned(),
    }
}

/// Serializes `msg` into a text frame.
fn frame(msg: &ServerMessage) -> Message {
    Message::Text(
        serde_json::to_string(msg)
            .expect("server messages always serialize")
            .into(),
    )
}

/// Runs the connection of `device`, authenticated as `user` with device `secret`, until it ends.
pub async fn run(
    state: AppState,
    socket: WebSocket,
    user: AuthUser,
    device: DeviceId,
    secret: String,
) {
    let (conn_id, mut outbound, was_offline) = state.hub.register(device);
    tracing::info!(device_id = %device, username = %user.username, "device connected");
    if let Err(err) = devices::touch_last_seen(&state.db, device).await {
        tracing::warn!(error = %err, "recording last seen failed");
    }
    if was_offline {
        presence::spawn_broadcast(&state, device, true);
    }

    let (mut sink, mut stream) = socket.split();
    let mut bucket = TokenBucket::new(RATE_PER_SEC, BURST, Instant::now());
    let mut revalidate = tokio::time::interval(state.ws_revalidate_interval);
    revalidate.tick().await;
    let mut revalidation = Revalidation::default();
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await;

    if sink
        .send(frame(&ServerMessage::Hello { device_id: device }))
        .await
        .is_ok()
    {
        loop {
            tokio::select! {
                out = outbound.recv() => match out {
                    Some(msg) => {
                        if sink.send(frame(&msg)).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                },
                incoming = stream.next() => match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if let Some(reply) = handle_text(&state, device, &mut bucket, text.as_str()) {
                            if sink.send(frame(&reply)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Binary(_))) => {
                        let reply = error(WsErrorCode::BadMessage, "binary frames are not supported");
                        if sink.send(frame(&reply)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                },
                _ = revalidate.tick() => {
                    let verdict = check_authorized(&state, &user, device, &secret).await;
                    if !revalidation.keep(verdict) {
                        tracing::info!(device_id = %device, "credentials no longer valid, closing");
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                }
                _ = ping.tick() => {
                    if sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    if state.hub.unregister(device, conn_id) {
        if let Err(err) = devices::touch_last_seen(&state.db, device).await {
            tracing::warn!(error = %err, "recording last seen failed");
        }
        presence::spawn_broadcast(&state, device, false);
    }
    tracing::info!(device_id = %device, "device disconnected");
}

/// Handles one text frame and returns the reply to send, if any.
fn handle_text(
    state: &AppState,
    device: DeviceId,
    bucket: &mut TokenBucket,
    text: &str,
) -> Option<ServerMessage> {
    if !bucket.try_take(Instant::now()) {
        return Some(error(WsErrorCode::RateLimited, "too many messages"));
    }
    let msg: ClientMessage = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(_) => return Some(error(WsErrorCode::BadMessage, "malformed message")),
    };
    match msg {
        ClientMessage::Signal {
            to,
            session_id,
            kind,
            data,
        } => {
            let len = session_id.chars().count();
            if len == 0 || len > MAX_SESSION_ID_CHARS {
                return Some(error(
                    WsErrorCode::BadMessage,
                    "session_id must be 1 to 64 characters",
                ));
            }
            tracing::debug!(from = %device, %to, ?kind, "signal");
            let delivered = state.hub.send(
                to,
                ServerMessage::Signal {
                    from: device,
                    session_id,
                    kind,
                    data,
                },
            );
            (!delivered).then(|| error(WsErrorCode::TargetOffline, "target device is offline"))
        }
        ClientMessage::Ping => Some(ServerMessage::Pong),
        ClientMessage::TurnRequest => {
            let config = &state.config;
            let now = chrono::Utc::now().timestamp().max(0) as u64;
            let (username, password) =
                turn::credentials(&config.turn_secret, device, config.turn_ttl_secs, now);
            Some(ServerMessage::TurnCredentials {
                username,
                password,
                ttl_secs: config.turn_ttl_secs,
                urls: config.turn_urls.clone(),
            })
        }
    }
}

/// Tracks re-validation results of one connection.
#[derive(Default)]
struct Revalidation {
    /// Consecutive checks that could not reach the database.
    errors: u32,
}

impl Revalidation {
    /// Returns whether the connection may stay open after a check.
    ///
    /// `verdict` is `Some(valid)` when the check completed, or `None` when the
    /// database could not be reached. Invalid credentials close at once;
    /// unreachable databases close after [`MAX_REVALIDATION_ERRORS`]
    /// consecutive failures.
    fn keep(&mut self, verdict: Option<bool>) -> bool {
        match verdict {
            Some(valid) => {
                self.errors = 0;
                valid
            }
            None => {
                self.errors += 1;
                self.errors < MAX_REVALIDATION_ERRORS
            }
        }
    }
}

/// Checks that the session is unexpired, the user enabled and the device secret current.
///
/// Returns `None` when the database could not be reached.
async fn check_authorized(
    state: &AppState,
    user: &AuthUser,
    device: DeviceId,
    secret: &str,
) -> Option<bool> {
    let session = sessions::is_valid(&state.db, &user.token_hash).await;
    let device_ok = devices::authenticate(&state.db, user.user_id, device, secret).await;
    match (session, device_ok) {
        (Ok(s), Ok(d)) => Some(s && d),
        (Err(err), _) | (_, Err(err)) => {
            tracing::warn!(error = %err, "re-validation failed, database unavailable");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_burst_then_limits() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(50.0, 100.0, t0);
        for _ in 0..100 {
            assert!(b.try_take(t0));
        }
        assert!(!b.try_take(t0));
        assert!(b.try_take(t0 + Duration::from_millis(20)));
        assert!(!b.try_take(t0 + Duration::from_millis(20)));
        let later = t0 + Duration::from_secs(10);
        for _ in 0..100 {
            assert!(b.try_take(later));
        }
        assert!(!b.try_take(later));
    }
}

#[cfg(test)]
mod revalidation_tests {
    use super::*;

    #[test]
    fn revalidation_closes_after_repeated_errors() {
        let mut r = Revalidation::default();
        for _ in 0..(MAX_REVALIDATION_ERRORS - 1) {
            assert!(r.keep(None));
        }
        assert!(r.keep(Some(true)));
        for _ in 0..(MAX_REVALIDATION_ERRORS - 1) {
            assert!(r.keep(None));
        }
        assert!(!r.keep(None));
    }

    #[test]
    fn revalidation_closes_when_invalid() {
        let mut r = Revalidation::default();
        assert!(!r.keep(Some(false)));
    }
}
