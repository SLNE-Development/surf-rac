//! Lifecycle of one device's WebSocket connection.
//!
//! A new connection first receives a `challenge` with a fresh random nonce and
//! must answer it with an `authenticate` signed by the device's identity key.
//! Only then does it register in the hub and receive `hello`. It then relays
//! signaling until the client leaves, the hub closes it (replacement) or a
//! periodic re-validation finds the device disabled or cannot reach the
//! database several times in a row.

use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use surf_rac_protocol::{
    ClientMessage, DeviceId, MAX_SEALED_PASSWORD_LEN, ServerMessage, WsErrorCode,
};

use crate::devices::{self, DeviceError, DeviceIdentity};
use crate::livekit::{self, Role};
use crate::presence;
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

/// The authenticated device of a connection, as stamped on the messages it sends.
struct Sender {
    /// The device's ID.
    device: DeviceId,
    /// The device's identity public key as standard base64.
    identity_key: String,
    /// The device's name.
    name: String,
}

/// Runs the connection of `device`, whose registered identity is `identity`, until it ends.
///
/// The device is connected only after it answers the challenge; a connection
/// that fails the challenge never replaces a live connection of the device.
pub async fn run(state: AppState, socket: WebSocket, device: DeviceId, identity: DeviceIdentity) {
    let (mut sink, mut stream) = socket.split();
    if !handshake(&state, &mut sink, &mut stream, device).await {
        let _ = sink.send(Message::Close(None)).await;
        return;
    }
    let sender = Sender {
        device,
        identity_key: STANDARD.encode(identity.public_key),
        name: identity.name,
    };

    let (conn_id, mut outbound, was_offline) = state.hub.register(device);
    tracing::info!(device_id = %device, "device connected");
    if let Err(err) = devices::touch_last_seen(&state.db, device).await {
        tracing::warn!(error = %err, "recording last seen failed");
    }
    if was_offline {
        presence::spawn_broadcast(&state, device, true);
    }

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
                        if let Some(reply) = handle_text(&state, &sender, &mut bucket, text.as_str())
                            && sink.send(frame(&reply)).await.is_err()
                        {
                            break;
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
                    let verdict = check_active(&state, device).await;
                    if !revalidation.keep(verdict) {
                        tracing::info!(device_id = %device, "device no longer active, closing");
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

/// Sends a challenge with a fresh random nonce and checks the device's answer.
///
/// The nonce exists only for this call, so a signature is valid for this one
/// connection only. Returns true when an `authenticate` arrives within
/// `state.ws_auth_timeout` whose signature verifies against `device`'s
/// identity key and whose fingerprint matches. On any other outcome the
/// client is sent an error, where one applies, and false is returned.
async fn handshake(
    state: &AppState,
    sink: &mut SplitSink<WebSocket, Message>,
    stream: &mut SplitStream<WebSocket>,
    device: DeviceId,
) -> bool {
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let challenge = ServerMessage::Challenge {
        nonce: STANDARD.encode(nonce),
    };
    if sink.send(frame(&challenge)).await.is_err() {
        return false;
    }
    let text = match tokio::time::timeout(state.ws_auth_timeout, next_text(stream)).await {
        Ok(Some(text)) => text,
        Ok(None) => return false,
        Err(_) => {
            tracing::info!(device_id = %device, "no challenge answer in time");
            return false;
        }
    };
    let verdict = match serde_json::from_str::<ClientMessage>(&text) {
        Ok(ClientMessage::Authenticate {
            signature,
            fingerprint_hash,
        }) => match decode_array::<64>(&signature) {
            Some(signature) => {
                devices::authenticate(&state.db, device, &fingerprint_hash, &nonce, &signature)
                    .await
            }
            None => Err(DeviceError::BadSignature),
        },
        _ => {
            let reply = error(WsErrorCode::BadMessage, "expected authenticate");
            let _ = sink.send(frame(&reply)).await;
            return false;
        }
    };
    let reply = match verdict {
        Ok(()) => return true,
        Err(DeviceError::CloneDetected) => {
            tracing::warn!(device_id = %device, "clone detected");
            error(
                WsErrorCode::CloneDetected,
                "identity key is registered for another installation",
            )
        }
        Err(DeviceError::Disabled) => error(WsErrorCode::Forbidden, "device is disabled"),
        Err(DeviceError::Db(err)) => {
            tracing::warn!(error = %err, "challenge check failed, database unavailable");
            return false;
        }
        Err(_) => {
            tracing::info!(device_id = %device, "bad challenge signature");
            error(WsErrorCode::BadSignature, "signature does not verify")
        }
    };
    let _ = sink.send(frame(&reply)).await;
    false
}

/// Returns the next text frame of `stream`, skipping pings and pongs.
///
/// Returns `None` when the client closes, the connection fails or a binary
/// frame arrives.
async fn next_text(stream: &mut SplitStream<WebSocket>) -> Option<String> {
    loop {
        match stream.next().await? {
            Ok(Message::Text(text)) => return Some(text.as_str().to_owned()),
            Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            Ok(Message::Binary(_) | Message::Close(_)) | Err(_) => return None,
        }
    }
}

/// Handles one text frame from `sender` and returns the reply to send, if any.
fn handle_text(
    state: &AppState,
    sender: &Sender,
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
    let device = sender.device;
    match msg {
        ClientMessage::Signal {
            to,
            session_id,
            kind,
            data,
        } => {
            if !valid_session_id(&session_id) {
                return Some(bad_session_id());
            }
            tracing::debug!(from = %device, %to, ?kind, "signal");
            relay(
                state,
                to,
                ServerMessage::Signal {
                    from: device,
                    session_id,
                    kind,
                    data,
                },
            )
        }
        ClientMessage::SessionRequest {
            to,
            session_id,
            session_key,
            signature,
            unattended,
        } => {
            if !valid_session_id(&session_id) {
                return Some(bad_session_id());
            }
            if !valid_key(&session_key) {
                return Some(bad_key());
            }
            if !valid_signature(&signature) {
                return Some(bad_signature_format());
            }
            tracing::info!(viewer = %device, host = %to, %session_id, "session requested");
            relay(
                state,
                to,
                ServerMessage::SessionRequest {
                    from: device,
                    session_id,
                    session_key,
                    signature,
                    identity_key: sender.identity_key.clone(),
                    name: sender.name.clone(),
                    unattended,
                },
            )
        }
        ClientMessage::PasswordChallenge {
            to,
            session_id,
            session_key,
            signature,
            host_nonce,
        } => {
            if !valid_session_id(&session_id) {
                return Some(bad_session_id());
            }
            if !valid_key(&session_key) || !valid_key(&host_nonce) {
                return Some(bad_key());
            }
            if !valid_signature(&signature) {
                return Some(bad_signature_format());
            }
            tracing::info!(host = %device, viewer = %to, %session_id, "password challenge");
            relay(
                state,
                to,
                ServerMessage::PasswordChallenge {
                    from: device,
                    session_id,
                    session_key,
                    signature,
                    host_nonce,
                    identity_key: sender.identity_key.clone(),
                },
            )
        }
        ClientMessage::SessionPassword {
            to,
            session_id,
            password,
        } => {
            if !valid_session_id(&session_id) {
                return Some(bad_session_id());
            }
            if password.len() > MAX_SEALED_PASSWORD_LEN {
                return Some(error(WsErrorCode::BadMessage, "password too long"));
            }
            tracing::info!(viewer = %device, host = %to, %session_id, "session password");
            relay(
                state,
                to,
                ServerMessage::SessionPassword {
                    from: device,
                    session_id,
                    password,
                },
            )
        }
        ClientMessage::SessionResponse {
            to,
            session_id,
            accepted,
            reason,
            session_key,
            signature,
            host_nonce,
        } => {
            if !valid_session_id(&session_id) {
                return Some(bad_session_id());
            }
            if session_key.as_deref().is_some_and(|k| !valid_key(k))
                || host_nonce.as_deref().is_some_and(|n| !valid_key(n))
            {
                return Some(bad_key());
            }
            if signature.as_deref().is_some_and(|s| !valid_signature(s)) {
                return Some(bad_signature_format());
            }
            tracing::info!(host = %device, viewer = %to, %session_id, accepted, "session answered");
            relay(
                state,
                to,
                ServerMessage::SessionResponse {
                    from: device,
                    session_id,
                    accepted,
                    reason,
                    session_key,
                    signature,
                    host_nonce,
                    identity_key: accepted.then(|| sender.identity_key.clone()),
                },
            )
        }
        ClientMessage::Authenticate { .. } => Some(error(
            WsErrorCode::BadMessage,
            "connection is already authenticated",
        )),
        ClientMessage::LinkAccount { .. } | ClientMessage::UnlinkAccount { .. } => Some(error(
            WsErrorCode::BadMessage,
            "account linking is not supported",
        )),
        ClientMessage::HostTokenRequest => {
            let room = livekit::room_for(device);
            tracing::info!(device_id = %device, "host token issued");
            Some(ServerMessage::HostToken {
                url: state.config.livekit_url.clone(),
                token: join_token(state, &room, device, Role::Host),
                room,
            })
        }
        ClientMessage::ViewerTokenRequest {
            session_id,
            viewer_device_id,
        } => {
            if !valid_session_id(&session_id) {
                return Some(bad_session_id());
            }
            if viewer_device_id == device {
                return Some(error(
                    WsErrorCode::Forbidden,
                    "a device cannot be a viewer of its own room",
                ));
            }
            let room = livekit::room_for(device);
            tracing::info!(host = %device, viewer = %viewer_device_id, %session_id, "viewer token issued");
            relay(
                state,
                viewer_device_id,
                ServerMessage::ViewerToken {
                    from: device,
                    session_id,
                    url: state.config.livekit_url.clone(),
                    token: join_token(state, &room, viewer_device_id, Role::Viewer),
                    room,
                },
            )
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

/// Queues `msg` for `to`; returns a `target_offline` error when it cannot be delivered.
fn relay(state: &AppState, to: DeviceId, msg: ServerMessage) -> Option<ServerMessage> {
    let delivered = state.hub.send(to, msg);
    (!delivered).then(|| error(WsErrorCode::TargetOffline, "target device is offline"))
}

/// Returns whether `session_id` has 1 to [`MAX_SESSION_ID_CHARS`] characters.
fn valid_session_id(session_id: &str) -> bool {
    (1..=MAX_SESSION_ID_CHARS).contains(&session_id.chars().count())
}

/// Decodes standard base64 of exactly `N` bytes.
fn decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    STANDARD.decode(s).ok()?.try_into().ok()
}

/// Returns whether `key` (a per-session key or nonce) is standard base64 of exactly 32 bytes.
fn valid_key(key: &str) -> bool {
    decode_array::<32>(key).is_some()
}

/// Returns whether `signature` is standard base64 of exactly 64 bytes.
fn valid_signature(signature: &str) -> bool {
    decode_array::<64>(signature).is_some()
}

/// Builds the error for an invalid session ID.
fn bad_session_id() -> ServerMessage {
    error(
        WsErrorCode::BadMessage,
        "session_id must be 1 to 64 characters",
    )
}

/// Builds the error for an invalid per-session key or nonce.
fn bad_key() -> ServerMessage {
    error(
        WsErrorCode::BadMessage,
        "session key and nonce must be base64 of 32 bytes",
    )
}

/// Builds the error for a signature that is not base64 of 64 bytes.
fn bad_signature_format() -> ServerMessage {
    error(
        WsErrorCode::BadMessage,
        "signature must be base64 of 64 bytes",
    )
}

/// Mints a LiveKit join token for `identity` in `room` with the server's API key.
fn join_token(state: &AppState, room: &str, identity: DeviceId, role: Role) -> String {
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    livekit::token(
        &state.config.livekit_api_key,
        &state.config.livekit_api_secret,
        room,
        identity,
        role,
        now,
    )
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
    /// `verdict` is `Some(active)` when the check completed, or `None` when the
    /// database could not be reached. An inactive device closes at once;
    /// unreachable databases close after [`MAX_REVALIDATION_ERRORS`]
    /// consecutive failures.
    fn keep(&mut self, verdict: Option<bool>) -> bool {
        match verdict {
            Some(active) => {
                self.errors = 0;
                active
            }
            None => {
                self.errors += 1;
                self.errors < MAX_REVALIDATION_ERRORS
            }
        }
    }
}

/// Checks that `device` still exists and is not disabled.
///
/// Returns `None` when the database could not be reached.
async fn check_active(state: &AppState, device: DeviceId) -> Option<bool> {
    match devices::is_active(&state.db, device).await {
        Ok(active) => Some(active),
        Err(err) => {
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

    #[test]
    fn base64_lengths_are_checked() {
        assert!(valid_key(&STANDARD.encode([1u8; 32])));
        assert!(!valid_key(&STANDARD.encode([1u8; 31])));
        assert!(valid_signature(&STANDARD.encode([1u8; 64])));
        assert!(!valid_signature(&STANDARD.encode([1u8; 32])));
        assert!(!valid_signature("not base64!"));
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
    fn revalidation_closes_when_inactive() {
        let mut r = Revalidation::default();
        assert!(!r.keep(Some(false)));
    }
}
