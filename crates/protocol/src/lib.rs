//! Wire types shared by the surf-rac signaling server and its clients.
//!
//! HTTP bodies are JSON objects. WebSocket frames are JSON objects tagged by a
//! `type` field. Device IDs travel as 9-character decimal strings.

pub mod data;

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Request header carrying the device ID on the WebSocket upgrade.
pub const HEADER_DEVICE_ID: &str = "x-device-id";

/// Request header carrying the client's protocol version on the WebSocket upgrade.
pub const HEADER_PROTOCOL_VERSION: &str = "x-protocol-version";

/// Wire protocol version this build speaks; peers on any other version are refused
/// with `update_required`.
pub const PROTOCOL_VERSION: u32 = 2;

/// Largest WebSocket message, in bytes, the server accepts.
pub const MAX_WS_MESSAGE_BYTES: usize = 65_536;

/// Longest sealed unattended password, in base64 characters, a session password message may carry.
pub const MAX_SEALED_PASSWORD_LEN: usize = 1024;

/// Domain tag prefixed to the nonce of a signed connect challenge.
///
/// A device answers the server's `challenge` with an Ed25519 signature over
/// this tag followed by the 32 nonce bytes.
pub const CHALLENGE_DOMAIN: &[u8] = b"surf-rac/challenge/v1";

/// Domain tag prefixed to the role, session ID and key of a signed per-session key.
///
/// A peer signs this tag, its role tag (`viewer` or `host`), the session ID and
/// the 32 bytes of its per-session X25519 public key with its identity key.
pub const SESSION_DOMAIN: &[u8] = b"surf-rac/session/v1";

/// Smallest valid device ID.
const DEVICE_ID_MIN: u32 = 100_000_000;

/// Largest valid device ID.
const DEVICE_ID_MAX: u32 = 999_999_999;

/// A surf-rac device ID: a 9-digit decimal number from 100000000 to 999999999.
///
/// Serialized as a 9-character string of digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId(u32);

impl DeviceId {
    /// Creates a device ID, or returns `None` when `value` is outside the 9-digit range.
    pub fn new(value: u32) -> Option<Self> {
        (DEVICE_ID_MIN..=DEVICE_ID_MAX)
            .contains(&value)
            .then_some(Self(value))
    }

    /// Returns the numeric value of the ID.
    pub fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for DeviceId {
    /// Writes the ID as its 9 decimal digits.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error returned when a string is not a valid device ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidDeviceId;

impl fmt::Display for InvalidDeviceId {
    /// Writes a short description of the parse failure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("device id must be 9 decimal digits from 100000000 to 999999999")
    }
}

impl std::error::Error for InvalidDeviceId {}

impl FromStr for DeviceId {
    type Err = InvalidDeviceId;

    /// Parses exactly 9 ASCII digits in the valid range.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 9 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(InvalidDeviceId);
        }
        s.parse::<u32>()
            .ok()
            .and_then(DeviceId::new)
            .ok_or(InvalidDeviceId)
    }
}

impl Serialize for DeviceId {
    /// Serializes the ID as a string of digits.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    /// Deserializes the ID from a string of digits; numbers are rejected.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Body of `POST /v1/register`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Desired username: 3 to 32 characters of `[a-z0-9._-]`.
    pub username: String,
    /// Password: 10 to 256 characters.
    pub password: String,
}

/// Response of `POST /v1/register`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// The username of the created account.
    pub username: String,
}

/// Body of `POST /v1/login`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Account username.
    pub username: String,
    /// Account password.
    pub password: String,
}

/// Response of `POST /v1/login`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    /// Opaque session token, sent as `Authorization: Bearer <token>`.
    pub token: String,
    /// When the token expires unless it is used before then.
    pub expires_at: DateTime<Utc>,
}

/// Body of `POST /v1/devices`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    /// The installation's Ed25519 identity public key, standard base64 of 32 bytes.
    pub public_key: String,
    /// Lowercase hex SHA-256 of the device's hardware fingerprint (64 characters).
    pub fingerprint_hash: String,
    /// Human-readable device name, 1 to 64 characters.
    pub name: String,
    /// Protocol version the client speaks.
    pub protocol_version: u32,
}

/// Response of `POST /v1/devices`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDeviceResponse {
    /// The device's ID.
    pub device_id: DeviceId,
}

/// Body of `DELETE /v1/account`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteAccountRequest {
    /// The account password, confirming the deletion.
    pub password: String,
}

/// One entry of the signed-in account's device list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MyDeviceInfo {
    /// The device's ID.
    pub device_id: DeviceId,
    /// Human-readable device name.
    pub name: String,
    /// Whether the device currently holds a WebSocket connection.
    pub online: bool,
    /// When the device last connected or disconnected.
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// One entry of `GET /v1/devices`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceInfo {
    /// The device's ID.
    pub device_id: DeviceId,
    /// Human-readable device name.
    pub name: String,
    /// Whether the device currently holds a WebSocket connection.
    pub online: bool,
    /// When the device last connected or disconnected.
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// One entry of `GET /v1/contacts`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContactInfo {
    /// The contact's device ID.
    pub device_id: DeviceId,
    /// The alias the account gave this device.
    pub alias: String,
    /// Whether the device is currently online.
    pub online: bool,
}

/// Body of `PUT /v1/contacts/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutContactRequest {
    /// Alias for the device, 1 to 64 characters.
    pub alias: String,
}

/// Response of `GET /v1/presence/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresenceInfo {
    /// The queried device ID.
    pub device_id: DeviceId,
    /// Whether the device is currently online.
    pub online: bool,
    /// The device's X25519 public key (standard base64 of 32 bytes), when it has published one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

/// Error body of every failed HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorBody {
    /// Machine-readable error code.
    pub error: ErrorCode,
    /// Human-readable description.
    pub message: String,
}

/// Machine-readable HTTP error codes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The request is malformed or fails validation.
    BadRequest,
    /// Credentials or session token are missing or invalid.
    Unauthorized,
    /// The caller may not act on this resource.
    Forbidden,
    /// The resource does not exist.
    NotFound,
    /// The request conflicts with existing state.
    Conflict,
    /// Too many requests from this client.
    RateLimited,
    /// The client's protocol version is not supported and it must be updated.
    UpdateRequired,
    /// Two installations are using the same device identity.
    CloneDetected,
    /// The account is temporarily locked after failed logins.
    Locked,
    /// The database is unreachable.
    Unavailable,
    /// An unexpected server error.
    Internal,
}

/// Kind of a relayed WebRTC signaling message.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// SDP offer.
    Offer,
    /// SDP answer.
    Answer,
    /// ICE candidate.
    Ice,
    /// End of the signaling session.
    Hangup,
}

/// Messages a client sends over the WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Relay `data` to device `to`.
    Signal {
        /// Target device.
        to: DeviceId,
        /// Client-chosen session identifier, 1 to 64 characters.
        session_id: String,
        /// What the payload is.
        kind: SignalKind,
        /// Opaque payload; the server never inspects it.
        data: serde_json::Value,
    },
    /// Ask host device `to` for a session; relayed as a server `session_request`.
    SessionRequest {
        /// Host device.
        to: DeviceId,
        /// Viewer-chosen session identifier, 1 to 64 characters.
        session_id: String,
        /// The viewer's per-session X25519 public key, standard base64 of 32 bytes.
        session_key: String,
        /// The viewer's Ed25519 signature over the session role, session ID and
        /// `session_key`, standard base64 of 64 bytes.
        signature: String,
        /// Whether the viewer intends to authenticate with the unattended password.
        unattended: bool,
    },
    /// Offer viewer `to` the chance to send the unattended password; relayed as a server
    /// `password_challenge`.
    PasswordChallenge {
        /// Viewer device.
        to: DeviceId,
        /// Session identifier of the request.
        session_id: String,
        /// The host's per-session X25519 public key, standard base64 of 32 bytes.
        session_key: String,
        /// The host's Ed25519 signature over the session role, session ID and
        /// `session_key`, standard base64 of 64 bytes.
        signature: String,
        /// Random bytes the host chose for this session's key, standard base64 of 32 bytes.
        host_nonce: String,
    },
    /// Send host `to` the unattended password; relayed as a server `session_password`.
    SessionPassword {
        /// Host device.
        to: DeviceId,
        /// Session identifier of the request.
        session_id: String,
        /// The password sealed for the host's per-session key, standard base64 of a 12-byte
        /// nonce followed by the ciphertext, at most [`MAX_SEALED_PASSWORD_LEN`] characters.
        password: String,
    },
    /// Answer a session request from viewer `to`; relayed as a server `session_response`.
    SessionResponse {
        /// Viewer device.
        to: DeviceId,
        /// Session identifier of the request.
        session_id: String,
        /// Whether the host accepted the session.
        accepted: bool,
        /// Why the session was refused, when it was.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<DenyReason>,
        /// The host's per-session X25519 public key, standard base64 of 32 bytes, when accepted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_key: Option<String>,
        /// The host's Ed25519 signature over the session role, session ID and
        /// `session_key`, standard base64 of 64 bytes, when accepted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        /// Random bytes the host chose for this session's key, standard base64 of 32 bytes, when accepted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host_nonce: Option<String>,
    },
    /// Prove ownership of the device identity by answering the server's challenge.
    Authenticate {
        /// Ed25519 signature over the challenge domain tag and nonce, standard base64 of 64 bytes.
        signature: String,
        /// Lowercase hex SHA-256 of the device's hardware fingerprint (64 characters).
        fingerprint_hash: String,
    },
    /// Link this device to the account that issued `token`; answered with `linked`.
    LinkAccount {
        /// Account session token from `POST /v1/login`.
        token: String,
    },
    /// Remove this device from the account that issued `token`; answered with `unlinked`.
    UnlinkAccount {
        /// Account session token from `POST /v1/login`.
        token: String,
    },
    /// Ask for a LiveKit token for this device's own room; answered with `host_token`.
    HostTokenRequest,
    /// Ask the server to issue a viewer token for this device's room to `viewer_device_id`.
    ViewerTokenRequest {
        /// Session the token is for.
        session_id: String,
        /// The accepted viewer device.
        viewer_device_id: DeviceId,
    },
    /// Ask for short-lived TURN credentials.
    TurnRequest,
    /// Application-level keepalive; answered with `pong`.
    Ping,
}

/// Messages the server sends over the WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// First message after the upgrade; the client answers with `authenticate`.
    Challenge {
        /// Random nonce to sign, standard base64 of 32 bytes.
        nonce: String,
    },
    /// First message after a successful connect.
    Hello {
        /// The authenticated device ID of this connection.
        device_id: DeviceId,
    },
    /// A signaling message relayed from another device.
    Signal {
        /// Sender device, set by the server.
        from: DeviceId,
        /// Session identifier chosen by the sender.
        session_id: String,
        /// What the payload is.
        kind: SignalKind,
        /// Opaque payload from the sender.
        data: serde_json::Value,
    },
    /// A viewer asks this device for a session.
    SessionRequest {
        /// Viewer device, set by the server.
        from: DeviceId,
        /// Session identifier chosen by the viewer.
        session_id: String,
        /// The viewer's per-session X25519 public key, standard base64 of 32 bytes.
        session_key: String,
        /// The viewer's Ed25519 signature over the session role, session ID and
        /// `session_key`, standard base64 of 64 bytes.
        signature: String,
        /// The viewer's Ed25519 identity public key as attested by the server,
        /// standard base64 of 32 bytes.
        identity_key: String,
        /// The viewer device's name.
        name: String,
        /// Whether the viewer intends to authenticate with the unattended password.
        unattended: bool,
    },
    /// A host offers this device the chance to send the unattended password.
    PasswordChallenge {
        /// Host device, set by the server.
        from: DeviceId,
        /// Session identifier of the request.
        session_id: String,
        /// The host's per-session X25519 public key, standard base64 of 32 bytes.
        session_key: String,
        /// The host's Ed25519 signature over the session role, session ID and
        /// `session_key`, standard base64 of 64 bytes.
        signature: String,
        /// Random bytes the host chose for this session's key, standard base64 of 32 bytes.
        host_nonce: String,
        /// The host's Ed25519 identity public key as attested by the server,
        /// standard base64 of 32 bytes.
        identity_key: String,
    },
    /// A viewer sends this device the unattended password.
    SessionPassword {
        /// Viewer device, set by the server.
        from: DeviceId,
        /// Session identifier of the request.
        session_id: String,
        /// The password sealed for this device's per-session key, as the viewer sent it;
        /// at most [`MAX_SEALED_PASSWORD_LEN`] characters.
        password: String,
    },
    /// A host answered this device's session request.
    SessionResponse {
        /// Host device, set by the server.
        from: DeviceId,
        /// Session identifier of the request.
        session_id: String,
        /// Whether the host accepted the session.
        accepted: bool,
        /// Why the session was refused, when it was.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<DenyReason>,
        /// The host's per-session X25519 public key, standard base64 of 32 bytes, when accepted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_key: Option<String>,
        /// The host's Ed25519 signature over the session role, session ID and
        /// `session_key`, standard base64 of 64 bytes, when accepted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        /// Random bytes the host chose for this session's key, standard base64 of 32 bytes, when accepted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host_nonce: Option<String>,
        /// The host's Ed25519 identity public key as attested by the server,
        /// standard base64 of 32 bytes, when accepted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity_key: Option<String>,
    },
    /// LiveKit join token for this device's own room.
    HostToken {
        /// LiveKit server URL.
        url: String,
        /// Room name, `host-<device_id>`.
        room: String,
        /// Short-lived join token.
        token: String,
    },
    /// LiveKit join token for a host's room, issued on that host's request.
    ViewerToken {
        /// Host device that requested the token, set by the server.
        from: DeviceId,
        /// Session the token is for.
        session_id: String,
        /// LiveKit server URL.
        url: String,
        /// Room name, `host-<host_device_id>`.
        room: String,
        /// Short-lived join token bound to this device's identity.
        token: String,
    },
    /// Short-lived TURN credentials.
    TurnCredentials {
        /// TURN username (`<expiry_unix>:<device_id>`).
        username: String,
        /// TURN password (base64 HMAC-SHA1).
        password: String,
        /// Lifetime of the credentials in seconds.
        ttl_secs: u64,
        /// TURN server URLs.
        urls: Vec<String>,
    },
    /// A watched device went online or offline.
    Presence {
        /// The device whose state changed.
        device_id: DeviceId,
        /// Its new state.
        online: bool,
    },
    /// Answer to `ping`.
    Pong,
    /// A client message could not be handled.
    Error {
        /// Machine-readable error code.
        code: WsErrorCode,
        /// Human-readable description.
        message: String,
    },
    /// This connection was superseded and is about to be closed.
    Replaced,
    /// This device was linked to the account named `username`.
    Linked {
        /// Username of the account the device is now linked to.
        username: String,
    },
    /// This device was removed from its account.
    Unlinked,
}

/// Why a host refused a session request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// The host declined the request.
    Denied,
    /// The host's room already holds the maximum number of viewers.
    RoomFull,
    /// The viewer's public key differs from the one the host pinned.
    KeyChanged,
}

/// Machine-readable WebSocket error codes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WsErrorCode {
    /// The target device is not connected.
    TargetOffline,
    /// The message is not valid JSON, has an unknown type or invalid fields.
    BadMessage,
    /// The connection exceeded its message rate.
    RateLimited,
    /// The device may not make this request.
    Forbidden,
    /// The client's protocol version is not supported and it must be updated.
    UpdateRequired,
    /// Two installations are using the same device identity.
    CloneDetected,
    /// A signature did not verify against the claimed identity key.
    BadSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn device_id_rejects_out_of_range() {
        assert!(DeviceId::new(99_999_999).is_none());
        assert!(DeviceId::new(1_000_000_000).is_none());
        assert_eq!(DeviceId::new(100_000_000).unwrap().get(), 100_000_000);
        assert_eq!(DeviceId::new(999_999_999).unwrap().get(), 999_999_999);
    }

    #[test]
    fn device_id_serializes_as_string() {
        let id = DeviceId::new(123_456_789).unwrap();
        assert_eq!(serde_json::to_value(id).unwrap(), json!("123456789"));
        let back: DeviceId = serde_json::from_value(json!("123456789")).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn device_id_parse_rejects_non_digits() {
        assert!("12345678a".parse::<DeviceId>().is_err());
        assert!("+23456789".parse::<DeviceId>().is_err());
        assert!("0123456789".parse::<DeviceId>().is_err());
        assert!(serde_json::from_value::<DeviceId>(json!(123456789)).is_err());
    }

    #[test]
    fn client_signal_round_trip() {
        let raw = json!({"type":"signal","to":"123456789","session_id":"s1","kind":"offer","data":{"sdp":"x"}});
        let msg: ClientMessage = serde_json::from_value(raw.clone()).unwrap();
        match &msg {
            ClientMessage::Signal {
                to,
                session_id,
                kind,
                data,
            } => {
                assert_eq!(to.get(), 123_456_789);
                assert_eq!(session_id, "s1");
                assert_eq!(*kind, SignalKind::Offer);
                assert_eq!(data, &json!({"sdp":"x"}));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(serde_json::to_value(&msg).unwrap(), raw);
    }

    #[test]
    fn unit_client_messages_parse() {
        let turn: ClientMessage = serde_json::from_value(json!({"type":"turn_request"})).unwrap();
        assert_eq!(turn, ClientMessage::TurnRequest);
        let ping: ClientMessage = serde_json::from_value(json!({"type":"ping"})).unwrap();
        assert_eq!(ping, ClientMessage::Ping);
    }

    #[test]
    fn server_error_serializes_snake_case() {
        let msg = ServerMessage::Error {
            code: WsErrorCode::TargetOffline,
            message: "offline".into(),
        };
        assert_eq!(
            serde_json::to_value(&msg).unwrap(),
            json!({"type":"error","code":"target_offline","message":"offline"})
        );
        assert_eq!(
            serde_json::to_value(ServerMessage::Replaced).unwrap(),
            json!({"type":"replaced"})
        );
    }

    #[test]
    fn http_error_code_serializes_snake_case() {
        let body = ErrorBody {
            error: ErrorCode::RateLimited,
            message: "slow down".into(),
        };
        assert_eq!(
            serde_json::to_value(&body).unwrap(),
            json!({"error":"rate_limited","message":"slow down"})
        );
    }

    #[test]
    fn unknown_type_fails() {
        assert!(serde_json::from_value::<ClientMessage>(json!({"type":"nope"})).is_err());
        assert!(serde_json::from_value::<ClientMessage>(json!({"to":"123456789"})).is_err());
    }

    #[test]
    fn token_messages_round_trip() {
        let req: ClientMessage =
            serde_json::from_value(json!({"type":"host_token_request"})).unwrap();
        assert_eq!(req, ClientMessage::HostTokenRequest);
        let v: ClientMessage = serde_json::from_value(
            json!({"type":"viewer_token_request","session_id":"s","viewer_device_id":"223456789"}),
        )
        .unwrap();
        assert!(matches!(v, ClientMessage::ViewerTokenRequest { .. }));
        let t = ServerMessage::ViewerToken {
            from: DeviceId::new(123_456_789).unwrap(),
            session_id: "s".into(),
            url: "ws://x".into(),
            room: "host-123456789".into(),
            token: "t".into(),
        };
        assert_eq!(serde_json::to_value(&t).unwrap()["type"], "viewer_token");
    }

    #[test]
    fn presence_public_key_optional() {
        let p: PresenceInfo =
            serde_json::from_value(json!({"device_id":"123456789","online":true})).unwrap();
        assert!(p.public_key.is_none());
    }

    #[test]
    fn protocol_version_is_two() {
        assert_eq!(PROTOCOL_VERSION, 2);
        assert_eq!(HEADER_PROTOCOL_VERSION, "x-protocol-version");
    }

    #[test]
    fn domain_tags_are_fixed() {
        assert_eq!(CHALLENGE_DOMAIN, b"surf-rac/challenge/v1");
        assert_eq!(SESSION_DOMAIN, b"surf-rac/session/v1");
    }

    #[test]
    fn challenge_round_trip() {
        let raw = json!({"type":"challenge","nonce":"AAAA"});
        let msg: ServerMessage = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(msg, ServerMessage::Challenge { nonce: "AAAA".into() });
        assert_eq!(serde_json::to_value(&msg).unwrap(), raw);
    }

    #[test]
    fn authenticate_round_trip() {
        let raw = json!({"type":"authenticate","signature":"c2ln","fingerprint_hash":"ab"});
        let msg: ClientMessage = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(
            msg,
            ClientMessage::Authenticate {
                signature: "c2ln".into(),
                fingerprint_hash: "ab".into()
            }
        );
        assert_eq!(serde_json::to_value(&msg).unwrap(), raw);
    }

    #[test]
    fn signed_session_request_round_trip() {
        let raw = json!({"type":"session_request","to":"123456789","session_id":"s1",
                         "session_key":"a2V5","signature":"c2ln","unattended":true});
        let msg: ClientMessage = serde_json::from_value(raw.clone()).unwrap();
        assert!(matches!(msg, ClientMessage::SessionRequest { unattended: true, .. }));
        assert_eq!(serde_json::to_value(&msg).unwrap(), raw);
        assert!(serde_json::to_value(&msg).unwrap().get("password").is_none());

        let relayed = json!({"type":"session_request","from":"123456789","session_id":"s1",
                             "session_key":"a2V5","signature":"c2ln","identity_key":"aWQ=",
                             "name":"pc","unattended":false});
        let msg: ServerMessage = serde_json::from_value(relayed.clone()).unwrap();
        let ServerMessage::SessionRequest { identity_key, name, .. } = &msg else {
            panic!("not a session request");
        };
        assert_eq!(identity_key, "aWQ=");
        assert_eq!(name, "pc");
        assert_eq!(serde_json::to_value(&msg).unwrap(), relayed);
    }

    #[test]
    fn password_challenge_and_session_password_round_trip() {
        let challenge = json!({"type":"password_challenge","to":"123456789","session_id":"s1",
                               "session_key":"a2V5","signature":"c2ln","host_nonce":"bm9uY2U="});
        let msg: ClientMessage = serde_json::from_value(challenge.clone()).unwrap();
        assert!(matches!(msg, ClientMessage::PasswordChallenge { .. }));
        assert_eq!(serde_json::to_value(&msg).unwrap(), challenge);

        let relayed = json!({"type":"password_challenge","from":"123456789","session_id":"s1",
                             "session_key":"a2V5","signature":"c2ln","host_nonce":"bm9uY2U=",
                             "identity_key":"aWQ="});
        let msg: ServerMessage = serde_json::from_value(relayed.clone()).unwrap();
        assert!(matches!(msg, ServerMessage::PasswordChallenge { .. }));
        assert_eq!(serde_json::to_value(&msg).unwrap(), relayed);

        let password = json!({"type":"session_password","to":"123456789","session_id":"s1",
                              "password":"c2VhbGVk"});
        let msg: ClientMessage = serde_json::from_value(password.clone()).unwrap();
        assert!(matches!(msg, ClientMessage::SessionPassword { .. }));
        assert_eq!(serde_json::to_value(&msg).unwrap(), password);

        let relayed = json!({"type":"session_password","from":"123456789","session_id":"s1",
                             "password":"c2VhbGVk"});
        let msg: ServerMessage = serde_json::from_value(relayed.clone()).unwrap();
        assert!(matches!(msg, ServerMessage::SessionPassword { .. }));
        assert_eq!(serde_json::to_value(&msg).unwrap(), relayed);
    }

    #[test]
    fn signed_session_response_round_trip() {
        let accepted = json!({"type":"session_response","to":"123456789","session_id":"s1",
                              "accepted":true,"session_key":"a2V5","signature":"c2ln",
                              "host_nonce":"bm9uY2U="});
        let msg: ClientMessage = serde_json::from_value(accepted.clone()).unwrap();
        assert_eq!(serde_json::to_value(&msg).unwrap(), accepted);

        let denied = json!({"type":"session_response","to":"123456789","session_id":"s1",
                            "accepted":false,"reason":"denied"});
        let msg: ClientMessage = serde_json::from_value(denied.clone()).unwrap();
        assert_eq!(serde_json::to_value(&msg).unwrap(), denied);

        let relayed = json!({"type":"session_response","from":"123456789","session_id":"s1",
                             "accepted":true,"session_key":"a2V5","signature":"c2ln",
                             "host_nonce":"bm9uY2U=","identity_key":"aWQ="});
        let msg: ServerMessage = serde_json::from_value(relayed.clone()).unwrap();
        assert_eq!(serde_json::to_value(&msg).unwrap(), relayed);
    }

    #[test]
    fn link_account_messages_round_trip() {
        let raw = json!({"type":"link_account","token":"t"});
        let msg: ClientMessage = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(msg, ClientMessage::LinkAccount { token: "t".into() });
        assert_eq!(serde_json::to_value(&msg).unwrap(), raw);
        let raw = json!({"type":"unlink_account","token":"t"});
        let msg: ClientMessage = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(msg, ClientMessage::UnlinkAccount { token: "t".into() });
        let linked = json!({"type":"linked","username":"bob"});
        let msg: ServerMessage = serde_json::from_value(linked.clone()).unwrap();
        assert_eq!(serde_json::to_value(&msg).unwrap(), linked);
        assert_eq!(
            serde_json::to_value(ServerMessage::Unlinked).unwrap(),
            json!({"type":"unlinked"})
        );
    }

    #[test]
    fn register_request_has_no_invite() {
        let value = serde_json::to_value(RegisterRequest {
            username: "bob".into(),
            password: "pw".into(),
        })
        .unwrap();
        let mut keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["password", "username"]);
    }

    #[test]
    fn register_device_bodies_round_trip() {
        let req: RegisterDeviceRequest = serde_json::from_value(json!({
            "public_key":"a2V5","fingerprint_hash":"ab","name":"pc","protocol_version":2
        }))
        .unwrap();
        assert_eq!(req.protocol_version, PROTOCOL_VERSION);
        let resp = RegisterDeviceResponse { device_id: DeviceId::new(123_456_789).unwrap() };
        assert_eq!(
            serde_json::to_value(&resp).unwrap(),
            json!({"device_id":"123456789"})
        );
    }

    #[test]
    fn account_bodies_and_new_error_codes() {
        let del: DeleteAccountRequest = serde_json::from_value(json!({"password":"pw"})).unwrap();
        assert_eq!(del.password, "pw");
        let info = MyDeviceInfo {
            device_id: DeviceId::new(123_456_789).unwrap(),
            name: "pc".into(),
            online: true,
            last_seen_at: None,
        };
        assert_eq!(serde_json::to_value(&info).unwrap()["name"], "pc");
        assert_eq!(serde_json::to_value(ErrorCode::UpdateRequired).unwrap(), json!("update_required"));
        assert_eq!(serde_json::to_value(ErrorCode::CloneDetected).unwrap(), json!("clone_detected"));
        assert_eq!(serde_json::to_value(WsErrorCode::UpdateRequired).unwrap(), json!("update_required"));
        assert_eq!(serde_json::to_value(WsErrorCode::CloneDetected).unwrap(), json!("clone_detected"));
        assert_eq!(serde_json::to_value(WsErrorCode::BadSignature).unwrap(), json!("bad_signature"));
    }
}
