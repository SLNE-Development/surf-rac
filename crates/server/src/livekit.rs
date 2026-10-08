//! LiveKit access tokens: HS256 JWTs signed with the LiveKit API secret.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use surf_rac_protocol::DeviceId;

/// Seconds a join token stays valid after it is issued.
pub const JOIN_TOKEN_TTL_SECS: u64 = 60;

/// What a token holder may do in the room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The room's own device: publishes media and data.
    Host,
    /// An accepted viewer: subscribes and publishes data only.
    Viewer,
}

/// Returns the name of `host`'s room, `host-<device_id>`.
pub fn room_for(host: DeviceId) -> String {
    format!("host-{host}")
}

/// Returns a join token for `identity` in `room` with the grants of `role`.
///
/// The token is valid from `now_unix` for [`JOIN_TOKEN_TTL_SECS`], is issued
/// by API key `key` and signed with HMAC-SHA256 under `secret`.
pub fn token(
    key: &str,
    secret: &str,
    room: &str,
    identity: DeviceId,
    role: Role,
    now_unix: u64,
) -> String {
    let header = URL_SAFE_NO_PAD.encode(json!({"alg": "HS256", "typ": "JWT"}).to_string());
    let claims = json!({
        "iss": key,
        "sub": identity.to_string(),
        "name": identity.to_string(),
        "nbf": now_unix,
        "exp": now_unix + JOIN_TOKEN_TTL_SECS,
        "video": {
            "room": room,
            "roomJoin": true,
            "canPublish": role == Role::Host,
            "canSubscribe": true,
            "canPublishData": true,
        },
    });
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let signed = format!("{header}.{payload}");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(signed.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{signed}.{signature}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn decode_part(p: &str) -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).unwrap()).unwrap()
    }

    #[test]
    fn viewer_token_claims() {
        let id = DeviceId::new(223_456_789).unwrap();
        let secret = "s".repeat(32);
        let t = token("k", &secret, "host-123456789", id, Role::Viewer, 1_700_000_000);
        let parts: Vec<&str> = t.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(decode_part(parts[0]), json!({"alg":"HS256","typ":"JWT"}));
        let c = decode_part(parts[1]);
        assert_eq!(c["iss"], "k");
        assert_eq!(c["sub"], "223456789");
        assert_eq!(c["nbf"], 1_700_000_000u64);
        assert_eq!(c["exp"], 1_700_000_060u64);
        assert_eq!(c["video"]["room"], "host-123456789");
        assert_eq!(c["video"]["roomJoin"], true);
        assert_eq!(c["video"]["canPublish"], false);
        assert_eq!(c["video"]["canSubscribe"], true);
        assert_eq!(c["video"]["canPublishData"], true);
    }

    #[test]
    fn token_signature_verifies() {
        let secret = "s".repeat(32);
        let t = token("k", &secret, "r", DeviceId::new(123_456_789).unwrap(), Role::Host, 1);
        let (signed, sig) = t.rsplit_once('.').unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signed.as_bytes());
        mac.verify_slice(&URL_SAFE_NO_PAD.decode(sig).unwrap()).unwrap();
        assert_eq!(decode_part(t.split('.').nth(1).unwrap())["video"]["canPublish"], true);
    }

    #[test]
    fn room_name() {
        assert_eq!(room_for(DeviceId::new(123_456_789).unwrap()), "host-123456789");
    }
}
