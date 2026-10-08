//! Helpers for unit tests that need the LiveKit dev server.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::Rng;
use serde_json::json;
use sha2::Sha256;

/// Reads a required environment variable.
pub fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

/// Returns the current Unix time in seconds.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Returns a fresh random room name.
pub fn room_name() -> String {
    format!("unit-{}", rand::thread_rng().r#gen::<u64>())
}

/// Mints a LiveKit token for `identity` in `room`, valid from `nbf` to `exp`.
pub fn mint_token(room: &str, identity: &str, nbf: i64, exp: i64) -> String {
    let header = URL_SAFE_NO_PAD.encode(json!({"alg":"HS256","typ":"JWT"}).to_string());
    let claims = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": env("LIVEKIT_API_KEY"), "sub": identity, "name": identity,
            "nbf": nbf, "exp": exp,
            "video": {"room": room, "roomJoin": true, "canPublish": true,
                      "canSubscribe": true, "canPublishData": true}
        })
        .to_string(),
    );
    let signed = format!("{header}.{claims}");
    let mut mac = Hmac::<Sha256>::new_from_slice(env("LIVEKIT_API_SECRET").as_bytes()).unwrap();
    mac.update(signed.as_bytes());
    format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}
