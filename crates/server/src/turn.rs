//! Short-lived TURN credentials in coturn's `use-auth-secret` scheme.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use surf_rac_protocol::DeviceId;

/// Returns the TURN username and password for `device`, valid `ttl_secs` after `now_unix`.
///
/// The username is `<expiry_unix>:<device_id>`; the password is the
/// standard base64 of HMAC-SHA1 over the username keyed with `secret`.
pub fn credentials(
    secret: &str,
    device: DeviceId,
    ttl_secs: u64,
    now_unix: u64,
) -> (String, String) {
    let username = format!("{}:{}", now_unix + ttl_secs, device);
    let mut mac =
        Hmac::<Sha1>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    let password = STANDARD.encode(mac.finalize().into_bytes());
    (username, password)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TURN credentials for a known secret, device, TTL and time match the expected username
    /// and HMAC password.
    #[test]
    fn turn_credentials_known_vector() {
        let id = DeviceId::new(123_456_789).unwrap();
        let (user, pass) = credentials("secret", id, 3600, 1_700_000_000);
        assert_eq!(user, "1700003600:123456789");
        assert_eq!(pass, "5OOIzBlP38skkSxqVU+agRvSg2Q=");
    }
}
