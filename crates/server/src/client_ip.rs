//! Determining the client IP address of a request.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;

/// Returns the client IP of a request.
///
/// When `trust_forwarded_for` is set, the right-most entry of the last
/// `X-Forwarded-For` header is used if it parses as an IP address; that entry
/// is the one appended by the trusted reverse proxy. Otherwise, and as a
/// fallback, the TCP peer address is used.
pub fn client_ip(headers: &HeaderMap, peer: SocketAddr, trust_forwarded_for: bool) -> IpAddr {
    if trust_forwarded_for {
        let forwarded = headers
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok());
        if let Some(ip) = forwarded {
            return ip;
        }
    }
    peer.ip()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn peer() -> SocketAddr {
        "192.0.2.1:5000".parse().unwrap()
    }

    #[test]
    fn client_ip_uses_rightmost_forwarded_when_trusted() {
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", HeaderValue::from_static("1.1.1.1, 2.2.2.2"));
        h.append("x-forwarded-for", HeaderValue::from_static("3.3.3.3 , 4.4.4.4"));
        assert_eq!(client_ip(&h, peer(), true).to_string(), "4.4.4.4");
    }

    #[test]
    fn client_ip_falls_back_to_peer_on_garbage() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("nonsense"));
        assert_eq!(client_ip(&h, peer(), true).to_string(), "192.0.2.1");
        assert_eq!(client_ip(&HeaderMap::new(), peer(), true).to_string(), "192.0.2.1");
    }

    #[test]
    fn client_ip_ignores_forwarded_when_untrusted() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("1.1.1.1"));
        assert_eq!(client_ip(&h, peer(), false).to_string(), "192.0.2.1");
    }
}
