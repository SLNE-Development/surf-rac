//! HTTP client for the signaling server's account, device, contact and presence routes.

use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use surf_rac_protocol::{
    ContactInfo, DeviceId, DeviceInfo, ErrorBody, ErrorCode, LoginRequest, LoginResponse,
    PresenceInfo, PutContactRequest, PutPublicKeyRequest, RegisterDeviceRequest,
    RegisterDeviceResponse, RegisterRequest,
};

/// How long one HTTP request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Why an API call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    /// The session token or credentials were rejected.
    #[error("not authorised")]
    Unauthorized,
    /// The request conflicts with existing state, such as a taken username.
    #[error("{0}")]
    Conflict(String),
    /// The account is temporarily locked after failed logins.
    #[error("{0}")]
    Locked(String),
    /// The server asks the client to slow down.
    #[error("too many requests, try again later")]
    RateLimited,
    /// The request was refused as invalid or not allowed.
    #[error("{0}")]
    Invalid(String),
    /// The resource does not exist.
    #[error("not found")]
    NotFound,
    /// The server could not be reached or the connection broke.
    #[error("server unreachable: {0}")]
    Network(String),
    /// The server failed or answered with something unexpected.
    #[error("server error: {0}")]
    Server(String),
}

impl ApiError {
    /// Returns a sentence suitable for showing to the user.
    pub fn user_message(&self) -> String {
        match self {
            ApiError::Unauthorized => "Wrong username or password, or your session expired.".into(),
            ApiError::Conflict(m) | ApiError::Locked(m) | ApiError::Invalid(m) => m.clone(),
            ApiError::RateLimited => "Too many attempts. Wait a moment and try again.".into(),
            ApiError::NotFound => "Not found.".into(),
            ApiError::Network(_) => "The server cannot be reached.".into(),
            ApiError::Server(_) => "The server reported an error.".into(),
        }
    }
}

/// Maps a failed response's status and body to an [`ApiError`].
pub fn error_from(status: u16, body: &[u8]) -> ApiError {
    let parsed = serde_json::from_slice::<ErrorBody>(body).ok();
    let message = parsed
        .as_ref()
        .map(|b| b.message.clone())
        .unwrap_or_else(|| format!("HTTP {status}"));
    match parsed.map(|b| b.error) {
        Some(ErrorCode::Unauthorized) => ApiError::Unauthorized,
        Some(ErrorCode::Conflict) => ApiError::Conflict(message),
        Some(ErrorCode::Locked) => ApiError::Locked(message),
        Some(ErrorCode::RateLimited) => ApiError::RateLimited,
        Some(ErrorCode::BadRequest | ErrorCode::Forbidden) => ApiError::Invalid(message),
        Some(ErrorCode::NotFound) => ApiError::NotFound,
        Some(ErrorCode::Unavailable | ErrorCode::Internal) => ApiError::Server(message),
        None => match status {
            401 => ApiError::Unauthorized,
            404 => ApiError::NotFound,
            409 => ApiError::Conflict(message),
            423 => ApiError::Locked(message),
            429 => ApiError::RateLimited,
            400..=499 => ApiError::Invalid(message),
            _ => ApiError::Server(message),
        },
    }
}

/// A client for one server, optionally authenticated with a session token.
#[derive(Clone)]
pub struct Api {
    /// Base URL without a trailing slash, e.g. `https://rac.slne.dev`.
    base: String,
    /// Session token sent as a bearer token.
    token: Option<String>,
    /// The shared HTTP client.
    http: reqwest::Client,
}

impl std::fmt::Debug for Api {
    /// Writes the base URL without the token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// Creates an unauthenticated client for the server at `base`.
    pub fn new(base: &str) -> Api {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .expect("HTTP client with default TLS settings");
        Api {
            base: base.trim_end_matches('/').to_string(),
            token: None,
            http,
        }
    }

    /// Returns a client for the same server that sends `token`.
    pub fn with_token(&self, token: Option<String>) -> Api {
        Api {
            token,
            ..self.clone()
        }
    }

    /// Returns the server's base URL.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Returns the WebSocket base URL: `ws://` for `http://`, `wss://` for `https://`.
    pub fn ws_url(&self) -> String {
        if let Some(rest) = self.base.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.base.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            self.base.clone()
        }
    }

    /// Creates an account with an invite code.
    pub async fn register(
        &self,
        invite: &str,
        username: &str,
        password: &str,
    ) -> Result<(), ApiError> {
        let body = RegisterRequest {
            invite_code: invite.into(),
            username: username.into(),
            password: password.into(),
        };
        self.send(self.http.post(self.url("/v1/register")).json(&body))
            .await?;
        Ok(())
    }

    /// Logs in and returns the session token.
    pub async fn login(&self, username: &str, password: &str) -> Result<String, ApiError> {
        let body = LoginRequest {
            username: username.into(),
            password: password.into(),
        };
        let res: LoginResponse = self
            .json(self.http.post(self.url("/v1/login")).json(&body))
            .await?;
        Ok(res.token)
    }

    /// Ends the session of this client's token.
    pub async fn logout(&self) -> Result<(), ApiError> {
        self.send(self.http.post(self.url("/v1/logout"))).await?;
        Ok(())
    }

    /// Registers this machine as a device, or re-binds `device_id` to it.
    pub async fn register_device(
        &self,
        fingerprint_hash: &str,
        name: &str,
        device_id: Option<DeviceId>,
    ) -> Result<RegisterDeviceResponse, ApiError> {
        let body = RegisterDeviceRequest {
            fingerprint_hash: fingerprint_hash.into(),
            name: name.into(),
            device_id,
        };
        self.json(self.http.post(self.url("/v1/devices")).json(&body))
            .await
    }

    /// Lists the account's devices.
    pub async fn devices(&self) -> Result<Vec<DeviceInfo>, ApiError> {
        self.json(self.http.get(self.url("/v1/devices"))).await
    }

    /// Removes one of the account's devices.
    pub async fn delete_device(&self, id: DeviceId) -> Result<(), ApiError> {
        self.send(self.http.delete(self.url(&format!("/v1/devices/{id}"))))
            .await?;
        Ok(())
    }

    /// Publishes the X25519 public key of one of the account's devices.
    pub async fn put_public_key(&self, id: DeviceId, public_key: &str) -> Result<(), ApiError> {
        let body = PutPublicKeyRequest {
            public_key: public_key.into(),
        };
        self.put(&format!("/v1/devices/{id}/public-key"), &body)
            .await
    }

    /// Lists the account's contacts with their presence.
    pub async fn contacts(&self) -> Result<Vec<ContactInfo>, ApiError> {
        self.json(self.http.get(self.url("/v1/contacts"))).await
    }

    /// Adds a contact or changes its alias.
    pub async fn put_contact(&self, id: DeviceId, alias: &str) -> Result<(), ApiError> {
        let body = PutContactRequest {
            alias: alias.into(),
        };
        self.put(&format!("/v1/contacts/{id}"), &body).await
    }

    /// Removes a contact.
    pub async fn delete_contact(&self, id: DeviceId) -> Result<(), ApiError> {
        self.send(self.http.delete(self.url(&format!("/v1/contacts/{id}"))))
            .await?;
        Ok(())
    }

    /// Returns whether a device is online and its published public key.
    pub async fn presence(&self, id: DeviceId) -> Result<PresenceInfo, ApiError> {
        self.json(self.http.get(self.url(&format!("/v1/presence/{id}"))))
            .await
    }

    /// Returns the absolute URL of `path`.
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// Sends a PUT with a JSON body and ignores the response body.
    async fn put<B: Serialize>(&self, path: &str, body: &B) -> Result<(), ApiError> {
        self.send(self.http.put(self.url(path)).json(body)).await?;
        Ok(())
    }

    /// Sends a request and parses its JSON response.
    async fn json<T: DeserializeOwned>(&self, req: reqwest::RequestBuilder) -> Result<T, ApiError> {
        let res = self.send(req).await?;
        res.json()
            .await
            .map_err(|e| ApiError::Server(format!("unexpected response: {e}")))
    }

    /// Sends a request with the token and turns failure statuses into errors.
    async fn send(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response, ApiError> {
        let req = match &self.token {
            Some(token) => req.bearer_auth(token),
            None => req,
        };
        let res = req
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        if res.status().is_success() {
            return Ok(res);
        }
        let status = res.status().as_u16();
        let body = res.bytes().await.unwrap_or_default();
        Err(error_from(status, &body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(code: &str) -> Vec<u8> {
        serde_json::json!({"error": code, "message": "msg"})
            .to_string()
            .into_bytes()
    }

    #[test]
    fn ws_url_follows_scheme() {
        assert_eq!(
            Api::new("https://rac.slne.dev/").ws_url(),
            "wss://rac.slne.dev"
        );
        assert_eq!(
            Api::new("http://127.0.0.1:8080").ws_url(),
            "ws://127.0.0.1:8080"
        );
    }

    #[test]
    fn error_codes_map_to_errors() {
        assert_eq!(
            error_from(401, &body("unauthorized")),
            ApiError::Unauthorized
        );
        assert_eq!(
            error_from(409, &body("conflict")),
            ApiError::Conflict("msg".into())
        );
        assert_eq!(
            error_from(423, &body("locked")),
            ApiError::Locked("msg".into())
        );
        assert_eq!(
            error_from(429, &body("rate_limited")),
            ApiError::RateLimited
        );
        assert_eq!(
            error_from(400, &body("bad_request")),
            ApiError::Invalid("msg".into())
        );
        assert_eq!(
            error_from(403, &body("forbidden")),
            ApiError::Invalid("msg".into())
        );
        assert_eq!(error_from(404, &body("not_found")), ApiError::NotFound);
        assert_eq!(
            error_from(500, &body("internal")),
            ApiError::Server("msg".into())
        );
    }

    #[test]
    fn non_json_bodies_map_by_status() {
        assert_eq!(error_from(401, b"<html>"), ApiError::Unauthorized);
        assert_eq!(error_from(404, b""), ApiError::NotFound);
        assert_eq!(error_from(429, b""), ApiError::RateLimited);
        assert_eq!(error_from(418, b""), ApiError::Invalid("HTTP 418".into()));
        assert_eq!(
            error_from(502, b"bad gateway"),
            ApiError::Server("HTTP 502".into())
        );
    }

    #[test]
    fn debug_hides_token() {
        let api = Api::new("http://x").with_token(Some("secret-token".into()));
        assert!(!format!("{api:?}").contains("secret-token"));
    }
}
