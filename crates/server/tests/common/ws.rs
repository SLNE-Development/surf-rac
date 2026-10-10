//! WebSocket helpers for the integration tests.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::{Identity, TestApp, sign_challenge};

/// A client WebSocket connection to the test server.
pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// How long helpers wait for an expected frame.
const RECV_TIMEOUT: Duration = Duration::from_secs(3);

/// A refused WebSocket upgrade: the HTTP status and the JSON body, if any.
#[derive(Debug)]
pub struct Refused {
    /// HTTP status of the refusal.
    pub status: u16,
    /// Response body parsed as JSON, when it is JSON.
    pub body: Option<Value>,
}

/// An online test device: its identity and open socket.
pub struct Device {
    /// Device ID.
    pub id: String,
    /// Identity key of the device.
    pub key: SigningKey,
    /// Fingerprint hash of the device.
    pub fingerprint: String,
    /// Open socket, past the `hello` message.
    pub ws: Ws,
}

impl TestApp {
    /// Opens `/v1/ws` with the given device ID and protocol version headers, omitting
    /// each one that is `None`; `Err` carries the refusal.
    pub async fn ws_open(
        &self,
        device_id: Option<&str>,
        protocol_version: Option<&str>,
    ) -> Result<Ws, Refused> {
        let mut req = format!("ws://{}/v1/ws", self.addr)
            .into_client_request()
            .unwrap();
        let h = req.headers_mut();
        if let Some(id) = device_id {
            h.insert("x-device-id", id.parse().unwrap());
        }
        if let Some(v) = protocol_version {
            h.insert("x-protocol-version", v.parse().unwrap());
        }
        match tokio_tungstenite::connect_async(req).await {
            Ok((ws, _)) => Ok(ws),
            Err(tokio_tungstenite::tungstenite::Error::Http(res)) => Err(Refused {
                status: res.status().as_u16(),
                body: res
                    .body()
                    .as_deref()
                    .and_then(|b| serde_json::from_slice(b).ok()),
            }),
            Err(e) => panic!("websocket connect failed: {e}"),
        }
    }

    /// Opens `/v1/ws` for `device_id` at the current protocol version and returns
    /// the socket together with the decoded challenge nonce.
    pub async fn ws_challenged(&self, device_id: &str) -> (Ws, Vec<u8>) {
        let version = surf_rac_protocol::PROTOCOL_VERSION.to_string();
        let mut ws = self
            .ws_open(Some(device_id), Some(&version))
            .await
            .expect("upgrade refused");
        let challenge = recv(&mut ws).await;
        assert_eq!(challenge["type"], "challenge");
        let nonce = STANDARD
            .decode(challenge["nonce"].as_str().unwrap())
            .unwrap();
        assert_eq!(nonce.len(), 32);
        (ws, nonce)
    }

    /// Opens `/v1/ws` as `identity` and answers the challenge; the next message is `hello`.
    pub async fn ws_connect(&self, identity: &Identity) -> Ws {
        let (mut ws, nonce) = self.ws_challenged(&identity.id).await;
        send(
            &mut ws,
            json!({
                "type": "authenticate",
                "signature": sign_challenge(&identity.key, &nonce),
                "fingerprint_hash": identity.fingerprint,
            }),
        )
        .await;
        ws
    }

    /// Connects `identity` and consumes `hello`.
    pub async fn connect_device(&self, identity: Identity) -> Device {
        let mut ws = self.ws_connect(&identity).await;
        let hello = recv(&mut ws).await;
        assert_eq!(hello["type"], "hello");
        assert_eq!(hello["device_id"], identity.id.as_str());
        Device {
            id: identity.id,
            key: identity.key,
            fingerprint: identity.fingerprint,
            ws,
        }
    }

    /// Registers device `n` with a fresh identity key and connects it, consuming `hello`.
    pub async fn online_device(&self, n: u32) -> Device {
        let identity = self.new_device(n).await;
        self.connect_device(identity).await
    }

    /// Registers and connects device `n`, then links it to the account of `token`.
    pub async fn linked_device(&self, n: u32, token: &str) -> Device {
        let mut device = self.online_device(n).await;
        let reply = link(&mut device.ws, token).await;
        assert_eq!(reply["type"], "linked", "{reply}");
        device
    }
}

/// Sends `link_account` with `token` and returns the server's reply.
pub async fn link(ws: &mut Ws, token: &str) -> Value {
    send(ws, json!({"type": "link_account", "token": token})).await;
    recv(ws).await
}

impl Device {
    /// Returns this device's identity without the socket, for opening another connection.
    pub fn identity(&self) -> Identity {
        Identity {
            id: self.id.clone(),
            key: self.key.clone(),
            fingerprint: self.fingerprint.clone(),
        }
    }
}

/// Sends `msg` as a JSON text frame.
pub async fn send(ws: &mut Ws, msg: Value) {
    ws.send(Message::Text(msg.to_string().into()))
        .await
        .unwrap();
}

/// Sends a raw text frame.
pub async fn send_raw(ws: &mut Ws, text: &str) {
    ws.send(Message::Text(text.to_owned().into()))
        .await
        .unwrap();
}

/// Receives the next JSON message, skipping control frames; panics on timeout or close.
pub async fn recv(ws: &mut Ws) -> Value {
    loop {
        let msg = tokio::time::timeout(RECV_TIMEOUT, ws.next())
            .await
            .expect("timed out waiting for a message")
            .expect("socket ended")
            .expect("socket error");
        match msg {
            Message::Text(t) => return serde_json::from_str(t.as_str()).unwrap(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

/// Returns the next JSON message whose `type` is `ty`, skipping others.
pub async fn recv_type(ws: &mut Ws, ty: &str) -> Value {
    loop {
        let v = recv(ws).await;
        if v["type"] == ty {
            return v;
        }
    }
}

/// Asserts that the server closes the socket within the timeout, skipping data frames.
pub async fn expect_closed(ws: &mut Ws) {
    expect_closed_within(ws, RECV_TIMEOUT).await;
}

/// Asserts that the server closes the socket within `wait`, skipping data frames.
pub async fn expect_closed_within(ws: &mut Ws, wait: Duration) {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => panic!("socket was not closed"),
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return,
            Ok(Some(Ok(_))) => continue,
        }
    }
}

/// Asserts that no data frame arrives within `wait`.
pub async fn expect_silence(ws: &mut Ws, wait: Duration) {
    loop {
        match tokio::time::timeout(wait, ws.next()).await {
            Err(_) => return,
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            Ok(other) => panic!("unexpected {other:?}"),
        }
    }
}
