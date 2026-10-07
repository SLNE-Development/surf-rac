//! WebSocket helpers for the integration tests.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::{TestApp, fingerprint};

/// A client WebSocket connection to the test server.
pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// How long helpers wait for an expected frame.
const RECV_TIMEOUT: Duration = Duration::from_secs(3);

/// An online test device: its credentials and open socket.
pub struct Device {
    /// Session token of the owning account.
    pub token: String,
    /// Device ID.
    pub id: String,
    /// Device secret.
    pub secret: String,
    /// Open socket, past the `hello` message.
    pub ws: Ws,
}

impl TestApp {
    /// Opens `/v1/ws` with the given credentials; `Err` carries the HTTP status of a refusal.
    pub async fn ws_connect(
        &self,
        token: Option<&str>,
        device_id: &str,
        secret: &str,
    ) -> Result<Ws, u16> {
        let mut req = format!("ws://{}/v1/ws", self.addr)
            .into_client_request()
            .unwrap();
        let h = req.headers_mut();
        if let Some(t) = token {
            h.insert("authorization", format!("Bearer {t}").parse().unwrap());
        }
        h.insert("x-device-id", device_id.parse().unwrap());
        h.insert("x-device-secret", secret.parse().unwrap());
        match tokio_tungstenite::connect_async(req).await {
            Ok((ws, _)) => Ok(ws),
            Err(tokio_tungstenite::tungstenite::Error::Http(res)) => Err(res.status().as_u16()),
            Err(e) => panic!("websocket connect failed: {e}"),
        }
    }

    /// Registers `username` with a device `n` and connects it, consuming `hello`.
    pub async fn online_device(&self, username: &str, n: u32) -> Device {
        let token = self.register_and_login(username).await;
        self.connect_new_device(&token, n).await
    }

    /// Registers device `n` for `token` and connects it, consuming `hello`.
    pub async fn connect_new_device(&self, token: &str, n: u32) -> Device {
        let (id, secret) = self.new_device(token, &fingerprint(n)).await;
        let mut ws = self.ws_connect(Some(token), &id, &secret).await.unwrap();
        let hello = recv(&mut ws).await;
        assert_eq!(hello["type"], "hello");
        assert_eq!(hello["device_id"], id.as_str());
        Device {
            token: token.to_owned(),
            id,
            secret,
            ws,
        }
    }
}

/// Sends `msg` as a JSON text frame.
pub async fn send(ws: &mut Ws, msg: Value) {
    ws.send(Message::Text(msg.to_string().into())).await.unwrap();
}

/// Sends a raw text frame.
pub async fn send_raw(ws: &mut Ws, text: &str) {
    ws.send(Message::Text(text.to_owned().into())).await.unwrap();
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
    let deadline = tokio::time::Instant::now() + RECV_TIMEOUT;
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
