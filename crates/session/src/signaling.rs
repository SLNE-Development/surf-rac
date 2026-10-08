//! Client side of the signaling WebSocket.
//!
//! One connection per device. Outgoing messages are queued to a writer task;
//! incoming messages are fanned out to every subscriber. When the connection
//! ends, sends fail with [`SignalingError::Closed`] and subscribers see the end.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use surf_rac_protocol::{
    ClientMessage, DeviceId, HEADER_DEVICE_ID, HEADER_DEVICE_SECRET, ServerMessage,
};
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// Incoming messages a subscriber may fall behind by before it skips ahead.
const EVENT_CAPACITY: usize = 256;

/// Outgoing messages queued before `send` waits.
const OUTBOUND_CAPACITY: usize = 64;

/// Interval between application-level pings.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// How long `connect` waits for the server's `hello`.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the signaling connection failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignalingError {
    /// The connection could not be established.
    #[error("signaling connection failed: {0}")]
    Connect(String),
    /// The server refused the upgrade with this HTTP status.
    #[error("signaling server refused the connection with status {0}")]
    Rejected(u16),
    /// The connection is closed.
    #[error("signaling connection closed")]
    Closed,
}

/// A device's connection to the signaling server; cheap to clone.
#[derive(Clone)]
pub struct SignalingClient {
    /// State shared with the connection task.
    inner: Arc<Inner>,
}

/// State shared between client handles and the connection task.
struct Inner {
    /// The authenticated device of this connection.
    device_id: DeviceId,
    /// Queue to the writer.
    out: mpsc::Sender<ClientMessage>,
    /// Fan-out of incoming messages; `None` once the connection ended.
    events: Mutex<Option<broadcast::Sender<ServerMessage>>>,
}

impl Inner {
    /// Locks the event sender slot, recovering from a poisoned lock.
    fn events(&self) -> std::sync::MutexGuard<'_, Option<broadcast::Sender<ServerMessage>>> {
        self.events.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl SignalingClient {
    /// Connects device `device_id` to `<url>/v1/ws` and waits for the server's `hello`.
    ///
    /// `url` is the server base as `ws://` or `wss://`, e.g. `wss://rac.slne.dev`.
    pub async fn connect(
        url: &str,
        session_token: &str,
        device_id: DeviceId,
        device_secret: &str,
    ) -> Result<Self, SignalingError> {
        let mut request = format!("{}/v1/ws", url.trim_end_matches('/'))
            .into_client_request()
            .map_err(|e| SignalingError::Connect(e.to_string()))?;
        let headers = request.headers_mut();
        let header = |v: String| {
            v.parse()
                .map_err(|_| SignalingError::Connect("invalid header value".into()))
        };
        headers.insert("authorization", header(format!("Bearer {session_token}"))?);
        headers.insert(HEADER_DEVICE_ID, header(device_id.to_string())?);
        headers.insert(HEADER_DEVICE_SECRET, header(device_secret.to_owned())?);
        let (mut ws, _) = match tokio_tungstenite::connect_async(request).await {
            Ok(ok) => ok,
            Err(tokio_tungstenite::tungstenite::Error::Http(res)) => {
                return Err(SignalingError::Rejected(res.status().as_u16()));
            }
            Err(e) => return Err(SignalingError::Connect(e.to_string())),
        };
        let hello = tokio::time::timeout(HELLO_TIMEOUT, async {
            while let Some(frame) = ws.next().await {
                if let Ok(Message::Text(text)) = frame {
                    return serde_json::from_str::<ServerMessage>(text.as_str()).ok();
                }
            }
            None
        })
        .await;
        match hello {
            Ok(Some(ServerMessage::Hello { device_id: id })) if id == device_id => {}
            _ => return Err(SignalingError::Connect("no hello from server".into())),
        }

        let (out, out_rx) = mpsc::channel(OUTBOUND_CAPACITY);
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        let inner = Arc::new(Inner {
            device_id,
            out,
            events: Mutex::new(Some(events)),
        });
        tokio::spawn(run(ws, out_rx, Arc::clone(&inner)));
        tracing::info!(%device_id, "signaling connected");
        Ok(Self { inner })
    }

    /// Returns the device this connection is authenticated as.
    pub fn device_id(&self) -> DeviceId {
        self.inner.device_id
    }

    /// Queues `msg` for the server.
    pub async fn send(&self, msg: ClientMessage) -> Result<(), SignalingError> {
        self.inner
            .out
            .send(msg)
            .await
            .map_err(|_| SignalingError::Closed)
    }

    /// Returns a stream of the messages the server sends from now on.
    pub fn subscribe(&self) -> SignalingEvents {
        match self.inner.events().as_ref() {
            Some(tx) => SignalingEvents(tx.subscribe()),
            None => SignalingEvents(broadcast::channel(1).1),
        }
    }
}

/// Messages received on a signaling connection, from the moment of subscribing.
pub struct SignalingEvents(broadcast::Receiver<ServerMessage>);

impl SignalingEvents {
    /// Returns the next message, skipping any this subscriber fell too far behind to keep.
    ///
    /// Returns `None` once the connection has ended.
    pub async fn recv(&mut self) -> Option<ServerMessage> {
        loop {
            match self.0.recv().await {
                Ok(msg) => return Some(msg),
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "signaling subscriber lagged");
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

/// The WebSocket stream type of a client connection.
type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Runs the connection until either side closes it, then marks it closed.
async fn run(ws: Ws, mut out_rx: mpsc::Receiver<ClientMessage>, inner: Arc<Inner>) {
    let (mut sink, mut stream) = ws.split();
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await;
    loop {
        tokio::select! {
            out = out_rx.recv() => {
                let Some(msg) = out else { break };
                let text = serde_json::to_string(&msg).expect("client messages always serialize");
                if sink.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Text(text))) => match serde_json::from_str::<ServerMessage>(text.as_str()) {
                    Ok(msg) => {
                        if let Some(tx) = inner.events().as_ref() {
                            let _ = tx.send(msg);
                        }
                    }
                    Err(_) => tracing::warn!("unparseable signaling message"),
                },
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
            _ = ping.tick() => {
                let text = serde_json::to_string(&ClientMessage::Ping).expect("ping serializes");
                if sink.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
        }
    }
    inner.events().take();
    out_rx.close();
    tracing::info!(device_id = %inner.device_id, "signaling disconnected");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lagging_subscriber_keeps_receiving() {
        let (tx, rx) = broadcast::channel(EVENT_CAPACITY);
        let mut events = SignalingEvents(rx);
        for _ in 0..EVENT_CAPACITY + 44 {
            tx.send(ServerMessage::Pong).unwrap();
        }
        assert_eq!(events.recv().await, Some(ServerMessage::Pong));
        tx.send(ServerMessage::Replaced).unwrap();
        let mut last = None;
        while let Ok(Some(msg)) =
            tokio::time::timeout(Duration::from_millis(50), events.recv()).await
        {
            last = Some(msg);
        }
        assert_eq!(last, Some(ServerMessage::Replaced));
        drop(tx);
        assert_eq!(events.recv().await, None);
    }
}
