//! The viewer side of a session: requests access to a host, joins its room
//! with the host-issued token, receives the screen and exchanges data.

use std::sync::{Arc, Mutex, MutexGuard};

use futures_util::StreamExt;
use livekit::e2ee::key_provider::KeyProvider;
use livekit::prelude::*;
use livekit::webrtc::video_stream::native::NativeVideoStream;
use rand::RngCore;
use rand::rngs::OsRng;
use surf_rac_protocol::data::{Control, DataMessage};
use surf_rac_protocol::{ClientMessage, DenyReason, DeviceId, ServerMessage, WsErrorCode};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::channel::{Inbound, PeerChannel, SendError, Side};
use crate::config::{EndReason, SessionConfig};
use crate::crypto::{self, DeviceKeys, PublicKey};
use crate::pinning::{KeyChanged, KnownKeys};
use crate::reconnect::ReconnectWatch;
use crate::room::{self, Incoming, JoinError};
use crate::signaling::{SignalingClient, SignalingError};
use crate::video::{self, Frame};

/// Viewer events buffered for the application; frames beyond this are dropped.
const EVENT_CAPACITY: usize = 64;

/// Something that happened in a viewer session.
#[derive(Debug)]
pub enum ViewerEvent {
    /// The session is connected and the host's media key is in place; also sent
    /// again after a media reconnect.
    Connected,
    /// A decoded frame of the host's screen.
    VideoFrame(Frame),
    /// The host sent a data message.
    DataReceived(DataMessage),
    /// The media connection dropped and is being restored.
    Reconnecting,
    /// The session is over; no further events follow.
    Ended {
        /// Why it ended.
        reason: EndReason,
    },
}

/// Why a session request failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// The host device is not online.
    #[error("host is offline")]
    Offline,
    /// The host refused the request.
    #[error("host denied the session")]
    Denied,
    /// The host's room has no free viewer slot.
    #[error("host room is full")]
    RoomFull,
    /// The host did not answer, or no token arrived, within the request timeout.
    #[error("session request timed out")]
    Timeout,
    /// LiveKit refused the viewer token.
    #[error("viewer token rejected")]
    TokenRejected,
    /// LiveKit could not be reached.
    #[error("media server unavailable: {0}")]
    MediaUnavailable(String),
    /// The host presented a key that differs from its pinned key.
    #[error(transparent)]
    KeyChanged(#[from] KeyChanged),
    /// The signaling connection failed.
    #[error(transparent)]
    Signaling(#[from] SignalingError),
}

/// A connected viewer session; cheap to clone.
#[derive(Clone)]
pub struct ViewerSession {
    /// State shared with the event loop.
    inner: Arc<Inner>,
}

/// State shared between session handles and the event loop.
struct Inner {
    /// The host device.
    host: DeviceId,
    /// Session identifier.
    session_id: String,
    /// The host's LiveKit room.
    room: Room,
    /// Sealed data channel with the host.
    channel: Mutex<PeerChannel>,
    /// Serializes sealing and sending so each topic's counters leave in order.
    send_lock: tokio::sync::Mutex<()>,
    /// Frame-encryption keys.
    key_provider: KeyProvider,
    /// Key index of the newest media key received.
    media_index: Mutex<Option<u8>>,
    /// The event loop task.
    task: Mutex<Option<JoinHandle<()>>>,
}

impl ViewerSession {
    /// Requests a session with `host` and, once accepted, joins its room.
    ///
    /// Returns when the room is joined; [`ViewerEvent::Connected`] follows once
    /// the host has handed over its media key.
    pub async fn request(
        signaling: SignalingClient,
        keys: Arc<DeviceKeys>,
        known: Arc<Mutex<KnownKeys>>,
        host: DeviceId,
        config: SessionConfig,
    ) -> Result<(ViewerSession, mpsc::Receiver<ViewerEvent>), RequestError> {
        let viewer = signaling.device_id();
        let session_id = new_session_id();
        let mut sig_events = signaling.subscribe();
        signaling
            .send(ClientMessage::SessionRequest {
                to: host,
                session_id: session_id.clone(),
                viewer_public_key: keys.public_key().to_base64(),
            })
            .await?;
        tracing::info!(%host, %session_id, "session requested");

        let (channel_key, url, token) = tokio::time::timeout(config.request_timeout, async {
            let mut key = None;
            let mut token = None;
            loop {
                match sig_events.recv().await {
                    None => return Err(RequestError::Signaling(SignalingError::Closed)),
                    Some(ServerMessage::Error {
                        code: WsErrorCode::TargetOffline,
                        ..
                    }) if key.is_none() => {
                        return Err(RequestError::Offline);
                    }
                    Some(ServerMessage::SessionResponse {
                        from,
                        session_id: sid,
                        accepted,
                        reason,
                        host_public_key,
                    }) if from == host && sid == session_id => {
                        if !accepted {
                            return Err(match reason {
                                Some(DenyReason::RoomFull) => RequestError::RoomFull,
                                _ => RequestError::Denied,
                            });
                        }
                        let host_key = host_public_key
                            .as_deref()
                            .and_then(|k| PublicKey::from_base64(k).ok())
                            .ok_or(RequestError::Denied)?;
                        lock(&known).check(host, &host_key)?;
                        let derived =
                            crypto::derive_session_key(&keys, &host_key, &session_id, host, viewer)
                                .map_err(|_| RequestError::Denied)?;
                        key = Some(derived);
                    }
                    Some(ServerMessage::ViewerToken {
                        from,
                        session_id: sid,
                        url,
                        token: t,
                        ..
                    }) if from == host && sid == session_id => {
                        token = Some((url, t));
                    }
                    Some(_) => {}
                }
                if let (Some(_), Some(_)) = (&key, &token) {
                    let (url, t) = token.take().expect("checked");
                    return Ok((key.take().expect("checked"), url, t));
                }
            }
        })
        .await
        .map_err(|_| RequestError::Timeout)??;

        let key_provider = room::key_provider();
        let (lk_room, room_events) = room::connect(&url, &token, &key_provider, config.force_relay)
            .await
            .map_err(|e| match e {
                JoinError::Rejected => RequestError::TokenRejected,
                JoinError::Unavailable(reason) => RequestError::MediaUnavailable(reason),
            })?;
        tracing::info!(%host, %session_id, "joined host room");

        let (public_tx, public_rx) = mpsc::channel(EVENT_CAPACITY);
        let inner = Arc::new(Inner {
            host,
            channel: Mutex::new(PeerChannel::new(
                session_id.clone(),
                channel_key,
                Side::Viewer,
            )),
            session_id,
            room: lk_room,
            send_lock: tokio::sync::Mutex::new(()),
            key_provider,
            media_index: Mutex::new(None),
            task: Mutex::new(None),
        });
        let task = tokio::spawn(run(
            Arc::clone(&inner),
            room_events,
            public_tx,
            ReconnectWatch::new(config.reconnect_window),
        ));
        *lock(&inner.task) = Some(task);
        Ok((ViewerSession { inner }, public_rx))
    }

    /// Sends `msg` to the host.
    pub async fn send(&self, msg: &DataMessage) -> Result<(), SendError> {
        self.inner.send(msg).await
    }

    /// Returns the key index of the newest media key received from the host.
    #[doc(hidden)]
    pub fn media_key_index(&self) -> Option<u8> {
        *lock(&self.inner.media_index)
    }

    /// Ends the session: tells the host and leaves the room.
    pub async fn hangup(self) {
        let _ = self
            .inner
            .send(&DataMessage::Control(Control::Hangup))
            .await;
        if let Some(task) = lock(&self.inner.task).take() {
            task.abort();
        }
        let _ = self.inner.room.close().await;
        tracing::info!(host = %self.inner.host, session_id = %self.inner.session_id, "session hung up");
    }
}

impl Inner {
    /// Seals `msg` and sends it to the host.
    async fn send(&self, msg: &DataMessage) -> Result<(), SendError> {
        let _order = self.send_lock.lock().await;
        let sealed = lock(&self.channel).seal(msg)?;
        room::send(
            &self.room,
            self.host,
            msg.topic(),
            msg.is_reliable(),
            sealed,
        )
        .await
    }

    /// Opens a sealed payload; returns the event to emit and whether the session ends.
    fn on_data(&self, incoming: Incoming) -> (Option<ViewerEvent>, Option<EndReason>) {
        if incoming.from != self.host.to_string() {
            return (None, None);
        }
        let outcome = lock(&self.channel).open(&incoming.topic, &incoming.payload);
        match outcome {
            Inbound::Message(DataMessage::Control(Control::MediaKey { index, key })) => {
                self.key_provider.set_key(
                    &room::identity(self.host),
                    i32::from(index),
                    key.to_vec(),
                );
                let first = lock(&self.media_index).replace(index).is_none();
                (first.then_some(ViewerEvent::Connected), None)
            }
            Inbound::Message(DataMessage::Control(Control::Hangup)) => {
                (None, Some(EndReason::Hangup))
            }
            Inbound::Message(message) => (Some(ViewerEvent::DataReceived(message)), None),
            Inbound::Dropped => (None, None),
            Inbound::UnknownVersion(version) => {
                tracing::warn!(host = %self.host, version, "data message of unknown version dropped");
                (None, None)
            }
            Inbound::CryptoLimit => (None, Some(EndReason::CryptoError)),
        }
    }
}

/// Runs the viewer's event loop until the session ends.
async fn run(
    inner: Arc<Inner>,
    mut room_events: mpsc::UnboundedReceiver<RoomEvent>,
    public: mpsc::Sender<ViewerEvent>,
    mut watch: ReconnectWatch,
) {
    let (events, mut events_rx) = mpsc::unbounded_channel::<ViewerEvent>();
    let forward_to = public.clone();
    let forwarder = tokio::spawn(async move {
        while let Some(ev) = events_rx.recv().await {
            if forward_to.send(ev).await.is_err() {
                break;
            }
        }
    });
    let (incoming_tx, mut incoming_rx) = mpsc::unbounded_channel();
    let gate = room::StreamGate::new();
    let host_identity = inner.host.to_string();
    let mut frames: Option<JoinHandle<()>> = None;
    let reason = loop {
        let incoming = tokio::select! {
            ev = room_events.recv() => match ev {
                Some(RoomEvent::TrackSubscribed { track: RemoteTrack::Video(track), participant, .. })
                    if participant.identity().0 == host_identity =>
                {
                    if let Some(old) = frames.take() {
                        old.abort();
                    }
                    frames = Some(spawn_frames(track, public.clone()));
                    continue;
                }
                Some(RoomEvent::DataReceived { payload, topic: Some(topic), participant: Some(p), .. }) => {
                    Incoming { from: p.identity().0, topic, payload: payload.to_vec() }
                }
                Some(RoomEvent::ByteStreamOpened { reader, topic, participant_identity }) => {
                    if participant_identity.0 == host_identity {
                        if let Some(reader) = reader.take() {
                            room::read_clipboard_stream(reader, topic, participant_identity.0, &gate, incoming_tx.clone());
                        }
                    }
                    continue;
                }
                Some(RoomEvent::ParticipantDisconnected(p)) if p.identity().0 == host_identity => {
                    break EndReason::Closed;
                }
                Some(RoomEvent::Reconnecting) => {
                    watch.reconnecting();
                    let _ = events.send(ViewerEvent::Reconnecting);
                    continue;
                }
                Some(RoomEvent::Reconnected) => {
                    watch.reconnected();
                    let _ = events.send(ViewerEvent::Connected);
                    continue;
                }
                Some(RoomEvent::Disconnected { .. }) | None => break EndReason::Closed,
                Some(_) => continue,
            },
            Some(incoming) = incoming_rx.recv() => incoming,
            _ = watch.expired() => break EndReason::Timeout,
        };
        let (event, end) = inner.on_data(incoming);
        if let Some(event) = event {
            let _ = events.send(event);
        }
        if let Some(reason) = end {
            break reason;
        }
    };
    if let Some(frames) = frames {
        frames.abort();
    }
    tracing::info!(host = %inner.host, session_id = %inner.session_id, ?reason, "session ended");
    let _ = inner.room.close().await;
    let _ = events.send(ViewerEvent::Ended { reason });
    drop(events);
    let _ = forwarder.await;
}

/// Decodes frames of `track` and offers them to `public`, dropping frames it has no room for.
fn spawn_frames(track: RemoteVideoTrack, public: mpsc::Sender<ViewerEvent>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut stream = NativeVideoStream::new(track.rtc_track());
        while let Some(frame) = stream.next().await {
            if let Err(mpsc::error::TrySendError::Closed(_)) =
                public.try_send(ViewerEvent::VideoFrame(video::from_livekit(&frame)))
            {
                break;
            }
        }
    })
}

/// Returns a new random 128-bit session ID as 32 hex characters.
fn new_session_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Locks `m`, recovering from a poisoned lock.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::crypto::SessionKey;
    use crate::testutil::{env, mint_token, room_name, unix_now};

    /// Joins a fresh room and starts the viewer loop on simulated room events.
    async fn loop_on_simulated_events(
        window: Duration,
    ) -> (
        Arc<Inner>,
        mpsc::UnboundedSender<RoomEvent>,
        mpsc::Receiver<ViewerEvent>,
    ) {
        let now = unix_now();
        let token = mint_token(&room_name(), "223456789", now, now + 60);
        let key_provider = room::key_provider();
        let (lk_room, _real_events) =
            room::connect(&env("LIVEKIT_URL"), &token, &key_provider, false)
                .await
                .unwrap();
        let inner = Arc::new(Inner {
            host: DeviceId::new(123_456_789).unwrap(),
            session_id: "s1".into(),
            room: lk_room,
            channel: Mutex::new(PeerChannel::new(
                "s1".into(),
                SessionKey::from_bytes([1; 32]),
                Side::Viewer,
            )),
            send_lock: tokio::sync::Mutex::new(()),
            key_provider,
            media_index: Mutex::new(None),
            task: Mutex::new(None),
        });
        let (tx, rx) = mpsc::unbounded_channel();
        let (public_tx, public_rx) = mpsc::channel(EVENT_CAPACITY);
        tokio::spawn(run(
            Arc::clone(&inner),
            rx,
            public_tx,
            ReconnectWatch::new(window),
        ));
        (inner, tx, public_rx)
    }

    /// Returns the events delivered within `wait`.
    async fn drain(events: &mut mpsc::Receiver<ViewerEvent>, wait: Duration) -> Vec<ViewerEvent> {
        let deadline = tokio::time::Instant::now() + wait;
        let mut out = Vec::new();
        while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, events.recv()).await {
            out.push(ev);
        }
        out
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reconnect_window_ends_session() {
        let (_inner, tx, mut events) = loop_on_simulated_events(Duration::from_secs(2)).await;
        tx.send(RoomEvent::Reconnecting).unwrap();
        let got = drain(&mut events, Duration::from_secs(4)).await;
        assert!(
            matches!(got.first(), Some(ViewerEvent::Reconnecting)),
            "{got:?}"
        );
        assert!(
            matches!(
                got.last(),
                Some(ViewerEvent::Ended {
                    reason: EndReason::Timeout
                })
            ),
            "{got:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reconnect_within_window_keeps_session() {
        let (_inner, tx, mut events) = loop_on_simulated_events(Duration::from_secs(2)).await;
        tx.send(RoomEvent::Reconnecting).unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        tx.send(RoomEvent::Reconnected).unwrap();
        let got = drain(&mut events, Duration::from_secs(4)).await;
        assert!(
            matches!(
                got.as_slice(),
                [ViewerEvent::Reconnecting, ViewerEvent::Connected]
            ),
            "{got:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ten_crypto_failures_end_session() {
        let (inner, _tx, _events) = loop_on_simulated_events(Duration::from_secs(30)).await;
        let garbage = || Incoming {
            from: "123456789".into(),
            topic: surf_rac_protocol::data::TOPIC_INPUT.into(),
            payload: vec![7; 40],
        };
        for _ in 0..crate::CRYPTO_FAILURE_LIMIT - 1 {
            assert!(matches!(inner.on_data(garbage()), (None, None)));
        }
        assert!(matches!(
            inner.on_data(garbage()),
            (None, Some(EndReason::CryptoError))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn data_from_other_participants_is_ignored() {
        let (inner, _tx, _events) = loop_on_simulated_events(Duration::from_secs(30)).await;
        for _ in 0..crate::CRYPTO_FAILURE_LIMIT + 5 {
            let forged = Incoming {
                from: "323456789".into(),
                topic: surf_rac_protocol::data::TOPIC_INPUT.into(),
                payload: vec![7; 40],
            };
            assert!(matches!(inner.on_data(forged), (None, None)));
        }
    }
}
