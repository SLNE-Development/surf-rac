//! The host side of a session: publishes the screen and serves up to
//! [`MAX_VIEWERS`] accepted viewers in the host's own LiveKit room.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use livekit::options::{TrackPublishOptions, VideoEncoding};
use livekit::prelude::*;
use livekit::webrtc::prelude::{RtcVideoSource, VideoResolution};
use livekit::webrtc::video_source::native::NativeVideoSource;
use surf_rac_protocol::data::{Control, DataMessage, TOPIC_POINTER};
use surf_rac_protocol::{ClientMessage, DenyReason, DeviceId, ServerMessage};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::channel::{Inbound, PeerChannel, SendError, Side};
use crate::config::{EndReason, MAX_VIEWERS, SessionConfig};
use crate::crypto::{self, DeviceKeys, PublicKey, SessionKey};
use crate::pinning::{KeyChanged, KnownKeys};
use crate::reconnect::ReconnectWatch;
use crate::room::{self, Incoming, JoinError};
use crate::signaling::{SignalingClient, SignalingError, SignalingEvents};
use crate::video::{self, Frame, FrameError};

/// Host events the application may fall behind by before the session waits for it.
const EVENT_CAPACITY: usize = 256;

/// Unanswered session requests kept at once; further requests are denied.
const MAX_PENDING: usize = 16;

/// How long an accepted viewer may take to join before its slot is freed.
const JOIN_WINDOW: Duration = Duration::from_secs(70);

/// Highest frame rate the video track is encoded at.
const MAX_FRAMERATE: f64 = 30.0;

/// Highest bitrate the video track is encoded at, in bits per second.
const MAX_BITRATE: u64 = 4_000_000;

/// Something that happened in a host session.
#[derive(Debug)]
pub enum HostEvent {
    /// A viewer asks for a session; answer with [`HostSession::accept`] or [`HostSession::deny`].
    ViewerRequested {
        /// Identifies the request.
        session_id: String,
        /// The requesting device.
        viewer: DeviceId,
        /// Fingerprint of the viewer's public key.
        fingerprint: String,
    },
    /// A viewer presented a key that differs from its pinned key; its request was refused.
    KeyChanged(KeyChanged),
    /// An accepted viewer joined the room and received the media key.
    ViewerJoined {
        /// The viewer device.
        viewer: DeviceId,
    },
    /// A viewer left, hung up or was hung up on.
    ViewerLeft {
        /// The viewer device.
        viewer: DeviceId,
    },
    /// A viewer sent a data message.
    DataReceived {
        /// The sending viewer.
        viewer: DeviceId,
        /// The message.
        message: DataMessage,
    },
    /// The media connection dropped and is being restored.
    Reconnecting,
    /// The media connection was restored.
    Reconnected,
    /// The session is over; no further events follow.
    Ended {
        /// Why it ended.
        reason: EndReason,
    },
}

/// Why a host session could not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartError {
    /// The signaling connection failed.
    #[error(transparent)]
    Signaling(#[from] SignalingError),
    /// The server did not issue a host token in time.
    #[error("no host token within the request timeout")]
    Timeout,
    /// LiveKit could not be joined.
    #[error("media server unavailable: {0}")]
    MediaUnavailable(String),
}

/// Why a host action failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    /// No pending request has this session ID.
    #[error("unknown session request")]
    UnknownRequest,
    /// The signaling connection failed.
    #[error(transparent)]
    Signaling(#[from] SignalingError),
}

/// A running host session; cheap to clone.
#[derive(Clone)]
pub struct HostSession {
    /// State shared with the event loop.
    inner: Arc<Inner>,
}

/// State shared between session handles and the event loop.
struct Inner {
    /// This device.
    device: DeviceId,
    /// Signaling connection.
    signaling: SignalingClient,
    /// The host's LiveKit room.
    room: Room,
    /// This device's key pair.
    keys: Arc<DeviceKeys>,
    /// Pinned viewer keys.
    known: Arc<Mutex<KnownKeys>>,
    /// Source of the published video track.
    source: NativeVideoSource,
    /// Requests and viewers.
    state: Mutex<State>,
    /// Serializes sealing and sending so each topic's counters leave in order.
    send_lock: tokio::sync::Mutex<()>,
    /// Events for the application.
    events: mpsc::Sender<HostEvent>,
    /// The event loop task.
    task: Mutex<Option<JoinHandle<()>>>,
}

/// Requests and viewers of a host session.
struct State {
    /// Unanswered requests by session ID.
    pending: HashMap<String, Pending>,
    /// Accepted viewers by device.
    viewers: HashMap<DeviceId, Viewer>,
    /// Current media key.
    media_key: SessionKey,
    /// Key index of the current media key.
    media_index: u8,
}

/// An unanswered session request.
struct Pending {
    /// The requesting device.
    viewer: DeviceId,
    /// Its public key.
    key: PublicKey,
}

/// An accepted viewer.
struct Viewer {
    /// Its session ID.
    session_id: String,
    /// Sealed data channel with it.
    channel: PeerChannel,
    /// Whether it has joined the room.
    joined: bool,
    /// When it was accepted.
    accepted_at: Instant,
}

impl State {
    /// Frees the slots of accepted viewers that never joined within [`JOIN_WINDOW`].
    fn purge_stale(&mut self, now: Instant) {
        self.viewers
            .retain(|_, v| v.joined || now.duration_since(v.accepted_at) < JOIN_WINDOW);
    }
}

impl HostSession {
    /// Starts hosting: obtains a host token, joins the host's room and publishes
    /// a `width` x `height` video track.
    ///
    /// Returns the session and the receiver of its events.
    pub async fn start(
        signaling: SignalingClient,
        keys: Arc<DeviceKeys>,
        known: Arc<Mutex<KnownKeys>>,
        width: u32,
        height: u32,
        config: SessionConfig,
    ) -> Result<(HostSession, mpsc::Receiver<HostEvent>), StartError> {
        let device = signaling.device_id();
        let mut sig_events = signaling.subscribe();
        signaling.send(ClientMessage::HostTokenRequest).await?;
        let (url, token) = tokio::time::timeout(config.request_timeout, async {
            loop {
                match sig_events.recv().await {
                    Some(ServerMessage::HostToken { url, token, .. }) => return Ok((url, token)),
                    Some(_) => continue,
                    None => return Err(StartError::Signaling(SignalingError::Closed)),
                }
            }
        })
        .await
        .map_err(|_| StartError::Timeout)??;

        let key_provider = room::key_provider();
        let media_key = SessionKey::random();
        key_provider.set_key(&room::identity(device), 0, media_key.as_bytes().to_vec());
        let (lk_room, room_events) =
            room::connect(&url, &token, &key_provider, config.force_relay)
                .await
                .map_err(|e| match e {
                    JoinError::Rejected => StartError::MediaUnavailable("token rejected".into()),
                    JoinError::Unavailable(reason) => StartError::MediaUnavailable(reason),
                })?;
        let source = NativeVideoSource::new(VideoResolution { width, height }, true);
        let track =
            LocalVideoTrack::create_video_track("screen", RtcVideoSource::Native(source.clone()));
        lk_room
            .local_participant()
            .publish_track(
                LocalTrack::Video(track),
                TrackPublishOptions {
                    source: TrackSource::Screenshare,
                    video_encoding: Some(VideoEncoding {
                        max_bitrate: MAX_BITRATE,
                        max_framerate: MAX_FRAMERATE,
                    }),
                    simulcast: false,
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| StartError::MediaUnavailable(e.to_string()))?;
        tracing::info!(device_id = %device, "hosting started");

        let (events, events_rx) = mpsc::channel(EVENT_CAPACITY);
        let inner = Arc::new(Inner {
            device,
            signaling,
            room: lk_room,
            keys,
            known,
            source,
            state: Mutex::new(State {
                pending: HashMap::new(),
                viewers: HashMap::new(),
                media_key,
                media_index: 0,
            }),
            send_lock: tokio::sync::Mutex::new(()),
            events,
            task: Mutex::new(None),
        });
        let task = tokio::spawn(run(
            Arc::clone(&inner),
            sig_events,
            room_events,
            ReconnectWatch::new(config.reconnect_window),
        ));
        *lock(&inner.task) = Some(task);
        Ok((HostSession { inner }, events_rx))
    }

    /// Accepts the pending request `session_id`.
    ///
    /// The viewer gets the host's public key and a join token for the room. When
    /// the room already has [`MAX_VIEWERS`] viewers the request is refused as
    /// room full instead.
    pub async fn accept(&self, session_id: &str) -> Result<(), HostError> {
        let inner = &self.inner;
        let (viewer, outcome) = {
            let mut st = lock(&inner.state);
            let pending = st
                .pending
                .remove(session_id)
                .ok_or(HostError::UnknownRequest)?;
            st.purge_stale(Instant::now());
            if st.viewers.len() >= MAX_VIEWERS {
                (pending.viewer, Err(DenyReason::RoomFull))
            } else {
                match crypto::derive_session_key(
                    &inner.keys,
                    &pending.key,
                    session_id,
                    inner.device,
                    pending.viewer,
                ) {
                    Ok(key) => {
                        st.viewers.insert(
                            pending.viewer,
                            Viewer {
                                session_id: session_id.to_owned(),
                                channel: PeerChannel::new(session_id.to_owned(), key, Side::Host),
                                joined: false,
                                accepted_at: Instant::now(),
                            },
                        );
                        (pending.viewer, Ok(()))
                    }
                    Err(_) => (pending.viewer, Err(DenyReason::Denied)),
                }
            }
        };
        match outcome {
            Err(reason) => inner.respond(viewer, session_id, Some(reason)).await,
            Ok(()) => {
                tracing::info!(viewer = %viewer, %session_id, "session accepted");
                inner.respond(viewer, session_id, None).await?;
                inner
                    .signaling
                    .send(ClientMessage::ViewerTokenRequest {
                        session_id: session_id.to_owned(),
                        viewer_device_id: viewer,
                    })
                    .await?;
                Ok(())
            }
        }
    }

    /// Refuses the pending request `session_id`.
    pub async fn deny(&self, session_id: &str) -> Result<(), HostError> {
        let pending = lock(&self.inner.state)
            .pending
            .remove(session_id)
            .ok_or(HostError::UnknownRequest)?;
        tracing::info!(viewer = %pending.viewer, %session_id, "session denied");
        self.inner
            .respond(pending.viewer, session_id, Some(DenyReason::Denied))
            .await
    }

    /// Publishes one frame on the video track.
    pub fn publish_frame(&self, frame: &Frame) -> Result<(), FrameError> {
        frame.validate()?;
        self.inner.source.capture_frame(&video::to_livekit(frame));
        Ok(())
    }

    /// Sends `msg` to `viewer`.
    pub async fn send(&self, viewer: DeviceId, msg: &DataMessage) -> Result<(), SendError> {
        self.inner.send(viewer, msg).await
    }

    /// Ends the session with `viewer`: tells it to hang up and frees its slot.
    pub async fn hangup(&self, viewer: DeviceId) -> Result<(), SendError> {
        let result = self
            .inner
            .send(viewer, &DataMessage::Control(Control::Hangup))
            .await;
        self.inner.remove_viewer(viewer).await;
        result
    }

    /// Stops hosting: leaves the room and ends the event loop.
    pub async fn close(self) {
        if let Some(task) = lock(&self.inner.task).take() {
            task.abort();
        }
        let _ = self.inner.room.close().await;
        tracing::info!(device_id = %self.inner.device, "hosting stopped");
    }
}

impl Inner {
    /// Answers `viewer`'s request `session_id`: accepted when `deny` is `None`.
    async fn respond(
        &self,
        viewer: DeviceId,
        session_id: &str,
        deny: Option<DenyReason>,
    ) -> Result<(), HostError> {
        self.signaling
            .send(ClientMessage::SessionResponse {
                to: viewer,
                session_id: session_id.to_owned(),
                accepted: deny.is_none(),
                reason: deny,
                host_public_key: deny.is_none().then(|| self.keys.public_key().to_base64()),
            })
            .await?;
        Ok(())
    }

    /// Seals `msg` for `viewer` and sends it.
    async fn send(&self, viewer: DeviceId, msg: &DataMessage) -> Result<(), SendError> {
        let _order = self.send_lock.lock().await;
        let sealed = {
            let mut st = lock(&self.state);
            let v = st.viewers.get_mut(&viewer).ok_or(SendError::NotConnected)?;
            v.channel.seal(msg)?
        };
        room::send(&self.room, viewer, msg.topic(), msg.is_reliable(), sealed).await
    }

    /// Forgets `viewer` and reports that it left, if it was a viewer.
    async fn remove_viewer(&self, viewer: DeviceId) {
        let removed = lock(&self.state).viewers.remove(&viewer);
        if let Some(v) = removed {
            tracing::info!(viewer = %viewer, session_id = %v.session_id, "viewer left");
            let _ = self.events.send(HostEvent::ViewerLeft { viewer }).await;
        }
    }

    /// Handles a session request from `viewer`.
    ///
    /// Requests from a viewer already in the room, or with a session ID or
    /// viewer that is already pending, are denied. A viewer that was accepted
    /// but never joined may request again; accepting that request replaces
    /// its old slot.
    async fn on_request(&self, viewer: DeviceId, session_id: String, key: String) {
        let Ok(key) = PublicKey::from_base64(&key) else {
            let _ = self.respond(viewer, &session_id, Some(DenyReason::Denied)).await;
            return;
        };
        let refusal = {
            let mut st = lock(&self.state);
            let duplicate = st.pending.contains_key(&session_id)
                || st.viewers.get(&viewer).is_some_and(|v| v.joined)
                || st.pending.values().any(|p| p.viewer == viewer);
            if duplicate || st.pending.len() >= MAX_PENDING {
                Some(Err(DenyReason::Denied))
            } else {
                match lock(&self.known).check(viewer, &key) {
                    Err(changed) => Some(Ok(changed)),
                    Ok(()) => {
                        st.pending
                            .insert(session_id.clone(), Pending { viewer, key });
                        None
                    }
                }
            }
        };
        match refusal {
            None => {
                tracing::info!(viewer = %viewer, %session_id, "session requested");
                let _ = self
                    .events
                    .send(HostEvent::ViewerRequested {
                        session_id,
                        viewer,
                        fingerprint: key.fingerprint(),
                    })
                    .await;
            }
            Some(Err(reason)) => {
                tracing::info!(viewer = %viewer, %session_id, "duplicate session request denied");
                let _ = self.respond(viewer, &session_id, Some(reason)).await;
            }
            Some(Ok(changed)) => {
                tracing::warn!(viewer = %viewer, %session_id, "viewer key changed, request refused");
                let _ = self.events.send(HostEvent::KeyChanged(changed)).await;
                let _ = self
                    .respond(viewer, &session_id, Some(DenyReason::KeyChanged))
                    .await;
            }
        }
    }

    /// Hands the media key to `viewer` once it is in the room.
    async fn on_viewer_active(&self, viewer: DeviceId) {
        let key_msg = {
            let mut st = lock(&self.state);
            let index = st.media_index;
            let key = *st.media_key.as_bytes();
            match st.viewers.get_mut(&viewer) {
                Some(v) if !v.joined => {
                    v.joined = true;
                    Some(DataMessage::Control(Control::MediaKey { index, key }))
                }
                _ => None,
            }
        };
        let Some(msg) = key_msg else { return };
        if let Err(err) = self.send(viewer, &msg).await {
            tracing::warn!(viewer = %viewer, error = %err, "sending media key failed");
            return;
        }
        tracing::info!(viewer = %viewer, "viewer joined");
        let _ = self.events.send(HostEvent::ViewerJoined { viewer }).await;
    }

    /// Opens a sealed payload from a participant and acts on it.
    async fn on_data(&self, incoming: Incoming) {
        let Ok(viewer) = incoming.from.parse::<DeviceId>() else {
            return;
        };
        let outcome = {
            let mut st = lock(&self.state);
            match st.viewers.get_mut(&viewer) {
                Some(v) => v.channel.open(&incoming.topic, &incoming.payload),
                None => return,
            }
        };
        match outcome {
            Inbound::Message(DataMessage::Control(Control::Hangup)) => {
                self.remove_viewer(viewer).await;
            }
            Inbound::Message(DataMessage::Control(Control::MediaKey { .. })) => {}
            Inbound::Message(message) => {
                let event = HostEvent::DataReceived { viewer, message };
                if incoming.topic == TOPIC_POINTER {
                    let _ = self.events.try_send(event);
                } else {
                    let _ = self.events.send(event).await;
                }
            }
            Inbound::Dropped => {}
            Inbound::UnknownVersion(version) => {
                tracing::warn!(viewer = %viewer, version, "data message of unknown version dropped");
            }
            Inbound::CryptoLimit => {
                tracing::warn!(viewer = %viewer, "too many undecryptable messages, ending session");
                let _ = self
                    .send(viewer, &DataMessage::Control(Control::Hangup))
                    .await;
                self.remove_viewer(viewer).await;
            }
        }
    }
}

/// Runs the host's event loop until the room is gone or the reconnect window runs out.
async fn run(
    inner: Arc<Inner>,
    mut signaling: SignalingEvents,
    mut room_events: mpsc::UnboundedReceiver<RoomEvent>,
    mut watch: ReconnectWatch,
) {
    let (incoming_tx, mut incoming_rx) = mpsc::unbounded_channel();
    let mut signaling_open = true;
    let reason = loop {
        tokio::select! {
            msg = signaling.recv(), if signaling_open => match msg {
                Some(ServerMessage::SessionRequest { from, session_id, viewer_public_key }) => {
                    inner.on_request(from, session_id, viewer_public_key).await;
                }
                Some(_) => {}
                None => {
                    tracing::warn!(device_id = %inner.device, "signaling closed, no new requests can arrive");
                    signaling_open = false;
                }
            },
            ev = room_events.recv() => match ev {
                Some(RoomEvent::ParticipantActive(p)) => {
                    if let Ok(viewer) = p.identity().0.parse() {
                        inner.on_viewer_active(viewer).await;
                    }
                }
                Some(RoomEvent::ParticipantDisconnected(p)) => {
                    if let Ok(viewer) = p.identity().0.parse() {
                        inner.remove_viewer(viewer).await;
                    }
                }
                Some(RoomEvent::DataReceived { payload, topic: Some(topic), participant: Some(p), .. }) => {
                    inner.on_data(Incoming { from: p.identity().0, topic, payload: payload.to_vec() }).await;
                }
                Some(RoomEvent::ByteStreamOpened { reader, topic, participant_identity }) => {
                    if let Some(reader) = reader.take() {
                        room::read_clipboard_stream(reader, topic, participant_identity.0, incoming_tx.clone());
                    }
                }
                Some(RoomEvent::Reconnecting) => {
                    watch.reconnecting();
                    tracing::info!(device_id = %inner.device, "media reconnecting");
                    let _ = inner.events.send(HostEvent::Reconnecting).await;
                }
                Some(RoomEvent::Reconnected) => {
                    watch.reconnected();
                    tracing::info!(device_id = %inner.device, "media reconnected");
                    let _ = inner.events.send(HostEvent::Reconnected).await;
                }
                Some(RoomEvent::Disconnected { .. }) | None => break EndReason::Closed,
                Some(_) => {}
            },
            Some(incoming) = incoming_rx.recv() => inner.on_data(incoming).await,
            _ = watch.expired() => break EndReason::Timeout,
        }
    };
    tracing::info!(device_id = %inner.device, ?reason, "hosting ended");
    let _ = inner.room.close().await;
    let _ = inner.events.send(HostEvent::Ended { reason }).await;
}

/// Locks `m`, recovering from a poisoned lock.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
