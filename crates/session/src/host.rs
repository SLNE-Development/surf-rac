//! The host side of a session: publishes the screen and serves up to
//! [`MAX_VIEWERS`] accepted viewers in the host's own LiveKit room.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use livekit::options::{TrackPublishOptions, VideoCodec, VideoEncoderBackend, VideoEncoding};
use livekit::prelude::*;
use livekit::webrtc::prelude::{RtcVideoSource, VideoResolution};
use livekit::webrtc::video_source::native::NativeVideoSource;
use surf_rac_protocol::data::{Control, DataMessage};
use surf_rac_protocol::{ClientMessage, DenyReason, DeviceId, ServerMessage};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::channel::{Inbound, PeerChannel, SendError, Side, topic_index};
use crate::config::{EndReason, MAX_VIEWERS, SessionConfig};
use crate::crypto::{self, DeviceKeys, PublicKey, SessionKey};
use crate::pinning::{KeyChanged, KnownKeys};
use crate::reconnect::ReconnectWatch;
use crate::room::{self, Incoming, JoinError};
use crate::signaling::{SignalingClient, SignalingError, SignalingEvents};
use crate::video::{self, EncodedFrame, Frame, FrameError, RateRequest, VideoInput};

/// Host events buffered for the application.
const EVENT_CAPACITY: usize = 1024;

/// Event slots kept free for lifecycle events; data messages that would use them are dropped.
const LIFECYCLE_RESERVE: usize = 64;

/// How often the host checks for expired requests and viewers that did not come back.
const HOUSEKEEPING_INTERVAL: Duration = Duration::from_secs(1);

/// Unanswered session requests kept at once; further requests are denied.
const MAX_PENDING: usize = 16;

/// Number of media key indices the frame-encryption key ring holds.
const KEY_RING_SIZE: u8 = 16;

/// How long remaining viewers get to install a rotated media key before the host switches to it.
const KEY_SWITCH_DELAY: Duration = Duration::from_millis(500);

/// Shortest time between two refusals the host sends to the same viewer.
const REFUSAL_INTERVAL: Duration = Duration::from_secs(2);

/// How long an accepted viewer may take to join before its slot is freed.
const JOIN_WINDOW: Duration = Duration::from_secs(70);

/// Highest frame rate the video track is encoded at.
const MAX_FRAMERATE: f64 = 30.0;

/// Highest bitrate the video track is encoded at, in bits per second.
pub const MAX_BITRATE: u64 = 8_000_000;

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
    /// A request was not answered within the request timeout; the viewer has given up.
    RequestExpired {
        /// Identifies the request.
        session_id: String,
        /// The requesting device.
        viewer: DeviceId,
    },
    /// A viewer left, hung up, was hung up on, or did not return within the reconnect window.
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
    /// The published video track and its source.
    video: Mutex<Video>,
    /// Serializes switches of the video input.
    video_switch: tokio::sync::Mutex<()>,
    /// Frame-encryption keys.
    key_provider: livekit::e2ee::key_provider::KeyProvider,
    /// Serializes media key rotations.
    rotate_lock: tokio::sync::Mutex<()>,
    /// Requests and viewers.
    state: Mutex<State>,
    /// Timeouts of the session.
    config: SessionConfig,
    /// Events for the application.
    events: mpsc::Sender<HostEvent>,
    /// The event loop task.
    task: Mutex<Option<JoinHandle<()>>>,
}

/// The host's published video track.
struct Video {
    /// Source the track is fed from.
    source: NativeVideoSource,
    /// What the source takes.
    input: VideoInput,
    /// The track's publication ID.
    sid: TrackSid,
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
    /// Key the host's track is encrypted with; differs from `media_key` during a rotation.
    active_key: SessionKey,
    /// Key index of `active_key`.
    active_index: u8,
    /// When each viewer was last sent a refusal.
    refused: HashMap<DeviceId, Instant>,
}

/// An unanswered session request.
struct Pending {
    /// The requesting device.
    viewer: DeviceId,
    /// Its public key.
    key: PublicKey,
    /// When the request arrived.
    requested_at: Instant,
}

/// An accepted viewer.
struct Viewer {
    /// Its session ID.
    session_id: String,
    /// Sealed data channel with it.
    channel: PeerChannel,
    /// Whether it is in the room and has been sent the current media keys.
    joined: bool,
    /// Whether it was ever sent a media key.
    keyed: bool,
    /// When it was accepted.
    accepted_at: Instant,
    /// When it dropped out of the room, while it may still come back.
    left_at: Option<Instant>,
    /// Serialize sealing and sending per topic so each topic's counters leave in order.
    send_locks: Arc<[tokio::sync::Mutex<()>; 3]>,
}

impl State {
    /// Returns the media keys a newly joined viewer needs, as `(index, key)`.
    ///
    /// That is the key the host encrypts with now and, while a rotation is
    /// under way, also the key it is about to switch to.
    fn join_keys(&self) -> Vec<(u8, [u8; 32])> {
        let mut keys = vec![(self.active_index, *self.active_key.as_bytes())];
        if self.media_index != self.active_index {
            keys.push((self.media_index, *self.media_key.as_bytes()));
        }
        keys
    }

    /// Returns whether `viewer` may be sent a refusal at `now`, and records it if so.
    fn may_refuse(&mut self, viewer: DeviceId, now: Instant) -> bool {
        self.refused
            .retain(|_, at| now.duration_since(*at) < REFUSAL_INTERVAL);
        if self.refused.contains_key(&viewer) {
            return false;
        }
        self.refused.insert(viewer, now);
        true
    }

    /// Frees the slots of accepted viewers that were never sent a key within [`JOIN_WINDOW`].
    fn purge_stale(&mut self, now: Instant) {
        self.viewers
            .retain(|_, v| v.keyed || now.duration_since(v.accepted_at) < JOIN_WINDOW);
    }

    /// Removes and returns requests older than `timeout`, as `(session_id, viewer)`.
    fn expire_pending(&mut self, now: Instant, timeout: Duration) -> Vec<(String, DeviceId)> {
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, p)| now.duration_since(p.requested_at) >= timeout)
            .map(|(sid, _)| sid.clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|sid| self.pending.remove(&sid).map(|p| (sid, p.viewer)))
            .collect()
    }

    /// Gives `viewer` a slot for `session_id` with data channel `channel`.
    ///
    /// Refused when the viewer already holds a slot that was sent a media key,
    /// or when [`MAX_VIEWERS`] other viewers hold slots. A slot the viewer holds
    /// without a key is replaced.
    fn admit(
        &mut self,
        viewer: DeviceId,
        session_id: &str,
        channel: PeerChannel,
        now: Instant,
    ) -> Result<(), DenyReason> {
        self.purge_stale(now);
        if self.viewers.get(&viewer).is_some_and(|v| v.keyed) {
            return Err(DenyReason::Denied);
        }
        let others = self.viewers.keys().filter(|v| **v != viewer).count();
        if others >= MAX_VIEWERS {
            return Err(DenyReason::RoomFull);
        }
        self.viewers.insert(
            viewer,
            Viewer {
                session_id: session_id.to_owned(),
                channel,
                joined: false,
                keyed: false,
                accepted_at: now,
                left_at: None,
                send_locks: Arc::default(),
            },
        );
        Ok(())
    }

    /// Records that `viewer` dropped out of the room at `now`; it may rejoin
    /// within the reconnect window. Returns whether it was a viewer.
    fn mark_left(&mut self, viewer: DeviceId, now: Instant) -> bool {
        match self.viewers.get_mut(&viewer) {
            Some(v) => {
                v.joined = false;
                v.left_at.get_or_insert(now);
                true
            }
            None => false,
        }
    }

    /// Removes and returns viewers that dropped out longer than `window` ago.
    fn expire_left(&mut self, now: Instant, window: Duration) -> Vec<(DeviceId, Viewer)> {
        let expired: Vec<DeviceId> = self
            .viewers
            .iter()
            .filter(|(_, v)| v.left_at.is_some_and(|at| now.duration_since(at) >= window))
            .map(|(id, _)| *id)
            .collect();
        expired
            .into_iter()
            .filter_map(|id| self.viewers.remove(&id).map(|v| (id, v)))
            .collect()
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
        let (lk_room, room_events) = room::connect(&url, &token, &key_provider, config.force_relay)
            .await
            .map_err(|e| match e {
                JoinError::Rejected => StartError::MediaUnavailable("token rejected".into()),
                JoinError::Unavailable(reason) => StartError::MediaUnavailable(reason),
            })?;
        let video = publish_video(&lk_room, &room::identity(device), 0, VideoInput::Raw, width, height)
            .await
            .map_err(StartError::MediaUnavailable)?;
        tracing::info!(device_id = %device, "hosting started");

        let (events, events_rx) = mpsc::channel(EVENT_CAPACITY);
        let inner = Arc::new(Inner {
            device,
            signaling,
            room: lk_room,
            keys,
            known,
            video: Mutex::new(video),
            video_switch: tokio::sync::Mutex::new(()),
            key_provider,
            rotate_lock: tokio::sync::Mutex::new(()),
            state: Mutex::new(State {
                pending: HashMap::new(),
                viewers: HashMap::new(),
                active_key: media_key.clone(),
                media_key,
                media_index: 0,
                active_index: 0,
                refused: HashMap::new(),
            }),
            config: config.clone(),
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
        inner.expire_requests().await;
        let nonce = crypto::random_nonce();
        let (viewer, outcome) = {
            let mut st = lock(&inner.state);
            let pending = st
                .pending
                .remove(session_id)
                .ok_or(HostError::UnknownRequest)?;
            let outcome = crypto::derive_session_key(
                &inner.keys,
                &pending.key,
                session_id,
                inner.device,
                pending.viewer,
                &nonce,
            )
            .map_err(|_| DenyReason::Denied)
            .and_then(|key| {
                let channel = PeerChannel::new(session_id.to_owned(), key, Side::Host);
                st.admit(pending.viewer, session_id, channel, Instant::now())
            });
            (pending.viewer, outcome)
        };
        match outcome {
            Err(reason) => inner.respond(viewer, session_id, Err(reason)).await,
            Ok(()) => {
                tracing::info!(viewer = %viewer, %session_id, "session accepted");
                inner.respond(viewer, session_id, Ok(&nonce)).await?;
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
            .respond(pending.viewer, session_id, Err(DenyReason::Denied))
            .await
    }

    /// Publishes one raw frame on the video track.
    ///
    /// Fails with [`FrameError::WrongInput`] while the track takes encoded frames.
    pub fn publish_frame(&self, frame: &Frame) -> Result<(), FrameError> {
        frame.validate()?;
        let source = self.source_for(VideoInput::Raw)?;
        source.capture_frame(&video::to_livekit(frame));
        Ok(())
    }

    /// Publishes one H.264 access unit on the video track.
    ///
    /// Fails with [`FrameError::WrongInput`] while the track takes raw frames, and
    /// with [`FrameError::ZeroSize`] for an empty picture or payload.
    pub fn publish_encoded(&self, frame: &EncodedFrame<'_>) -> Result<(), FrameError> {
        if frame.width == 0 || frame.height == 0 || frame.data.is_empty() {
            return Err(FrameError::ZeroSize);
        }
        let source = self.source_for(VideoInput::Encoded)?;
        source.capture_encoded_frame(&video::to_livekit_encoded(frame));
        Ok(())
    }

    /// Returns what the video track is currently fed with.
    pub fn video_input(&self) -> VideoInput {
        lock(&self.inner.video).input
    }

    /// Replaces the video track with one fed by `input` at `width` x `height`.
    ///
    /// Does nothing when the track already takes `input`. The new track is
    /// published before the old one is removed, so a failed switch leaves the
    /// old track and input in place. Viewers subscribe to the new track on
    /// their own; frame encryption keys are unchanged.
    pub async fn set_video_input(
        &self,
        input: VideoInput,
        width: u32,
        height: u32,
    ) -> Result<(), StartError> {
        let _switch = self.inner.video_switch.lock().await;
        if lock(&self.inner.video).input == input {
            return Ok(());
        }
        let own = room::identity(self.inner.device);
        let index = lock(&self.inner.state).active_index;
        let video = publish_video(&self.inner.room, &own, index, input, width, height)
            .await
            .map_err(StartError::MediaUnavailable)?;
        self.inner.sync_key_index();
        let old = std::mem::replace(&mut *lock(&self.inner.video), video).sid;
        tracing::info!(device_id = %self.inner.device, ?input, "video input switched");
        if let Err(e) = self.inner.room.local_participant().unpublish_track(&old).await {
            tracing::warn!(device_id = %self.inner.device, error = %e, "removing the previous video track failed");
        }
        Ok(())
    }

    /// Returns and clears whether the network asked the external encoder for a keyframe.
    ///
    /// Always false while the track takes raw frames.
    pub fn take_keyframe_request(&self) -> bool {
        let video = lock(&self.inner.video);
        video.input == VideoInput::Encoded && video.source.take_keyframe_request()
    }

    /// Returns and clears the latest rate the network asked the external encoder for.
    ///
    /// Always `None` while the track takes raw frames.
    pub fn take_rate_request(&self) -> Option<RateRequest> {
        let video = lock(&self.inner.video);
        if video.input != VideoInput::Encoded {
            return None;
        }
        video.source.take_rate_control_request().map(|r| RateRequest {
            bitrate_bps: r.target_bitrate_bps,
            framerate: r.framerate_fps,
        })
    }

    /// Returns the video source when the track takes `input`.
    fn source_for(&self, input: VideoInput) -> Result<NativeVideoSource, FrameError> {
        let video = lock(&self.inner.video);
        if video.input != input {
            return Err(FrameError::WrongInput);
        }
        Ok(video.source.clone())
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

/// Publishes a `width` x `height` H.264 screen track in `room` fed by `input`.
///
/// The track's frame cryptor encrypts with key `key_index` of `own` from its
/// first frame on.
async fn publish_video(
    room: &Room,
    own: &ParticipantIdentity,
    key_index: u8,
    input: VideoInput,
    width: u32,
    height: u32,
) -> Result<Video, String> {
    let resolution = VideoResolution { width, height };
    let (source, backend) = match input {
        VideoInput::Raw => (
            NativeVideoSource::new(resolution, true),
            VideoEncoderBackend::Auto,
        ),
        VideoInput::Encoded => (
            NativeVideoSource::new_encoded(resolution),
            VideoEncoderBackend::PreEncoded,
        ),
    };
    let track =
        LocalVideoTrack::create_video_track("screen", RtcVideoSource::Native(source.clone()));
    let publication = room
        .local_participant()
        .publish_track(
            LocalTrack::Video(track),
            TrackPublishOptions {
                source: TrackSource::Screenshare,
                video_codec: VideoCodec::H264,
                video_encoding: Some(VideoEncoding {
                    max_bitrate: MAX_BITRATE,
                    max_framerate: MAX_FRAMERATE,
                }),
                video_encoder: backend,
                simulcast: false,
                ..Default::default()
            },
        )
        .await
        .map_err(|e| e.to_string())?;
    sync_own_key_index(room, own, key_index);
    Ok(Video {
        source,
        input,
        sid: publication.sid(),
    })
}

impl Inner {
    /// Makes every frame cryptor of the host's tracks encrypt with the active key.
    ///
    /// Runs under the state lock, like the rotation that changes the active
    /// key, so a sync can never move cryptors back to a key that was retired.
    fn sync_key_index(&self) {
        let st = lock(&self.state);
        sync_own_key_index(&self.room, &room::identity(self.device), st.active_index);
    }

    /// Answers `viewer`'s request `session_id`: accepted with the session's
    /// host nonce, or refused with a reason.
    async fn respond(
        &self,
        viewer: DeviceId,
        session_id: &str,
        answer: Result<&[u8; 32], DenyReason>,
    ) -> Result<(), HostError> {
        let (reason, host_public_key, host_nonce) = match answer {
            Ok(nonce) => (
                None,
                Some(self.keys.public_key().to_base64()),
                Some(STANDARD.encode(nonce)),
            ),
            Err(reason) => (Some(reason), None, None),
        };
        self.signaling
            .send(ClientMessage::SessionResponse {
                to: viewer,
                session_id: session_id.to_owned(),
                accepted: answer.is_ok(),
                reason,
                host_public_key,
                host_nonce,
            })
            .await?;
        Ok(())
    }

    /// Seals `msg` for `viewer` and sends it.
    async fn send(&self, viewer: DeviceId, msg: &DataMessage) -> Result<(), SendError> {
        let slot = topic_index(msg.topic()).expect("every message topic is known");
        let locks = lock(&self.state)
            .viewers
            .get(&viewer)
            .map(|v| Arc::clone(&v.send_locks))
            .ok_or(SendError::NotConnected)?;
        let _order = locks[slot].lock().await;
        let sealed = {
            let mut st = lock(&self.state);
            let v = st.viewers.get_mut(&viewer).ok_or(SendError::NotConnected)?;
            v.channel.seal(msg)?
        };
        room::send(&self.room, viewer, msg.topic(), msg.is_reliable(), sealed).await
    }

    /// Forgets `viewer` and reports that it left, if it was a viewer.
    ///
    /// A viewer that was sent a media key could still hold it, so the key is rotated.
    async fn remove_viewer(self: &Arc<Self>, viewer: DeviceId) {
        let removed = lock(&self.state).viewers.remove(&viewer);
        if let Some(v) = removed {
            self.viewer_gone(viewer, v).await;
        }
    }

    /// Rotates the media key if `v` held it and reports that `viewer` left.
    async fn viewer_gone(self: &Arc<Self>, viewer: DeviceId, v: Viewer) {
        tracing::info!(viewer = %viewer, session_id = %v.session_id, "viewer left");
        if v.keyed {
            spawn_rotation(self);
        }
        let _ = self.events.send(HostEvent::ViewerLeft { viewer }).await;
    }

    /// Drops requests the viewer has given up on and reports each one.
    async fn expire_requests(&self) {
        let expired = lock(&self.state).expire_pending(Instant::now(), self.config.request_timeout);
        for (session_id, viewer) in expired {
            tracing::info!(viewer = %viewer, %session_id, "session request expired");
            let _ = self
                .events
                .send(HostEvent::RequestExpired { session_id, viewer })
                .await;
        }
    }

    /// Ends the sessions of viewers that dropped out and did not return within the reconnect window.
    async fn expire_departed(self: &Arc<Self>) {
        let gone = lock(&self.state).expire_left(Instant::now(), self.config.reconnect_window);
        for (viewer, v) in gone {
            self.viewer_gone(viewer, v).await;
        }
    }

    /// Records that `viewer` dropped out of the room; it keeps its slot for the reconnect window.
    fn on_viewer_dropped(&self, viewer: DeviceId) {
        if lock(&self.state).mark_left(viewer, Instant::now()) {
            tracing::info!(viewer = %viewer, "viewer dropped out, waiting for it to return");
        }
    }

    /// Hands a data message to the application unless its event buffer is nearly full.
    ///
    /// The last [`LIFECYCLE_RESERVE`] slots are kept for lifecycle events, so a
    /// flood of data never blocks the session.
    fn emit_data(&self, event: HostEvent) {
        if self.events.capacity() > LIFECYCLE_RESERVE {
            let _ = self.events.try_send(event);
        } else {
            tracing::warn!(device_id = %self.device, "application not reading events, data message dropped");
        }
    }

    /// Handles a session request from `viewer`.
    ///
    /// Requests with a malformed key, from a viewer already in the room, with a
    /// session ID or viewer that is already pending, or beyond [`MAX_PENDING`]
    /// are refused, as are viewers whose key differs from the pinned one. Each
    /// viewer is told about a refusal at most once per [`REFUSAL_INTERVAL`];
    /// further requests in that interval are dropped without an answer. A
    /// viewer that was accepted but never joined may request again; accepting
    /// that request replaces its old slot.
    async fn on_request(&self, viewer: DeviceId, session_id: String, key: String) {
        self.expire_requests().await;
        let decision = match PublicKey::from_base64(&key) {
            Err(_) => Err(DenyReason::Denied),
            Ok(key) => {
                let mut st = lock(&self.state);
                let duplicate = st.pending.contains_key(&session_id)
                    || st.viewers.get(&viewer).is_some_and(|v| v.joined)
                    || st.pending.values().any(|p| p.viewer == viewer);
                if duplicate || st.pending.len() >= MAX_PENDING {
                    Err(DenyReason::Denied)
                } else {
                    match lock(&self.known).check(viewer, &key) {
                        Err(changed) => Ok(Err(changed)),
                        Ok(()) => {
                            st.pending.insert(
                                session_id.clone(),
                                Pending {
                                    viewer,
                                    key,
                                    requested_at: Instant::now(),
                                },
                            );
                            Ok(Ok(key.fingerprint()))
                        }
                    }
                }
            }
        };
        if let Ok(Ok(fingerprint)) = decision {
            tracing::info!(viewer = %viewer, %session_id, "session requested");
            let _ = self
                .events
                .send(HostEvent::ViewerRequested {
                    session_id,
                    viewer,
                    fingerprint,
                })
                .await;
            return;
        }
        let may_refuse = lock(&self.state).may_refuse(viewer, Instant::now());
        if !may_refuse {
            return;
        }
        match decision {
            Ok(Err(changed)) => {
                tracing::warn!(viewer = %viewer, %session_id, "viewer key changed, request refused");
                let _ = self.events.send(HostEvent::KeyChanged(changed)).await;
                let _ = self
                    .respond(viewer, &session_id, Err(DenyReason::KeyChanged))
                    .await;
            }
            Err(reason) => {
                tracing::info!(viewer = %viewer, %session_id, "session request refused");
                let _ = self.respond(viewer, &session_id, Err(reason)).await;
            }
            Ok(Ok(_)) => {}
        }
    }

    /// Hands the media key, and during a rotation also the next one, to `viewer` once it is in the room.
    async fn on_viewer_active(&self, viewer: DeviceId) {
        let keys = {
            let mut st = lock(&self.state);
            let keys = st.join_keys();
            match st.viewers.get_mut(&viewer) {
                Some(v) if !v.joined => {
                    v.joined = true;
                    v.keyed = true;
                    v.left_at = None;
                    keys
                }
                _ => return,
            }
        };
        for (index, key) in keys {
            let msg = DataMessage::Control(Control::MediaKey { index, key });
            if let Err(err) = self.send(viewer, &msg).await {
                tracing::warn!(viewer = %viewer, error = %err, "sending media key failed");
                return;
            }
        }
        tracing::info!(viewer = %viewer, "viewer joined");
        let _ = self.events.send(HostEvent::ViewerJoined { viewer }).await;
    }

    /// Opens a sealed payload from a participant and acts on it.
    async fn on_data(self: &Arc<Self>, incoming: Incoming) {
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
                self.emit_data(HostEvent::DataReceived { viewer, message });
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
    let mut gates: HashMap<String, room::StreamGate> = HashMap::new();
    let mut housekeeping = tokio::time::interval(HOUSEKEEPING_INTERVAL);
    let mut signaling_open = true;
    let reason = loop {
        tokio::select! {
            msg = signaling.recv(), if signaling_open => match msg {
                Some(ServerMessage::SessionRequest { from, session_id, viewer_public_key, .. }) => {
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
                        inner.on_viewer_dropped(viewer);
                    }
                }
                Some(RoomEvent::DataReceived { payload, topic: Some(topic), participant: Some(p), .. }) => {
                    inner.on_data(Incoming { from: p.identity().0, topic, payload: payload.to_vec() }).await;
                }
                Some(RoomEvent::ByteStreamOpened { reader, topic, participant_identity }) => {
                    let from_viewer = participant_identity
                        .0
                        .parse()
                        .is_ok_and(|viewer| lock(&inner.state).viewers.contains_key(&viewer));
                    if let (true, Some(reader)) = (from_viewer, reader.take()) {
                        let gate = gates
                            .entry(participant_identity.0.clone())
                            .or_insert_with(room::StreamGate::new);
                        room::read_clipboard_stream(reader, topic, participant_identity.0, gate, incoming_tx.clone());
                    }
                }
                Some(RoomEvent::LocalTrackPublished { .. } | RoomEvent::LocalTrackRepublished { .. }) => {
                    inner.sync_key_index();
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
            _ = housekeeping.tick() => {
                inner.expire_requests().await;
                inner.expire_departed().await;
                gates.retain(|identity, _| {
                    identity
                        .parse()
                        .is_ok_and(|viewer| lock(&inner.state).viewers.contains_key(&viewer))
                });
            }
            _ = watch.expired() => break EndReason::Timeout,
        }
    };
    tracing::info!(device_id = %inner.device, ?reason, "hosting ended");
    let _ = inner.room.close().await;
    let _ = inner.events.send(HostEvent::Ended { reason }).await;
}

/// Replaces the media key in the background.
///
/// The new key goes to every remaining joined viewer at the next key index;
/// after [`KEY_SWITCH_DELAY`] the host encrypts with it. Viewers that left
/// keep only older keys and cannot decrypt frames from then on. A viewer the
/// new key could not be sent to is hung up on, since it could no longer decrypt.
fn spawn_rotation(inner: &Arc<Inner>) {
    let inner = Arc::clone(inner);
    tokio::spawn(async move {
        let _serial = inner.rotate_lock.lock().await;
        let (index, key, remaining) = {
            let mut st = lock(&inner.state);
            st.media_index = (st.media_index + 1) % KEY_RING_SIZE;
            st.media_key = SessionKey::random();
            let remaining: Vec<DeviceId> = st
                .viewers
                .iter()
                .filter(|(_, v)| v.joined)
                .map(|(id, _)| *id)
                .collect();
            (st.media_index, *st.media_key.as_bytes(), remaining)
        };
        let msg = DataMessage::Control(Control::MediaKey { index, key });
        let mut failed = Vec::new();
        for viewer in remaining {
            if let Err(err) = inner.send(viewer, &msg).await {
                tracing::warn!(viewer = %viewer, error = %err, "sending rotated media key failed, ending its session");
                failed.push(viewer);
            }
        }
        tokio::time::sleep(KEY_SWITCH_DELAY).await;
        let own = room::identity(inner.device);
        inner
            .key_provider
            .set_key(&own, i32::from(index), key.to_vec());
        {
            let mut st = lock(&inner.state);
            st.active_index = index;
            st.active_key = SessionKey::from_bytes(key);
            sync_own_key_index(&inner.room, &own, index);
        }
        tracing::info!(device_id = %inner.device, index, "media key rotated");
        drop(_serial);
        for viewer in failed {
            let _ = inner
                .send(viewer, &DataMessage::Control(Control::Hangup))
                .await;
            inner.remove_viewer(viewer).await;
        }
    });
}

/// Makes every frame cryptor of `own`'s published tracks encrypt with key `index`.
fn sync_own_key_index(lk_room: &Room, own: &ParticipantIdentity, index: u8) {
    for ((identity, _), cryptor) in lk_room.e2ee_manager().frame_cryptors() {
        if &identity == own {
            cryptor.set_key_index(i32::from(index));
        }
    }
}

/// Locks `m`, recovering from a poisoned lock.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use livekit::webrtc::prelude::{RtcVideoSource, VideoResolution};

    use super::*;
    use crate::testutil::{env, mint_token, room_name, unix_now};

    /// Publishes a fresh video track named `name` on `lk_room`.
    async fn publish(lk_room: &Room, name: &str) {
        let source = NativeVideoSource::new(
            VideoResolution {
                width: 64,
                height: 64,
            },
            true,
        );
        let track = LocalVideoTrack::create_video_track(name, RtcVideoSource::Native(source));
        lk_room
            .local_participant()
            .publish_track(LocalTrack::Video(track), TrackPublishOptions::default())
            .await
            .unwrap();
    }

    fn state(media_index: u8, active_index: u8) -> State {
        State {
            pending: HashMap::new(),
            viewers: HashMap::new(),
            media_key: SessionKey::from_bytes([media_index; 32]),
            media_index,
            active_key: SessionKey::from_bytes([active_index; 32]),
            active_index,
            refused: HashMap::new(),
        }
    }

    fn id(n: u32) -> DeviceId {
        DeviceId::new(100_000_000 + n).unwrap()
    }

    fn channel(sid: &str) -> PeerChannel {
        PeerChannel::new(sid.into(), SessionKey::from_bytes([1; 32]), Side::Host)
    }

    fn pending(st: &mut State, sid: &str, viewer: DeviceId, at: Instant) {
        st.pending.insert(
            sid.into(),
            Pending {
                viewer,
                key: PublicKey::from_bytes([5; 32]),
                requested_at: at,
            },
        );
    }

    #[test]
    fn pending_requests_expire() {
        let mut st = state(0, 0);
        let t0 = Instant::now();
        pending(&mut st, "old", id(1), t0);
        pending(&mut st, "new", id(2), t0 + Duration::from_secs(50));
        let gone = st.expire_pending(t0 + Duration::from_secs(61), Duration::from_secs(60));
        assert_eq!(gone, vec![("old".to_owned(), id(1))]);
        assert!(st.pending.contains_key("new"));
    }

    #[test]
    fn keyed_viewer_cannot_be_replaced() {
        let mut st = state(0, 0);
        let now = Instant::now();
        st.admit(id(1), "s1", channel("s1"), now).unwrap();
        st.viewers.get_mut(&id(1)).unwrap().keyed = true;
        assert_eq!(
            st.admit(id(1), "s2", channel("s2"), now),
            Err(DenyReason::Denied)
        );
        assert_eq!(st.viewers[&id(1)].session_id, "s1");
    }

    #[test]
    fn unkeyed_slot_is_replaced_without_counting_twice() {
        let mut st = state(0, 0);
        let now = Instant::now();
        for n in 1..=MAX_VIEWERS as u32 {
            st.admit(id(n), "s", channel("s"), now).unwrap();
        }
        st.admit(id(1), "again", channel("again"), now).unwrap();
        assert_eq!(st.viewers[&id(1)].session_id, "again");
        assert_eq!(
            st.admit(id(99), "s", channel("s"), now),
            Err(DenyReason::RoomFull)
        );
    }

    #[test]
    fn stale_unkeyed_slots_are_freed() {
        let mut st = state(0, 0);
        let t0 = Instant::now();
        for n in 1..=MAX_VIEWERS as u32 {
            st.admit(id(n), "s", channel("s"), t0).unwrap();
        }
        st.viewers.get_mut(&id(1)).unwrap().keyed = true;
        st.admit(id(99), "s", channel("s"), t0 + JOIN_WINDOW)
            .unwrap();
        assert!(st.viewers.contains_key(&id(1)), "keyed viewer kept");
        assert_eq!(st.viewers.len(), 2);
    }

    #[test]
    fn viewer_that_drops_out_expires_after_window() {
        let mut st = state(0, 0);
        let t0 = Instant::now();
        st.admit(id(1), "s", channel("s"), t0).unwrap();
        st.viewers.get_mut(&id(1)).unwrap().joined = true;
        assert!(st.mark_left(id(1), t0));
        assert!(!st.viewers[&id(1)].joined, "a rejoin gets the keys again");
        assert!(!st.mark_left(id(2), t0));
        assert!(
            st.expire_left(t0 + Duration::from_secs(29), Duration::from_secs(30))
                .is_empty()
        );
        let gone = st.expire_left(t0 + Duration::from_secs(31), Duration::from_secs(30));
        assert_eq!(
            gone.iter().map(|(v, _)| *v).collect::<Vec<_>>(),
            vec![id(1)]
        );
        assert!(st.viewers.is_empty());
    }

    #[test]
    fn joining_viewer_gets_active_key_only_when_settled() {
        assert_eq!(state(2, 2).join_keys(), vec![(2, [2; 32])]);
    }

    #[test]
    fn joining_viewer_gets_both_keys_during_rotation() {
        assert_eq!(state(3, 2).join_keys(), vec![(2, [2; 32]), (3, [3; 32])]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_cryptors_take_current_key_index() {
        let now = unix_now();
        let own = room::identity(DeviceId::new(123_456_789).unwrap());
        let token = mint_token(&room_name(), &own.0, now, now + 60);
        let keys = room::key_provider();
        keys.set_key(&own, 0, vec![1; 32]);
        keys.set_key(&own, 3, vec![2; 32]);
        let (lk_room, _events) = room::connect(&env("LIVEKIT_URL"), &token, &keys, false)
            .await
            .unwrap();
        publish(&lk_room, "first").await;
        sync_own_key_index(&lk_room, &own, 3);
        publish(&lk_room, "second").await;
        let before: Vec<i32> = lk_room
            .e2ee_manager()
            .frame_cryptors()
            .values()
            .map(|c| c.key_index())
            .collect();
        assert!(
            before.contains(&0),
            "a new cryptor starts at index 0: {before:?}"
        );
        sync_own_key_index(&lk_room, &own, 3);
        let after: Vec<i32> = lk_room
            .e2ee_manager()
            .frame_cryptors()
            .values()
            .map(|c| c.key_index())
            .collect();
        assert_eq!(after, vec![3, 3]);
        lk_room.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn republished_video_encrypts_with_active_key_at_once() {
        let now = unix_now();
        let own = room::identity(DeviceId::new(123_456_788).unwrap());
        let token = mint_token(&room_name(), &own.0, now, now + 60);
        let keys = room::key_provider();
        keys.set_key(&own, 0, vec![1; 32]);
        keys.set_key(&own, 5, vec![2; 32]);
        let (lk_room, _events) = room::connect(&env("LIVEKIT_URL"), &token, &keys, false)
            .await
            .unwrap();
        for input in [VideoInput::Raw, VideoInput::Encoded] {
            publish_video(&lk_room, &own, 5, input, 64, 64).await.unwrap();
        }
        let indices: Vec<i32> = lk_room
            .e2ee_manager()
            .frame_cryptors()
            .values()
            .map(|c| c.key_index())
            .collect();
        assert_eq!(indices, vec![5, 5]);
        lk_room.close().await.unwrap();
    }
}
