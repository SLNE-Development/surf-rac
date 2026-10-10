//! The host side of a session: publishes the screen and serves up to
//! [`MAX_VIEWERS`] accepted viewers in the host's own LiveKit room.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use livekit::options::{TrackPublishOptions, VideoCodec, VideoEncoderBackend, VideoEncoding};
use livekit::participant::ParticipantTrackPermission;
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
use crate::crypto::{
    self, Ephemeral, EphemeralPublic, IdentityKey, IdentityPublic, Role, SessionKey,
};
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
    /// A viewer asks for a session and the user must decide; answer with
    /// [`HostSession::accept`] or [`HostSession::deny`].
    ViewerRequested {
        /// Identifies the request.
        session_id: String,
        /// The requesting device.
        viewer: DeviceId,
        /// The requesting device's name, as registered with the server.
        name: String,
        /// Fingerprint of the viewer's identity key.
        fingerprint: String,
        /// The viewer's identity key.
        viewer_key: IdentityPublic,
        /// Whether the viewer asked for unattended access: password access was
        /// unavailable, or the password it sent was rejected.
        unattended: bool,
    },
    /// A viewer that asked for unattended access sent its password.
    ///
    /// Check the password and answer with [`HostSession::accept`] when it is
    /// correct, [`HostSession::reject_password`] to ask the user instead, or
    /// [`HostSession::deny`].
    PasswordReceived {
        /// Identifies the request.
        session_id: String,
        /// The requesting device.
        viewer: DeviceId,
        /// The requesting device's name, as registered with the server.
        name: String,
        /// Fingerprint of the viewer's identity key.
        fingerprint: String,
        /// The viewer's identity key.
        viewer_key: IdentityPublic,
        /// The password, or `None` when the sealed password could not be opened.
        password: Option<Password>,
    },
    /// A viewer presented an identity key that differs from its pinned key; its request was refused.
    KeyChanged(KeyChanged),
    /// An accepted viewer joined the room and received the media key.
    ViewerJoined {
        /// The viewer device.
        viewer: DeviceId,
    },
    /// A request expired: it was not answered within the request timeout, so
    /// the viewer has given up, or the viewer did not send its password within
    /// the challenge timeout, so the host refused it.
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

/// An unattended password a viewer sent; its `Debug` output hides the text.
#[derive(Clone, PartialEq, Eq)]
pub struct Password(String);

impl Password {
    /// Returns the password text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Password {
    /// Writes a placeholder instead of the password.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(..)")
    }
}

/// Why a host action failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    /// No pending request has this session ID, or it is not at a step the action applies to.
    #[error("unknown session request")]
    UnknownRequest,
    /// The signaling connection failed.
    #[error(transparent)]
    Signaling(#[from] SignalingError),
}

/// Why pausing or resuming a viewer's view failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PauseError {
    /// The device is not an accepted viewer of this session.
    #[error("not a viewer of this session")]
    NotViewer,
    /// The video subscription permissions could not be updated. While any
    /// view is paused the video track is then muted for everyone.
    #[error("the video permissions could not be updated: {0}")]
    Permissions(String),
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
    /// This device's identity key.
    identity: Arc<IdentityKey>,
    /// Pinned viewer identity keys.
    known: Arc<Mutex<KnownKeys>>,
    /// Whether unattended requests get a password challenge instead of a prompt.
    password_access: AtomicBool,
    /// The published video track and its source.
    video: Mutex<Video>,
    /// Serializes switches of the video input.
    video_switch: tokio::sync::Mutex<()>,
    /// Frame-encryption keys.
    key_provider: livekit::e2ee::key_provider::KeyProvider,
    /// Serializes media key rotations.
    rotate_lock: tokio::sync::Mutex<()>,
    /// Serializes updates of the video track's subscription permissions.
    permissions_lock: tokio::sync::Mutex<()>,
    /// Whether the video track is muted and fed no frames because the
    /// subscription permissions could not be applied while a view was paused.
    video_muted: AtomicBool,
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
    /// Whether the view is paused for every viewer, including viewers that join later.
    all_paused: bool,
}

/// An unanswered session request.
struct Pending {
    /// The requesting device.
    viewer: DeviceId,
    /// The requesting device's name.
    name: String,
    /// The viewer's identity key.
    viewer_key: IdentityPublic,
    /// Its signed per-session key.
    session_key: EphemeralPublic,
    /// When the request arrived.
    requested_at: Instant,
    /// How far the request has got.
    stage: Stage,
}

/// The step an unanswered session request is at.
enum Stage {
    /// The user was asked to accept or deny it.
    Prompt {
        /// The session keys agreed in an earlier password challenge, which an
        /// accept answers with; `None` when there was no challenge.
        agreed: Option<Agreed>,
    },
    /// A password challenge was sent at `sent_at`; the host waits for the password.
    AwaitingPassword {
        /// The host's per-session key pair offered in the challenge.
        ephemeral: Ephemeral,
        /// The host nonce offered in the challenge.
        nonce: [u8; 32],
        /// When the challenge was sent.
        sent_at: Instant,
    },
    /// The password arrived and was handed to the application for checking.
    PasswordReceived {
        /// The session keys agreed in the challenge.
        agreed: Agreed,
    },
}

/// The host side of an agreed session key.
struct Agreed {
    /// The host's per-session public key.
    host_key: EphemeralPublic,
    /// The host nonce.
    nonce: [u8; 32],
    /// The derived session key.
    key: SessionKey,
}

impl Agreed {
    /// Agrees on the session key for `session_id` between the host's
    /// per-session key pair `ephemeral` with `nonce` and the viewer's
    /// per-session key `viewer_key`.
    ///
    /// Fails with [`crypto::CryptoError::LowOrderPoint`] when `viewer_key`
    /// yields no shared secret.
    fn new(
        ephemeral: &Ephemeral,
        nonce: [u8; 32],
        viewer_key: &EphemeralPublic,
        session_id: &str,
        host: DeviceId,
        viewer: DeviceId,
    ) -> Result<Self, crypto::CryptoError> {
        let shared = ephemeral.agree(viewer_key)?;
        Ok(Self {
            host_key: ephemeral.public(),
            nonce,
            key: crypto::derive_session_key(
                &shared,
                viewer_key,
                &ephemeral.public(),
                session_id,
                &nonce,
                host,
                viewer,
            ),
        })
    }
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
    /// Whether the host paused this viewer's view; it may not subscribe to the video track.
    paused: bool,
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

    /// Removes and returns requests older than `timeout`, and requests whose
    /// password challenge is older than `challenge_timeout`.
    ///
    /// Each entry is `(session_id, viewer, challenged)`, where `challenged`
    /// says whether the request was still waiting for its password.
    fn expire_pending(
        &mut self,
        now: Instant,
        timeout: Duration,
        challenge_timeout: Duration,
    ) -> Vec<(String, DeviceId, bool)> {
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, p)| {
                now.duration_since(p.requested_at) >= timeout
                    || matches!(p.stage, Stage::AwaitingPassword { sent_at, .. }
                        if now.duration_since(sent_at) >= challenge_timeout)
            })
            .map(|(sid, _)| sid.clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|sid| {
                self.pending.remove(&sid).map(|p| {
                    let challenged = matches!(p.stage, Stage::AwaitingPassword { .. });
                    (sid, p.viewer, challenged)
                })
            })
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
        let paused = self.all_paused || self.viewers.get(&viewer).is_some_and(|v| v.paused);
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
                paused,
            },
        );
        Ok(())
    }

    /// Returns who may subscribe to the video track: `None` when every
    /// participant may, otherwise the viewers that may, which are all viewers
    /// whose view is not paused.
    fn video_permissions(&self) -> Option<Vec<DeviceId>> {
        if !self.all_paused && !self.viewers.values().any(|v| v.paused) {
            return None;
        }
        let mut allowed: Vec<DeviceId> = self
            .viewers
            .iter()
            .filter(|(_, v)| !v.paused)
            .map(|(id, _)| *id)
            .collect();
        allowed.sort_by_key(|id| id.to_string());
        Some(allowed)
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
        identity: Arc<IdentityKey>,
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
        let video = publish_video(
            &lk_room,
            &room::identity(device),
            0,
            VideoInput::Raw,
            width,
            height,
        )
        .await
        .map_err(StartError::MediaUnavailable)?;
        tracing::info!(device_id = %device, "hosting started");

        let (events, events_rx) = mpsc::channel(EVENT_CAPACITY);
        let inner = Arc::new(Inner {
            device,
            signaling,
            room: lk_room,
            identity,
            known,
            password_access: AtomicBool::new(false),
            video: Mutex::new(video),
            video_switch: tokio::sync::Mutex::new(()),
            key_provider,
            rotate_lock: tokio::sync::Mutex::new(()),
            permissions_lock: tokio::sync::Mutex::new(()),
            video_muted: AtomicBool::new(false),
            state: Mutex::new(State {
                pending: HashMap::new(),
                viewers: HashMap::new(),
                active_key: media_key.clone(),
                media_key,
                media_index: 0,
                active_index: 0,
                refused: HashMap::new(),
                all_paused: false,
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

    /// Sets whether unattended requests get a password challenge.
    ///
    /// When `available` is true, a viewer that asks for unattended access is
    /// sent the host's signed per-session key and may answer with its
    /// password, which arrives as [`HostEvent::PasswordReceived`]. When false
    /// (the default), such requests arrive as [`HostEvent::ViewerRequested`].
    pub fn set_password_access(&self, available: bool) {
        self.inner
            .password_access
            .store(available, Ordering::Relaxed);
    }

    /// Accepts the pending request `session_id`.
    ///
    /// The viewer gets the host's per-session key, signed with the host's
    /// identity key, the host nonce and a join token for the room. After a
    /// password challenge, also one whose password was rejected, these are the
    /// key and nonce of the challenge; otherwise they are fresh. When the room
    /// already has [`MAX_VIEWERS`] viewers the request is refused as room full
    /// instead. Fails with [`HostError::UnknownRequest`] while the request
    /// still waits for its password.
    pub async fn accept(&self, session_id: &str) -> Result<(), HostError> {
        let inner = &self.inner;
        inner.expire_requests().await;
        let (viewer, outcome) = {
            let mut st = lock(&inner.state);
            if st
                .pending
                .get(session_id)
                .is_some_and(|p| matches!(p.stage, Stage::AwaitingPassword { .. }))
            {
                return Err(HostError::UnknownRequest);
            }
            let pending = st
                .pending
                .remove(session_id)
                .ok_or(HostError::UnknownRequest)?;
            let agreed = match pending.stage {
                Stage::PasswordReceived { agreed }
                | Stage::Prompt {
                    agreed: Some(agreed),
                } => Ok(agreed),
                Stage::AwaitingPassword { .. } => unreachable!("checked above"),
                Stage::Prompt { agreed: None } => Agreed::new(
                    &Ephemeral::generate(),
                    crypto::random_nonce(),
                    &pending.session_key,
                    session_id,
                    inner.device,
                    pending.viewer,
                ),
            };
            let outcome = agreed.map_err(|_| DenyReason::Denied).and_then(|agreed| {
                let channel = PeerChannel::new(session_id.to_owned(), agreed.key, Side::Host);
                st.admit(pending.viewer, session_id, channel, Instant::now())
                    .map(|()| (agreed.host_key, agreed.nonce))
            });
            (pending.viewer, outcome)
        };
        match outcome {
            Err(reason) => inner.respond(viewer, session_id, Err(reason)).await,
            Ok((host_key, nonce)) => {
                tracing::info!(viewer = %viewer, %session_id, "session accepted");
                let _ = inner.apply_video_permissions().await;
                inner
                    .respond(viewer, session_id, Ok((&host_key, &nonce)))
                    .await?;
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

    /// Reports that the password of request `session_id` was wrong.
    ///
    /// The request falls back to asking the user: the host emits
    /// [`HostEvent::ViewerRequested`] with `unattended` set and keeps the
    /// challenge's keys for an accept. Fails with [`HostError::UnknownRequest`]
    /// unless the request's password was received and not yet answered.
    pub async fn reject_password(&self, session_id: &str) -> Result<(), HostError> {
        let event = {
            let mut st = lock(&self.inner.state);
            let pending = st
                .pending
                .get_mut(session_id)
                .filter(|p| matches!(p.stage, Stage::PasswordReceived { .. }))
                .ok_or(HostError::UnknownRequest)?;
            let Stage::PasswordReceived { agreed } =
                std::mem::replace(&mut pending.stage, Stage::Prompt { agreed: None })
            else {
                unreachable!("checked above")
            };
            pending.stage = Stage::Prompt {
                agreed: Some(agreed),
            };
            prompt_event(session_id, pending, true)
        };
        tracing::info!(%session_id, "password rejected, asking the user");
        let _ = self.inner.events.send(event).await;
        Ok(())
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
    /// Fails with [`FrameError::WrongInput`] while the track takes encoded
    /// frames. While the track is muted because a pause could not be enforced,
    /// the frame is dropped.
    pub fn publish_frame(&self, frame: &Frame) -> Result<(), FrameError> {
        frame.validate()?;
        let source = self.source_for(VideoInput::Raw)?;
        if !self.inner.video_muted.load(Ordering::Acquire) {
            source.capture_frame(&video::to_livekit(frame));
        }
        Ok(())
    }

    /// Publishes one H.264 access unit on the video track.
    ///
    /// Fails with [`FrameError::WrongInput`] while the track takes raw frames, and
    /// with [`FrameError::ZeroSize`] for an empty picture or payload. While the
    /// track is muted because a pause could not be enforced, the frame is dropped.
    pub fn publish_encoded(&self, frame: &EncodedFrame<'_>) -> Result<(), FrameError> {
        if frame.width == 0 || frame.height == 0 || frame.data.is_empty() {
            return Err(FrameError::ZeroSize);
        }
        let source = self.source_for(VideoInput::Encoded)?;
        if !self.inner.video_muted.load(Ordering::Acquire) {
            source.capture_encoded_frame(&video::to_livekit_encoded(frame));
        }
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
        self.inner.sync_mute();
        let _ = self.inner.apply_video_permissions().await;
        tracing::info!(device_id = %self.inner.device, ?input, "video input switched");
        if let Err(e) = self
            .inner
            .room
            .local_participant()
            .unpublish_track(&old)
            .await
        {
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
        video
            .source
            .take_rate_control_request()
            .map(|r| RateRequest {
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

    /// Pauses (`paused` true) or resumes the view of `viewer` without ending its session.
    ///
    /// While paused the viewer may not subscribe to the video track, so the
    /// SFU forwards it no frames; on resume it subscribes again and the SFU
    /// asks the encoder for a keyframe. Once the permissions are updated the
    /// viewer is told with [`Control::ViewPaused`]; a viewer that is accepted
    /// but not yet in the room is told when it joins.
    ///
    /// Fails with [`PauseError::NotViewer`] when `viewer` is not an accepted
    /// viewer, and with [`PauseError::Permissions`] when the permissions could
    /// not be updated; a pause then still holds because the video track is
    /// muted for everyone, while a resume leaves the viewer without video.
    pub async fn pause_view(&self, viewer: DeviceId, paused: bool) -> Result<(), PauseError> {
        {
            let mut st = lock(&self.inner.state);
            let v = st.viewers.get_mut(&viewer).ok_or(PauseError::NotViewer)?;
            v.paused = paused;
        }
        let applied = self.inner.apply_video_permissions().await;
        tracing::info!(viewer = %viewer, paused, ok = applied.is_ok(), "view pause changed");
        if paused || applied.is_ok() {
            self.inner.tell_paused(viewer, paused).await;
        }
        applied
    }

    /// Pauses (`paused` true) or resumes the view of every viewer without ending their sessions.
    ///
    /// While paused, viewers that join later start paused as well. Once the
    /// permissions are updated every viewer in the room is told with
    /// [`Control::ViewPaused`]; viewers the message cannot reach are skipped.
    /// Fails with [`PauseError::Permissions`] like [`HostSession::pause_view`].
    pub async fn pause_all(&self, paused: bool) -> Result<(), PauseError> {
        let viewers: Vec<DeviceId> = {
            let mut st = lock(&self.inner.state);
            st.all_paused = paused;
            st.viewers
                .iter_mut()
                .map(|(id, v)| {
                    v.paused = paused;
                    *id
                })
                .collect()
        };
        let applied = self.inner.apply_video_permissions().await;
        tracing::info!(device_id = %self.inner.device, paused, ok = applied.is_ok(), "view pause changed for all viewers");
        if paused || applied.is_ok() {
            for viewer in viewers {
                self.inner.tell_paused(viewer, paused).await;
            }
        }
        applied
    }

    /// Returns whether the view of `viewer` is paused; false for an unknown viewer.
    pub fn is_view_paused(&self, viewer: DeviceId) -> bool {
        lock(&self.inner.state)
            .viewers
            .get(&viewer)
            .is_some_and(|v| v.paused)
    }

    /// Returns whether the view is paused for every viewer, including viewers that join later.
    pub fn is_all_paused(&self) -> bool {
        lock(&self.inner.state).all_paused
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

    /// Answers `viewer`'s request `session_id`: accepted with the host's
    /// per-session key, signed with its identity key, and the session's host
    /// nonce, or refused with a reason.
    async fn respond(
        &self,
        viewer: DeviceId,
        session_id: &str,
        answer: Result<(&EphemeralPublic, &[u8; 32]), DenyReason>,
    ) -> Result<(), HostError> {
        let (reason, session_key, signature, host_nonce) = match answer {
            Ok((key, nonce)) => (
                None,
                Some(key.to_base64()),
                Some(crypto::signature_to_base64(&self.identity.sign_session(
                    Role::Host,
                    session_id,
                    key,
                ))),
                Some(STANDARD.encode(nonce)),
            ),
            Err(reason) => (Some(reason), None, None, None),
        };
        self.signaling
            .send(ClientMessage::SessionResponse {
                to: viewer,
                session_id: session_id.to_owned(),
                accepted: answer.is_ok(),
                reason,
                session_key,
                signature,
                host_nonce,
            })
            .await?;
        Ok(())
    }

    /// Sets who may subscribe to the video track from the viewers' pause states.
    ///
    /// With no view paused every participant may subscribe; otherwise only
    /// the accepted viewers whose view is not paused may, and only to the
    /// screen track. The permissions are computed from the state at the time
    /// they are sent, and updates are serialized, so the last update always
    /// matches the latest state.
    ///
    /// When the update fails while a view is paused, the video track is muted
    /// and fed no frames until a later update succeeds, and
    /// [`PauseError::Permissions`] is returned.
    async fn apply_video_permissions(&self) -> Result<(), PauseError> {
        let _serial = self.permissions_lock.lock().await;
        let allowed = lock(&self.state).video_permissions();
        let restrictive = allowed.is_some();
        let screen = lock(&self.video).sid.clone();
        let (all, permissions) = match allowed {
            None => (true, Vec::new()),
            Some(viewers) => (false, screen_permissions(&viewers, &screen)),
        };
        let applied = self
            .room
            .local_participant()
            .set_track_subscription_permissions(all, permissions)
            .await
            .map_err(|err| PauseError::Permissions(err.to_string()));
        if let Err(err) = &applied {
            tracing::warn!(device_id = %self.device, error = %err, "updating video subscription permissions failed");
        }
        let muted = self.video_muted.load(Ordering::Acquire);
        if let Some(mute) = mute_after_apply(applied.is_ok(), restrictive, muted) {
            self.video_muted.store(mute, Ordering::Release);
            self.sync_mute();
            tracing::warn!(device_id = %self.device, muted = mute, "video track mute changed to enforce paused views");
        }
        applied
    }

    /// Mutes the published video track when [`Inner::video_muted`] is set and unmutes it otherwise.
    fn sync_mute(&self) {
        let sid = lock(&self.video).sid.clone();
        let Some(publication) = self.room.local_participant().get_track_publication(&sid) else {
            return;
        };
        if self.video_muted.load(Ordering::Acquire) {
            publication.mute();
        } else {
            publication.unmute();
        }
    }

    /// Tells `viewer` that its view is paused or resumed, if it is in the room.
    async fn tell_paused(&self, viewer: DeviceId, paused: bool) {
        let joined = lock(&self.state)
            .viewers
            .get(&viewer)
            .is_some_and(|v| v.joined);
        if !joined {
            return;
        }
        let msg = DataMessage::Control(Control::ViewPaused { paused });
        if let Err(err) = self.send(viewer, &msg).await {
            tracing::warn!(viewer = %viewer, error = %err, "sending view pause failed");
        }
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

    /// Follows the screen track to its new ID `sid` after the room republished
    /// it under `previous` and reapplies its mute and subscription permissions.
    async fn on_republished(&self, previous: &TrackSid, sid: TrackSid) {
        {
            let mut video = lock(&self.video);
            if video.sid != *previous {
                return;
            }
            video.sid = sid;
        }
        self.sync_mute();
        let _ = self.apply_video_permissions().await;
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

    /// Rotates the media key if `v` held it, withdraws its video permission
    /// and reports that `viewer` left.
    async fn viewer_gone(self: &Arc<Self>, viewer: DeviceId, v: Viewer) {
        tracing::info!(viewer = %viewer, session_id = %v.session_id, "viewer left");
        if v.keyed {
            spawn_rotation(self);
        }
        let _ = self.apply_video_permissions().await;
        let _ = self.events.send(HostEvent::ViewerLeft { viewer }).await;
    }

    /// Drops expired requests and reports each one.
    ///
    /// A request whose viewer did not send its password within the challenge
    /// timeout is also refused to the viewer.
    async fn expire_requests(&self) {
        let expired = lock(&self.state).expire_pending(
            Instant::now(),
            self.config.request_timeout,
            self.config.challenge_timeout,
        );
        for (session_id, viewer, challenged) in expired {
            tracing::info!(viewer = %viewer, %session_id, challenged, "session request expired");
            if challenged {
                let _ = self
                    .respond(viewer, &session_id, Err(DenyReason::Denied))
                    .await;
            }
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

    /// Handles a session request from `viewer` named `name`.
    ///
    /// `session_key` is the viewer's per-session key, `signature` its signature
    /// by the viewer's identity key and `identity_key` that identity key as
    /// attested by the server. A request with a malformed key or signature, or
    /// a signature that does not verify, is dropped without an answer and only
    /// logged. Requests from a viewer already in the room, with a session ID
    /// or viewer that is already pending, or beyond [`MAX_PENDING`] are
    /// refused, as are viewers whose identity key differs from the pinned one.
    /// Each viewer is told about a refusal at most once per
    /// [`REFUSAL_INTERVAL`]; further requests in that interval are dropped
    /// without an answer. A viewer that was accepted but never joined may
    /// request again; accepting that request replaces its old slot.
    ///
    /// An `unattended` request gets a password challenge while password access
    /// is available; any other request is handed to the user as
    /// [`HostEvent::ViewerRequested`].
    #[allow(clippy::too_many_arguments)]
    async fn on_request(
        &self,
        viewer: DeviceId,
        name: String,
        session_id: String,
        session_key: &str,
        signature: &str,
        identity_key: &str,
        unattended: bool,
    ) {
        self.expire_requests().await;
        let (viewer_key, session_key) = match verify_request(
            &session_id,
            session_key,
            signature,
            identity_key,
        ) {
            Ok(verified) => verified,
            Err(err) => {
                tracing::warn!(viewer = %viewer, %session_id, error = %err, "session request does not verify, dropped");
                return;
            }
        };
        let challenge = unattended && self.password_access.load(Ordering::Relaxed);
        let decision = {
            let mut st = lock(&self.state);
            let duplicate = st.pending.contains_key(&session_id)
                || st.viewers.get(&viewer).is_some_and(|v| v.joined)
                || st.pending.values().any(|p| p.viewer == viewer);
            if duplicate || st.pending.len() >= MAX_PENDING {
                Err(DenyReason::Denied)
            } else {
                match lock(&self.known).check(viewer, &viewer_key) {
                    Err(changed) => Ok(Err(changed)),
                    Ok(()) => {
                        let now = Instant::now();
                        let (stage, offer) = if challenge {
                            let ephemeral = Ephemeral::generate();
                            let nonce = crypto::random_nonce();
                            let offer = (ephemeral.public(), nonce);
                            let stage = Stage::AwaitingPassword {
                                ephemeral,
                                nonce,
                                sent_at: now,
                            };
                            (stage, Some(offer))
                        } else {
                            (Stage::Prompt { agreed: None }, None)
                        };
                        let pending = Pending {
                            viewer,
                            name,
                            viewer_key,
                            session_key,
                            requested_at: now,
                            stage,
                        };
                        let event = offer
                            .is_none()
                            .then(|| prompt_event(&session_id, &pending, unattended));
                        st.pending.insert(session_id.clone(), pending);
                        Ok(Ok((event, offer)))
                    }
                }
            }
        };
        let refusal = match decision {
            Ok(Ok((Some(event), _))) => {
                tracing::info!(viewer = %viewer, %session_id, unattended, "session requested");
                let _ = self.events.send(event).await;
                return;
            }
            Ok(Ok((None, Some((host_key, nonce))))) => {
                tracing::info!(viewer = %viewer, %session_id, "unattended session requested, password challenge sent");
                let signature = self
                    .identity
                    .sign_session(Role::Host, &session_id, &host_key);
                let sent = self
                    .signaling
                    .send(ClientMessage::PasswordChallenge {
                        to: viewer,
                        session_id: session_id.clone(),
                        session_key: host_key.to_base64(),
                        signature: crypto::signature_to_base64(&signature),
                        host_nonce: STANDARD.encode(nonce),
                    })
                    .await;
                if let Err(err) = sent {
                    tracing::warn!(viewer = %viewer, %session_id, error = %err, "sending password challenge failed");
                }
                return;
            }
            Ok(Ok((None, None))) => return,
            Ok(Err(changed)) => Err(changed),
            Err(reason) => Ok(reason),
        };
        let may_refuse = lock(&self.state).may_refuse(viewer, Instant::now());
        if !may_refuse {
            return;
        }
        match refusal {
            Err(changed) => {
                tracing::warn!(viewer = %viewer, %session_id, "viewer key changed, request refused");
                let _ = self.events.send(HostEvent::KeyChanged(changed)).await;
                let _ = self
                    .respond(viewer, &session_id, Err(DenyReason::KeyChanged))
                    .await;
            }
            Ok(reason) => {
                tracing::info!(viewer = %viewer, %session_id, "session request refused");
                let _ = self.respond(viewer, &session_id, Err(reason)).await;
            }
        }
    }

    /// Handles the sealed unattended password `sealed` that `viewer` sent for request `session_id`.
    ///
    /// The password is opened with the per-session key of the request's
    /// challenge, which is then dropped, and handed to the application as
    /// [`HostEvent::PasswordReceived`]. A password for a request that is not
    /// waiting for one, or from another device, is ignored.
    async fn on_password(&self, viewer: DeviceId, session_id: String, sealed: &str) {
        let event = {
            let mut st = lock(&self.state);
            let Some(pending) = st
                .pending
                .get_mut(&session_id)
                .filter(|p| p.viewer == viewer)
            else {
                tracing::warn!(viewer = %viewer, %session_id, "password for no pending request ignored");
                return;
            };
            let Stage::AwaitingPassword {
                ephemeral, nonce, ..
            } = &pending.stage
            else {
                tracing::warn!(viewer = %viewer, %session_id, "password not asked for ignored");
                return;
            };
            let password = crypto::open_password(
                ephemeral,
                &pending.session_key,
                &session_id,
                viewer,
                self.device,
                sealed,
            )
            .map(Password)
            .inspect_err(|err| {
                tracing::warn!(viewer = %viewer, %session_id, error = %err, "sealed password could not be opened");
            })
            .ok();
            match Agreed::new(
                ephemeral,
                *nonce,
                &pending.session_key,
                &session_id,
                self.device,
                viewer,
            ) {
                Ok(agreed) => {
                    pending.stage = Stage::PasswordReceived { agreed };
                    HostEvent::PasswordReceived {
                        session_id: session_id.clone(),
                        viewer,
                        name: pending.name.clone(),
                        fingerprint: pending.viewer_key.fingerprint(),
                        viewer_key: pending.viewer_key,
                        password,
                    }
                }
                Err(err) => {
                    tracing::warn!(viewer = %viewer, %session_id, error = %err, "key agreement failed, request dropped");
                    st.pending.remove(&session_id);
                    return;
                }
            }
        };
        tracing::info!(viewer = %viewer, %session_id, "unattended password received");
        let _ = self.events.send(event).await;
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
                    (keys, v.paused)
                }
                _ => return,
            }
        };
        let (keys, paused) = keys;
        for (index, key) in keys {
            let msg = DataMessage::Control(Control::MediaKey { index, key });
            if let Err(err) = self.send(viewer, &msg).await {
                tracing::warn!(viewer = %viewer, error = %err, "sending media key failed");
                return;
            }
        }
        if paused {
            let msg = DataMessage::Control(Control::ViewPaused { paused: true });
            if let Err(err) = self.send(viewer, &msg).await {
                tracing::warn!(viewer = %viewer, error = %err, "sending view pause failed");
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
                Some(ServerMessage::SessionRequest {
                    from,
                    session_id,
                    session_key,
                    signature,
                    identity_key,
                    name,
                    unattended,
                }) => {
                    inner
                        .on_request(from, name, session_id, &session_key, &signature, &identity_key, unattended)
                        .await;
                }
                Some(ServerMessage::SessionPassword { from, session_id, password }) => {
                    inner.on_password(from, session_id, &password).await;
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
                Some(RoomEvent::LocalTrackPublished { .. }) => {
                    inner.sync_key_index();
                }
                Some(RoomEvent::LocalTrackRepublished { previous_sid, publication, .. }) => {
                    inner.sync_key_index();
                    inner.on_republished(&previous_sid, publication.sid()).await;
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

/// Returns subscription permissions that let each of `viewers` subscribe to
/// the track `screen` and to no other track.
fn screen_permissions(viewers: &[DeviceId], screen: &TrackSid) -> Vec<ParticipantTrackPermission> {
    viewers
        .iter()
        .map(|viewer| ParticipantTrackPermission {
            participant_identity: room::identity(*viewer),
            allow_all: false,
            allowed_track_sids: vec![screen.clone()],
        })
        .collect()
}

/// Returns how the video track's mute must change after a permission update:
/// `Some(true)` to mute when the update failed (`applied` false) while a view
/// is paused (`restrictive`), `Some(false)` to unmute once an update
/// succeeded, and `None` to leave it as `muted` says.
fn mute_after_apply(applied: bool, restrictive: bool, muted: bool) -> Option<bool> {
    match (applied, muted) {
        (true, true) => Some(false),
        (false, false) if restrictive => Some(true),
        _ => None,
    }
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

/// Parses a viewer's signed per-session key and checks its signature.
///
/// `identity_key` and `session_key` are standard base64 of 32 bytes and
/// `signature` standard base64 of 64 bytes. Returns the viewer's identity key
/// and per-session key when `signature` is the identity key's signature over
/// the per-session key as viewer of `session_id`; fails with the
/// [`CryptoError`](crypto::CryptoError) of the first malformed or
/// non-verifying input otherwise.
fn verify_request(
    session_id: &str,
    session_key: &str,
    signature: &str,
    identity_key: &str,
) -> Result<(IdentityPublic, EphemeralPublic), crypto::CryptoError> {
    let identity = IdentityPublic::from_base64(identity_key)?;
    let key = EphemeralPublic::from_base64(session_key)?;
    let signature = crypto::signature_from_base64(signature)?;
    identity.verify_session(Role::Viewer, session_id, &key, &signature)?;
    Ok((identity, key))
}

/// Returns the event that asks the user about request `session_id` described by `pending`.
fn prompt_event(session_id: &str, pending: &Pending, unattended: bool) -> HostEvent {
    HostEvent::ViewerRequested {
        session_id: session_id.to_owned(),
        viewer: pending.viewer,
        name: pending.name.clone(),
        fingerprint: pending.viewer_key.fingerprint(),
        viewer_key: pending.viewer_key,
        unattended,
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

    /// Returns an empty host state with the given media and active key indices, each
    /// key filled with its index.
    fn state(media_index: u8, active_index: u8) -> State {
        State {
            pending: HashMap::new(),
            viewers: HashMap::new(),
            media_key: SessionKey::from_bytes([media_index; 32]),
            media_index,
            active_key: SessionKey::from_bytes([active_index; 32]),
            active_index,
            refused: HashMap::new(),
            all_paused: false,
        }
    }

    /// Returns the test device ID with offset `n`.
    fn id(n: u32) -> DeviceId {
        DeviceId::new(100_000_000 + n).unwrap()
    }

    /// Returns a host-side channel for session `sid` with a fixed key.
    fn channel(sid: &str) -> PeerChannel {
        PeerChannel::new(sid.into(), SessionKey::from_bytes([1; 32]), Side::Host)
    }

    /// Adds request `sid` from `viewer`, made at `at`, waiting for the host user.
    fn pending(st: &mut State, sid: &str, viewer: DeviceId, at: Instant) {
        pending_at(st, sid, viewer, at, Stage::Prompt { agreed: None });
    }

    /// Adds request `sid` from `viewer`, made at `at`, in `stage`.
    fn pending_at(st: &mut State, sid: &str, viewer: DeviceId, at: Instant, stage: Stage) {
        st.pending.insert(
            sid.into(),
            Pending {
                viewer,
                name: "pc".into(),
                viewer_key: IdentityKey::generate().public(),
                session_key: EphemeralPublic::from_bytes([5; 32]),
                requested_at: at,
                stage,
            },
        );
    }

    /// Returns the stage of a request whose password challenge went out at `sent_at`.
    fn awaiting(sent_at: Instant) -> Stage {
        Stage::AwaitingPassword {
            ephemeral: Ephemeral::generate(),
            nonce: [3; 32],
            sent_at,
        }
    }

    /// A request whose password challenge went unanswered for the challenge timeout
    /// expires, while a prompt still waiting on the host user lasts until the request
    /// timeout.
    #[test]
    fn unanswered_challenge_expires_after_challenge_timeout() {
        let mut st = state(0, 0);
        let t0 = Instant::now();
        pending_at(&mut st, "challenged", id(1), t0, awaiting(t0));
        pending_at(
            &mut st,
            "fresh",
            id(2),
            t0,
            awaiting(t0 + Duration::from_secs(10)),
        );
        pending(&mut st, "prompt", id(3), t0);
        let challenge = Duration::from_secs(30);
        let later = t0 + challenge;
        let gone = st.expire_pending(later, Duration::from_secs(60), challenge);
        assert_eq!(gone, vec![("challenged".to_owned(), id(1), true)]);
        assert!(st.pending.contains_key("fresh"));
        assert!(st.pending.contains_key("prompt"));
        let gone = st.expire_pending(
            later + Duration::from_secs(10),
            Duration::from_secs(60),
            challenge,
        );
        assert_eq!(gone, vec![("fresh".to_owned(), id(2), true)]);
        assert!(
            st.pending.contains_key("prompt"),
            "a prompt waits for the request timeout"
        );
    }

    /// The host's agreed session key matches the key the viewer derives, and a password
    /// the viewer seals to the agreed host key opens on the host.
    #[test]
    fn host_and_viewer_derive_equal_keys_through_the_challenge() {
        let (host, viewer) = (id(1), id(2));
        let (host_eph, viewer_eph) = (Ephemeral::generate(), Ephemeral::generate());
        let nonce = [4; 32];
        let agreed =
            Agreed::new(&host_eph, nonce, &viewer_eph.public(), "s1", host, viewer).unwrap();
        assert_eq!(agreed.host_key, host_eph.public());
        let shared = viewer_eph.agree(&agreed.host_key).unwrap();
        let viewer_side = crypto::derive_session_key(
            &shared,
            &viewer_eph.public(),
            &agreed.host_key,
            "s1",
            &nonce,
            host,
            viewer,
        );
        assert_eq!(agreed.key.as_bytes(), viewer_side.as_bytes());
        let sealed = crypto::seal_password(
            &viewer_eph,
            &agreed.host_key,
            "s1",
            viewer,
            host,
            "hunter22",
        )
        .unwrap();
        let opened =
            crypto::open_password(&host_eph, &viewer_eph.public(), "s1", viewer, host, &sealed)
                .unwrap();
        assert_eq!(opened, "hunter22");
    }

    /// A password exposes its text through `as_str` but not through debug output.
    #[test]
    fn password_debug_hides_text() {
        let password = Password("hunter22".into());
        assert_eq!(password.as_str(), "hunter22");
        assert!(!format!("{password:?}").contains("hunter22"));
    }

    /// A session request verifies only with a viewer-role signature for the same
    /// session by the claimed identity over a valid key.
    #[test]
    fn verify_request_accepts_only_a_viewer_signature_for_the_session() {
        let identity = IdentityKey::generate();
        let key = Ephemeral::generate().public();
        let b64 = |role| crypto::signature_to_base64(&identity.sign_session(role, "s1", &key));
        let id_b64 = identity.public().to_base64();
        let (got_identity, got_key) =
            verify_request("s1", &key.to_base64(), &b64(Role::Viewer), &id_b64).unwrap();
        assert_eq!((got_identity, got_key), (identity.public(), key));
        assert!(verify_request("s1", &key.to_base64(), &b64(Role::Host), &id_b64).is_err());
        assert!(verify_request("s2", &key.to_base64(), &b64(Role::Viewer), &id_b64).is_err());
        let other = IdentityKey::generate().public().to_base64();
        assert!(verify_request("s1", &key.to_base64(), &b64(Role::Viewer), &other).is_err());
        assert!(verify_request("s1", "AAAA", &b64(Role::Viewer), &id_b64).is_err());
    }

    /// A pending request older than the request timeout expires, while a newer one
    /// stays.
    #[test]
    fn pending_requests_expire() {
        let mut st = state(0, 0);
        let t0 = Instant::now();
        pending(&mut st, "old", id(1), t0);
        pending(&mut st, "new", id(2), t0 + Duration::from_secs(50));
        let gone = st.expire_pending(
            t0 + Duration::from_secs(61),
            Duration::from_secs(60),
            Duration::from_secs(30),
        );
        assert_eq!(gone, vec![("old".to_owned(), id(1), false)]);
        assert!(st.pending.contains_key("new"));
    }

    /// Every participant may subscribe while no view is paused; once one is,
    /// only the viewers whose view is not paused may.
    #[test]
    fn paused_viewers_lose_the_video_permission() {
        let mut st = state(0, 0);
        let now = Instant::now();
        for n in 1..=3 {
            st.admit(id(n), "s", channel("s"), now).unwrap();
        }
        assert_eq!(st.video_permissions(), None);
        st.viewers.get_mut(&id(2)).unwrap().paused = true;
        assert_eq!(st.video_permissions(), Some(vec![id(1), id(3)]));
        st.viewers.get_mut(&id(2)).unwrap().paused = false;
        assert_eq!(st.video_permissions(), None);
    }

    /// While every view is paused no viewer may subscribe, and a viewer
    /// admitted meanwhile starts paused.
    #[test]
    fn viewers_admitted_while_all_paused_start_paused() {
        let mut st = state(0, 0);
        let now = Instant::now();
        st.admit(id(1), "s", channel("s"), now).unwrap();
        st.all_paused = true;
        st.viewers.get_mut(&id(1)).unwrap().paused = true;
        st.admit(id(2), "s", channel("s"), now).unwrap();
        assert!(st.viewers[&id(2)].paused);
        assert_eq!(st.video_permissions(), Some(vec![]));
    }

    /// A failed permission update mutes the video while a view is paused, a
    /// successful one unmutes it, and nothing else changes the mute.
    #[test]
    fn video_is_muted_while_a_pause_cannot_be_enforced() {
        assert_eq!(mute_after_apply(false, true, false), Some(true));
        assert_eq!(mute_after_apply(false, true, true), None);
        assert_eq!(mute_after_apply(false, false, false), None);
        assert_eq!(mute_after_apply(false, false, true), None);
        assert_eq!(mute_after_apply(true, true, true), Some(false));
        assert_eq!(mute_after_apply(true, false, true), Some(false));
        assert_eq!(mute_after_apply(true, true, false), None);
    }

    /// Restrictive permissions name each allowed viewer with only the screen
    /// track, never every track.
    #[test]
    fn permissions_allow_only_the_screen_track() {
        let screen = TrackSid::try_from("TR_screen".to_string()).unwrap();
        let permissions = screen_permissions(&[id(1), id(2)], &screen);
        assert_eq!(permissions.len(), 2);
        for (p, viewer) in permissions.iter().zip([id(1), id(2)]) {
            assert_eq!(p.participant_identity, room::identity(viewer));
            assert!(!p.allow_all);
            assert_eq!(p.allowed_track_sids, std::slice::from_ref(&screen));
        }
    }

    /// Viewers that left, and participants that were never accepted, are not
    /// in the restrictive permissions; a paused viewer never is.
    #[test]
    fn only_accepted_unpaused_viewers_are_allowed() {
        let mut st = state(0, 0);
        let now = Instant::now();
        for n in 1..=3 {
            st.admit(id(n), "s", channel("s"), now).unwrap();
        }
        st.viewers.get_mut(&id(1)).unwrap().paused = true;
        st.viewers.remove(&id(3));
        assert_eq!(st.video_permissions(), Some(vec![id(2)]));
        st.all_paused = true;
        st.viewers.get_mut(&id(2)).unwrap().paused = true;
        assert_eq!(st.video_permissions(), Some(vec![]));
    }

    /// A viewer that is readmitted into its unkeyed slot keeps its paused view.
    #[test]
    fn readmitted_viewer_stays_paused() {
        let mut st = state(0, 0);
        let now = Instant::now();
        st.admit(id(1), "s1", channel("s1"), now).unwrap();
        st.viewers.get_mut(&id(1)).unwrap().paused = true;
        st.admit(id(1), "s2", channel("s2"), now).unwrap();
        assert!(st.viewers[&id(1)].paused);
    }

    /// Admitting a viewer that already holds a keyed slot under a new session is denied
    /// and the original session is kept.
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

    /// A viewer with an unkeyed slot is readmitted under a new session in the same
    /// slot, so the room stays full for others.
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

    /// Unkeyed slots older than the join window are freed when a new viewer is
    /// admitted, while keyed slots are kept.
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

    /// A viewer that leaves is marked as not joined and is removed only once the
    /// reconnect window has passed.
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

    /// A viewer joining with no key rotation in progress receives only the active key.
    #[test]
    fn joining_viewer_gets_active_key_only_when_settled() {
        assert_eq!(state(2, 2).join_keys(), vec![(2, [2; 32])]);
    }

    /// A viewer joining during a key rotation receives both the active and the new
    /// media key.
    #[test]
    fn joining_viewer_gets_both_keys_during_rotation() {
        assert_eq!(state(3, 2).join_keys(), vec![(2, [2; 32]), (3, [3; 32])]);
    }

    /// Frame cryptors created for newly published tracks start at key index 0 and move
    /// to the current index once the own key index is synced.
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

    /// Video published with raw or encoded input encrypts with the given active key
    /// index from the start.
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
            publish_video(&lk_room, &own, 5, input, 64, 64)
                .await
                .unwrap();
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
