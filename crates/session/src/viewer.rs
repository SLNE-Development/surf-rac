//! The viewer side of a session: requests access to a host, joins its room
//! with the host-issued token, receives the screen and exchanges data.

use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
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

use crate::channel::{Inbound, PeerChannel, SendError, Side, topic_index};
use crate::config::{EndReason, SessionConfig};
use crate::crypto::{
    self, Ephemeral, EphemeralPublic, IdentityKey, IdentityPublic, Role, SessionKey,
};
use crate::pinning::{KeyChanged, KnownKeys};
use crate::reconnect::ReconnectWatch;
use crate::room::{self, Incoming, JoinError};
use crate::signaling::{SignalingClient, SignalingError};
use crate::video::{self, Frame};

/// Number of media key indices the frame-decryption key ring holds.
const KEY_RING_SIZE: u8 = 16;

/// Viewer events buffered for the application; frames beyond this are dropped.
const EVENT_CAPACITY: usize = 64;

/// Optional inputs of a session request.
#[derive(Clone, Default)]
pub struct RequestOptions {
    /// Unattended password the viewer authenticates with; when set, the
    /// request is marked unattended and the password is sent once the host
    /// offers its signed per-session key.
    pub password: Option<String>,
}

impl std::fmt::Debug for RequestOptions {
    /// Writes the options without the password.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestOptions")
            .field("password", &self.password.as_ref().map(|_| ".."))
            .finish()
    }
}

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
    /// Serialize sealing and sending per topic so each topic's counters leave in order.
    send_locks: [tokio::sync::Mutex<()>; 3],
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
        identity: Arc<IdentityKey>,
        known: Arc<Mutex<KnownKeys>>,
        host: DeviceId,
        config: SessionConfig,
    ) -> Result<(ViewerSession, mpsc::Receiver<ViewerEvent>), RequestError> {
        Self::request_with(
            signaling,
            identity,
            known,
            host,
            RequestOptions::default(),
            config,
        )
        .await
    }

    /// Requests a session with `host` like [`ViewerSession::request`], with the
    /// inputs in `options`.
    ///
    /// The request carries a fresh per-session key signed with `identity`. The
    /// host's per-session key must carry a valid signature by the host's
    /// identity key, which is pinned on first contact and must match the pin
    /// afterwards.
    ///
    /// With a password in `options`, the host may answer with a password
    /// challenge; the password is then sealed to the host's verified
    /// per-session key and sent. A wrong password leaves the decision to the
    /// host's user. A challenge with an invalid signature fails the request
    /// with [`RequestError::Denied`], one from a host whose identity key
    /// differs from the pin with [`RequestError::KeyChanged`].
    pub async fn request_with(
        signaling: SignalingClient,
        identity: Arc<IdentityKey>,
        known: Arc<Mutex<KnownKeys>>,
        host: DeviceId,
        options: RequestOptions,
        config: SessionConfig,
    ) -> Result<(ViewerSession, mpsc::Receiver<ViewerEvent>), RequestError> {
        let viewer = signaling.device_id();
        let session_id = new_session_id();
        let ephemeral = Ephemeral::generate();
        let signature = identity.sign_session(Role::Viewer, &session_id, &ephemeral.public());
        let mut sig_events = signaling.subscribe();
        signaling
            .send(ClientMessage::SessionRequest {
                to: host,
                session_id: session_id.clone(),
                session_key: ephemeral.public().to_base64(),
                signature: crypto::signature_to_base64(&signature),
                unattended: options.password.is_some(),
            })
            .await?;
        tracing::info!(%host, %session_id, "session requested");

        let (channel_key, url, token) = tokio::time::timeout(config.request_timeout, async {
            let mut key = None;
            let mut token = None;
            let mut password = options.password.as_deref();
            loop {
                match sig_events.recv().await {
                    None => return Err(RequestError::Signaling(SignalingError::Closed)),
                    Some(ServerMessage::Error {
                        code: WsErrorCode::TargetOffline,
                        ..
                    }) if key.is_none() => {
                        return Err(RequestError::Offline);
                    }
                    Some(ServerMessage::PasswordChallenge {
                        from,
                        session_id: sid,
                        session_key,
                        signature,
                        identity_key,
                        ..
                    }) if from == host && sid == session_id => {
                        let Some(pw) = password.take() else {
                            tracing::warn!(%host, %session_id, "unexpected password challenge ignored");
                            continue;
                        };
                        let host_key = verified_host_key(
                            Some(&identity_key),
                            Some(&session_key),
                            Some(&signature),
                            &known,
                            &session_id,
                            host,
                        )?;
                        let sealed =
                            crypto::seal_password(&ephemeral, &host_key, &session_id, viewer, host, pw)
                                .map_err(|_| RequestError::Denied)?;
                        signaling
                            .send(ClientMessage::SessionPassword {
                                to: host,
                                session_id: session_id.clone(),
                                password: sealed,
                            })
                            .await?;
                        tracing::info!(%host, %session_id, "unattended password sent");
                    }
                    Some(ServerMessage::SessionResponse {
                        from,
                        session_id: sid,
                        accepted,
                        reason,
                        session_key,
                        signature,
                        host_nonce,
                        identity_key,
                    }) if from == host && sid == session_id => {
                        if !accepted {
                            return Err(match reason {
                                Some(DenyReason::RoomFull) => RequestError::RoomFull,
                                _ => RequestError::Denied,
                            });
                        }
                        let accepted = AcceptedKeys {
                            identity_key: identity_key.as_deref(),
                            session_key: session_key.as_deref(),
                            signature: signature.as_deref(),
                            host_nonce: host_nonce.as_deref(),
                        };
                        key =
                            Some(accepted.derive(&ephemeral, &known, &session_id, host, viewer)?);
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
            send_locks: Default::default(),
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
        let slot = topic_index(msg.topic()).expect("every message topic is known");
        let _order = self.send_locks[slot].lock().await;
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
            Inbound::Message(DataMessage::Control(Control::MediaKey { index, .. }))
                if index >= KEY_RING_SIZE =>
            {
                tracing::warn!(host = %self.host, index, "media key index outside the key ring ignored");
                (None, None)
            }
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
                    host_presence(false, &mut watch, &events);
                    continue;
                }
                Some(RoomEvent::ParticipantActive(p)) if p.identity().0 == host_identity => {
                    host_presence(true, &mut watch, &events);
                    continue;
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

/// Records that the host left the room (`present` false) or came back (`present` true).
///
/// A host that leaves is treated like a dropped connection: the reconnect
/// window starts and the session ends only if the host does not return in time.
fn host_presence(
    present: bool,
    watch: &mut ReconnectWatch,
    events: &mpsc::UnboundedSender<ViewerEvent>,
) {
    if present {
        if watch.is_reconnecting() {
            watch.reconnected();
            let _ = events.send(ViewerEvent::Connected);
        }
    } else {
        watch.reconnecting();
        let _ = events.send(ViewerEvent::Reconnecting);
    }
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

/// The key material of an accepted session response, as received.
struct AcceptedKeys<'a> {
    /// The host's identity key as attested by the server, standard base64.
    identity_key: Option<&'a str>,
    /// The host's per-session key, standard base64.
    session_key: Option<&'a str>,
    /// The host's signature over its per-session key, standard base64.
    signature: Option<&'a str>,
    /// The host nonce of the session, standard base64 of 32 bytes.
    host_nonce: Option<&'a str>,
}

/// Verifies the host's signed per-session key and returns it.
///
/// `session_key` must be signed by `identity_key`, the host's identity key as
/// attested by the server, as the host's key for `session_id`; the identity
/// key is then checked against the pin in `known`, which pins it on first
/// contact. Fails with [`RequestError::Denied`] when a field is missing or
/// malformed or the signature does not verify, and with
/// [`RequestError::KeyChanged`] when the identity key differs from the pinned
/// one.
fn verified_host_key(
    identity_key: Option<&str>,
    session_key: Option<&str>,
    signature: Option<&str>,
    known: &Mutex<KnownKeys>,
    session_id: &str,
    host: DeviceId,
) -> Result<EphemeralPublic, RequestError> {
    let identity_key = identity_key
        .and_then(|k| IdentityPublic::from_base64(k).ok())
        .ok_or(RequestError::Denied)?;
    let host_key = session_key
        .and_then(|k| EphemeralPublic::from_base64(k).ok())
        .ok_or(RequestError::Denied)?;
    let signature = signature
        .and_then(|s| crypto::signature_from_base64(s).ok())
        .ok_or(RequestError::Denied)?;
    if let Err(err) = identity_key.verify_session(Role::Host, session_id, &host_key, &signature) {
        tracing::warn!(%host, %session_id, error = %err, "host per-session key does not verify");
        return Err(RequestError::Denied);
    }
    lock(known).check(host, &identity_key)?;
    Ok(host_key)
}

impl AcceptedKeys<'_> {
    /// Verifies the host's signed per-session key and derives the session key.
    ///
    /// The key is verified with [`verified_host_key`]. `ephemeral` is this
    /// viewer's per-session key pair. Fails like [`verified_host_key`], and
    /// with [`RequestError::Denied`] when the host nonce is missing or
    /// malformed or the key agreement fails.
    fn derive(
        &self,
        ephemeral: &Ephemeral,
        known: &Mutex<KnownKeys>,
        session_id: &str,
        host: DeviceId,
        viewer: DeviceId,
    ) -> Result<SessionKey, RequestError> {
        let host_key = verified_host_key(
            self.identity_key,
            self.session_key,
            self.signature,
            known,
            session_id,
            host,
        )?;
        let nonce: [u8; 32] = self
            .host_nonce
            .and_then(|n| STANDARD.decode(n).ok())
            .and_then(|n| n.try_into().ok())
            .ok_or(RequestError::Denied)?;
        let shared = ephemeral
            .agree(&host_key)
            .map_err(|_| RequestError::Denied)?;
        Ok(crypto::derive_session_key(
            &shared,
            &ephemeral.public(),
            &host_key,
            session_id,
            &nonce,
            host,
            viewer,
        ))
    }
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
    use crate::testutil::{env, mint_token, room_name, unix_now};

    #[test]
    fn accepted_keys_verify_host_signature_pin_and_derive_shared_key() {
        let (host, viewer) = (
            DeviceId::new(123_456_789).unwrap(),
            DeviceId::new(223_456_789).unwrap(),
        );
        let host_identity = IdentityKey::generate();
        let (host_eph, viewer_eph) = (Ephemeral::generate(), Ephemeral::generate());
        let identity_b64 = host_identity.public().to_base64();
        let key_b64 = host_eph.public().to_base64();
        let nonce_b64 = STANDARD.encode([9; 32]);
        let sig = |role| {
            crypto::signature_to_base64(&host_identity.sign_session(role, "s1", &host_eph.public()))
        };
        let (host_sig, viewer_sig) = (sig(Role::Host), sig(Role::Viewer));
        let known = Mutex::new(KnownKeys::default());
        let keys = |signature: &str| {
            AcceptedKeys {
                identity_key: Some(identity_b64.as_str()),
                session_key: Some(key_b64.as_str()),
                signature: Some(signature),
                host_nonce: Some(nonce_b64.as_str()),
            }
            .derive(&viewer_eph, &known, "s1", host, viewer)
        };

        assert_eq!(keys(&viewer_sig).unwrap_err(), RequestError::Denied);
        assert!(
            lock(&known).get(host).is_none(),
            "a bad signature pins nothing"
        );

        let derived = keys(&host_sig).unwrap();
        let shared = host_eph.agree(&viewer_eph.public()).unwrap();
        let host_side = crypto::derive_session_key(
            &shared,
            &viewer_eph.public(),
            &host_eph.public(),
            "s1",
            &[9; 32],
            host,
            viewer,
        );
        assert_eq!(derived.as_bytes(), host_side.as_bytes());
        assert_eq!(lock(&known).get(host), Some(&host_identity.public()));

        lock(&known).trust_key(host, IdentityKey::generate().public());
        assert!(matches!(keys(&host_sig), Err(RequestError::KeyChanged(_))));
    }

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
            send_locks: Default::default(),
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

    #[tokio::test(start_paused = true)]
    async fn host_that_drops_out_counts_as_reconnecting() {
        let mut watch = ReconnectWatch::new(Duration::from_secs(30));
        let (tx, mut rx) = mpsc::unbounded_channel();
        host_presence(false, &mut watch, &tx);
        assert!(matches!(rx.try_recv(), Ok(ViewerEvent::Reconnecting)));
        assert!(
            tokio::time::timeout(Duration::from_secs(29), watch.expired())
                .await
                .is_err()
        );
        host_presence(true, &mut watch, &tx);
        assert!(matches!(rx.try_recv(), Ok(ViewerEvent::Connected)));
        assert!(
            tokio::time::timeout(Duration::from_secs(60), watch.expired())
                .await
                .is_err()
        );
        host_presence(false, &mut watch, &tx);
        assert!(
            tokio::time::timeout(Duration::from_secs(31), watch.expired())
                .await
                .is_ok()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn media_key_outside_key_ring_is_ignored() {
        let (inner, _tx, _events) = loop_on_simulated_events(Duration::from_secs(30)).await;
        let mut host = PeerChannel::new("s1".into(), SessionKey::from_bytes([1; 32]), Side::Host);
        let bad = host
            .seal(&DataMessage::Control(Control::MediaKey {
                index: 16,
                key: [4; 32],
            }))
            .unwrap();
        let incoming = Incoming {
            from: "123456789".into(),
            topic: surf_rac_protocol::data::TOPIC_INPUT.into(),
            payload: bad,
        };
        assert!(matches!(inner.on_data(incoming), (None, None)));
        assert_eq!(*lock(&inner.media_index), None);
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
