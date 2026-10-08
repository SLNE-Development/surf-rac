//! Joining a LiveKit room with frame encryption and moving sealed data through it.

use futures_util::StreamExt;
use livekit::e2ee::key_provider::{KeyProvider, KeyProviderOptions};
use livekit::e2ee::{E2eeOptions, EncryptionType};
use livekit::prelude::*;
use livekit::webrtc::prelude::IceTransportsType;
use livekit::{ByteStreamReader, StreamByteOptions};
use surf_rac_protocol::DeviceId;
use surf_rac_protocol::data::{MAX_CLIPBOARD_BYTES, TOPIC_CLIPBOARD};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::channel::SendError;

/// Largest sealed clipboard stream accepted: the item limit plus sealing overhead.
const MAX_CLIPBOARD_STREAM_BYTES: usize = MAX_CLIPBOARD_BYTES + 1024;

/// Why joining a room failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JoinError {
    /// LiveKit refused the token.
    Rejected,
    /// LiveKit could not be reached or the connection could not be set up.
    Unavailable(String),
}

/// A sealed payload received from a participant.
#[derive(Debug)]
pub(crate) struct Incoming {
    /// The sending participant's identity.
    pub from: String,
    /// The topic it arrived on.
    pub topic: String,
    /// The sealed bytes.
    pub payload: Vec<u8>,
}

/// Creates a per-participant frame-encryption key provider.
pub(crate) fn key_provider() -> KeyProvider {
    KeyProvider::new(KeyProviderOptions::default())
}

/// Returns the LiveKit identity of `device`.
pub(crate) fn identity(device: DeviceId) -> ParticipantIdentity {
    device.to_string().into()
}

/// Joins the room `token` grants at `url`, encrypting media with keys from `keys`.
///
/// Data channels are not encrypted by LiveKit; data is sealed by the caller.
#[allow(deprecated)]
pub(crate) async fn connect(
    url: &str,
    token: &str,
    keys: &KeyProvider,
    force_relay: bool,
) -> Result<(Room, UnboundedReceiver<RoomEvent>), JoinError> {
    let mut options = RoomOptions::default();
    options.e2ee = Some(E2eeOptions {
        encryption_type: EncryptionType::Gcm,
        key_provider: keys.clone(),
    });
    options.join_retries = 1;
    if force_relay {
        options.rtc_config.ice_transport_type = IceTransportsType::Relay;
    }
    let (room, events) = Room::connect(url, token, options)
        .await
        .map_err(classify)?;
    room.e2ee_manager().set_enabled(true);
    Ok((room, events))
}

/// Maps a LiveKit join failure to a [`JoinError`].
///
/// LiveKit reports refused tokens as HTTP 401 or 403 from its signaling
/// endpoint; every other failure counts as LiveKit being unavailable.
fn classify(err: RoomError) -> JoinError {
    let text = err.to_string();
    if text.contains("401") || text.contains("403") {
        JoinError::Rejected
    } else {
        JoinError::Unavailable(text)
    }
}

/// Sends `sealed` on `topic` to the participant `to`.
///
/// Clipboard payloads go as a byte stream; other topics as one data packet,
/// reliable unless `reliable` is false.
pub(crate) async fn send(
    room: &Room,
    to: DeviceId,
    topic: &str,
    reliable: bool,
    sealed: Vec<u8>,
) -> Result<(), SendError> {
    let participant = room.local_participant();
    if topic == TOPIC_CLIPBOARD {
        let options = StreamByteOptions {
            destination_identities: vec![identity(to)],
            ..StreamByteOptions::new_with_topic(topic)
        };
        participant
            .send_bytes(&sealed, options)
            .await
            .map(|_| ())
            .map_err(|e| SendError::Transport(e.to_string()))
    } else {
        participant
            .publish_data(DataPacket {
                payload: sealed,
                topic: Some(topic.to_owned()),
                reliable,
                destination_identities: vec![identity(to)],
            })
            .await
            .map_err(|e| SendError::Transport(e.to_string()))
    }
}

/// Reads a clipboard byte stream from `from` in the background and forwards it to `out`.
///
/// Streams on other topics, and streams longer than the clipboard limit, are discarded.
pub(crate) fn read_clipboard_stream(
    reader: ByteStreamReader,
    topic: String,
    from: String,
    out: UnboundedSender<Incoming>,
) {
    if topic != TOPIC_CLIPBOARD {
        return;
    }
    tokio::spawn(async move {
        let mut reader = reader;
        let mut payload = Vec::new();
        while let Some(chunk) = reader.next().await {
            let Ok(chunk) = chunk else { return };
            if payload.len() + chunk.len() > MAX_CLIPBOARD_STREAM_BYTES {
                tracing::warn!(from = %from, "clipboard stream over the size limit dropped");
                return;
            }
            payload.extend_from_slice(&chunk);
        }
        let _ = out.send(Incoming {
            from,
            topic,
            payload,
        });
    });
}
