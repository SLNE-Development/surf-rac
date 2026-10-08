//! Sealing and opening of data messages exchanged with one peer.

use surf_rac_protocol::data::{DataMessage, DecodeError, MAX_CLIPBOARD_BYTES};

use crate::crypto::{self, SessionKey};

/// Consecutive messages that fail to decrypt before the session ends.
pub const CRYPTO_FAILURE_LIMIT: u32 = 10;

/// Why a data message could not be sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// A clipboard item exceeds the size limit; it is never sent.
    #[error("clipboard item of {size} bytes exceeds the limit")]
    ClipboardTooLarge {
        /// Size of the refused item in bytes.
        size: usize,
    },
    /// There is no connected peer to send to.
    #[error("not connected")]
    NotConnected,
    /// The transport failed to send.
    #[error("transport error: {0}")]
    Transport(String),
}

/// Result of opening one received data packet.
#[derive(Debug, PartialEq)]
pub(crate) enum Inbound {
    /// A valid message.
    Message(DataMessage),
    /// The packet was discarded.
    Dropped,
    /// The packet carried a message of an unknown protocol version.
    UnknownVersion(u8),
    /// Too many consecutive packets failed to decrypt; the session must end.
    CryptoLimit,
}

/// The data channel state with one peer: its key and failure counter.
pub(crate) struct PeerChannel {
    /// Session the key belongs to.
    session_id: String,
    /// Pairwise session key.
    key: SessionKey,
    /// Consecutive decryption failures.
    failures: u32,
}

impl PeerChannel {
    /// Creates the channel for `session_id` keyed with `key`.
    pub fn new(session_id: String, key: SessionKey) -> Self {
        Self {
            session_id,
            key,
            failures: 0,
        }
    }

    /// Encodes and seals `msg` for its topic.
    ///
    /// Clipboard items larger than [`MAX_CLIPBOARD_BYTES`] are refused.
    pub fn seal(&self, msg: &DataMessage) -> Result<Vec<u8>, SendError> {
        if let DataMessage::Clipboard { bytes, .. } = msg {
            if bytes.len() > MAX_CLIPBOARD_BYTES {
                return Err(SendError::ClipboardTooLarge { size: bytes.len() });
            }
        }
        Ok(crypto::seal(
            &self.key,
            msg.topic(),
            &self.session_id,
            &msg.encode(),
        ))
    }

    /// Opens a packet received on `topic`.
    ///
    /// Decryption failures are counted; the [`CRYPTO_FAILURE_LIMIT`]th in a row
    /// yields [`Inbound::CryptoLimit`]. A successful decryption resets the count.
    /// Messages whose topic differs from `topic` are dropped.
    pub fn open(&mut self, topic: &str, sealed: &[u8]) -> Inbound {
        let plaintext = match crypto::open(&self.key, topic, &self.session_id, sealed) {
            Ok(p) => p,
            Err(_) => {
                self.failures += 1;
                return if self.failures >= CRYPTO_FAILURE_LIMIT {
                    Inbound::CryptoLimit
                } else {
                    Inbound::Dropped
                };
            }
        };
        self.failures = 0;
        match DataMessage::decode(&plaintext) {
            Ok(msg) if msg.topic() == topic => Inbound::Message(msg),
            Ok(_) | Err(DecodeError::Empty | DecodeError::Malformed) => Inbound::Dropped,
            Err(DecodeError::UnknownVersion(v)) => Inbound::UnknownVersion(v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use surf_rac_protocol::data::{ClipboardKind, TOPIC_CLIPBOARD, TOPIC_INPUT, TOPIC_POINTER};

    fn channel() -> PeerChannel {
        PeerChannel::new("s1".into(), SessionKey::from_bytes([4; 32]))
    }

    #[test]
    fn channel_round_trip() {
        let (tx, mut rx) = (channel(), channel());
        let msg = DataMessage::Key { code: 30, down: true };
        let sealed = tx.seal(&msg).unwrap();
        assert_eq!(rx.open(TOPIC_INPUT, &sealed), Inbound::Message(msg));
    }

    #[test]
    fn channel_rejects_topic_mismatch() {
        let (tx, mut rx) = (channel(), channel());
        let msg = DataMessage::Key { code: 30, down: true };
        let sealed = tx.seal(&msg).unwrap();
        assert_ne!(rx.open(TOPIC_POINTER, &sealed), Inbound::Message(msg.clone()));
        assert_eq!(rx.open(TOPIC_INPUT, &sealed), Inbound::Message(msg));
        let inner = crypto::seal(&rx.key, TOPIC_POINTER, "s1", &DataMessage::Key { code: 1, down: true }.encode());
        assert_eq!(rx.open(TOPIC_POINTER, &inner), Inbound::Dropped);
    }

    #[test]
    fn channel_crypto_limit_after_ten() {
        let mut rx = channel();
        for _ in 0..CRYPTO_FAILURE_LIMIT - 1 {
            assert_eq!(rx.open(TOPIC_INPUT, b"garbage-garbage-garbage"), Inbound::Dropped);
        }
        let good = channel().seal(&DataMessage::Wheel { dx: 1, dy: 1 }).unwrap();
        assert!(matches!(rx.open(TOPIC_INPUT, &good), Inbound::Message(_)));
        for _ in 0..CRYPTO_FAILURE_LIMIT - 1 {
            assert_eq!(rx.open(TOPIC_INPUT, b"garbage-garbage-garbage"), Inbound::Dropped);
        }
        assert_eq!(rx.open(TOPIC_INPUT, b"garbage-garbage-garbage"), Inbound::CryptoLimit);
    }

    #[test]
    fn channel_unknown_version() {
        let mut rx = channel();
        let sealed = crypto::seal(&rx.key, TOPIC_INPUT, "s1", &[99, 1, 2]);
        assert_eq!(rx.open(TOPIC_INPUT, &sealed), Inbound::UnknownVersion(99));
    }

    #[test]
    fn clipboard_over_limit_refused() {
        let tx = channel();
        let big = DataMessage::Clipboard { kind: ClipboardKind::Image, bytes: vec![0; MAX_CLIPBOARD_BYTES + 1] };
        assert_eq!(tx.seal(&big), Err(SendError::ClipboardTooLarge { size: MAX_CLIPBOARD_BYTES + 1 }));
        let max = DataMessage::Clipboard { kind: ClipboardKind::Image, bytes: vec![0; MAX_CLIPBOARD_BYTES] };
        let sealed = tx.seal(&max).unwrap();
        assert!(matches!(channel().open(TOPIC_CLIPBOARD, &sealed), Inbound::Message(_)));
    }
}
