//! Sealing and opening of data messages exchanged with one peer.
//!
//! The sealed plaintext of a message is a 9-byte header followed by the
//! encoded [`DataMessage`]: one byte naming the sender's side, then a
//! big-endian `u64` counter that the sender increases per topic. The receiver
//! rejects messages from its own side. On reliable topics it accepts only
//! counters above the highest one seen; on the lossy pointer topic it also
//! accepts each counter once within a window behind the highest.

use surf_rac_protocol::data::{
    DataMessage, DecodeError, MAX_CLIPBOARD_BYTES, TOPIC_CLIPBOARD, TOPIC_INPUT, TOPIC_POINTER,
};

use crate::crypto::{self, SessionKey};

/// Consecutive messages that fail to decrypt before the session ends.
pub const CRYPTO_FAILURE_LIMIT: u32 = 10;

/// Length of the side byte and counter that precede each sealed message.
const HEADER_LEN: usize = 9;

/// How many counters below the highest one seen are still accepted once.
const REPLAY_WINDOW: u64 = 64;

/// The topics in the order of the per-topic counter arrays.
const TOPICS: [&str; 3] = [TOPIC_POINTER, TOPIC_INPUT, TOPIC_CLIPBOARD];

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

/// Which end of a session a channel belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    /// The device sharing its screen.
    Host,
    /// A device watching the host.
    Viewer,
}

impl Side {
    /// Returns the header byte of messages sent by this side.
    fn byte(self) -> u8 {
        match self {
            Side::Host => 0,
            Side::Viewer => 1,
        }
    }
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

/// Counters already received on one topic.
#[derive(Default)]
struct ReplayWindow {
    /// Highest counter received so far, if any.
    highest: Option<u64>,
    /// Bit `i` is set when counter `highest - i` was received.
    seen: u64,
}

impl ReplayWindow {
    /// Records `counter` and returns whether it is accepted.
    ///
    /// With `ordered`, only counters above the highest seen are accepted;
    /// otherwise each counter within the window is accepted once.
    fn accept(&mut self, counter: u64, ordered: bool) -> bool {
        match self.highest {
            None => {
                self.highest = Some(counter);
                self.seen = 1;
                true
            }
            Some(high) if counter > high => {
                let shift = counter - high;
                self.seen = if shift >= REPLAY_WINDOW {
                    0
                } else {
                    self.seen << shift
                };
                self.seen |= 1;
                self.highest = Some(counter);
                true
            }
            Some(_) if ordered => false,
            Some(high) => {
                let age = high - counter;
                if age >= REPLAY_WINDOW || self.seen & (1 << age) != 0 {
                    return false;
                }
                self.seen |= 1 << age;
                true
            }
        }
    }
}

/// The data channel state with one peer: key, counters and failure count.
pub(crate) struct PeerChannel {
    /// Session the key belongs to.
    session_id: String,
    /// Pairwise session key.
    key: SessionKey,
    /// The side this channel sends as.
    side: Side,
    /// Next counter to send, per topic.
    next: [u64; 3],
    /// Counters received, per topic.
    received: [ReplayWindow; 3],
    /// Consecutive decryption failures.
    failures: u32,
}

impl PeerChannel {
    /// Creates the channel of `side` for `session_id` keyed with `key`.
    pub fn new(session_id: String, key: SessionKey, side: Side) -> Self {
        Self {
            session_id,
            key,
            side,
            next: [0; 3],
            received: Default::default(),
            failures: 0,
        }
    }

    /// Encodes and seals `msg` for its topic under the next counter.
    ///
    /// Clipboard items larger than [`MAX_CLIPBOARD_BYTES`] are refused.
    pub fn seal(&mut self, msg: &DataMessage) -> Result<Vec<u8>, SendError> {
        if let DataMessage::Clipboard { bytes, .. } = msg {
            if bytes.len() > MAX_CLIPBOARD_BYTES {
                return Err(SendError::ClipboardTooLarge { size: bytes.len() });
            }
        }
        let topic = msg.topic();
        let slot = topic_index(topic).expect("every message topic is known");
        let counter = self.next[slot];
        self.next[slot] += 1;
        let encoded = msg.encode();
        let mut plaintext = Vec::with_capacity(HEADER_LEN + encoded.len());
        plaintext.push(self.side.byte());
        plaintext.extend_from_slice(&counter.to_be_bytes());
        plaintext.extend_from_slice(&encoded);
        Ok(crypto::seal(&self.key, topic, &self.session_id, &plaintext))
    }

    /// Opens a packet received on `topic`.
    ///
    /// Decryption failures are counted; the [`CRYPTO_FAILURE_LIMIT`]th in a row
    /// yields [`Inbound::CryptoLimit`]. A successful decryption resets the count.
    /// Packets on unknown topics, from this channel's own side, replayed or too
    /// old, or whose message belongs to another topic are dropped.
    pub fn open(&mut self, topic: &str, sealed: &[u8]) -> Inbound {
        let Some(slot) = topic_index(topic) else {
            return Inbound::Dropped;
        };
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
        if plaintext.len() < HEADER_LEN || plaintext[0] == self.side.byte() {
            return Inbound::Dropped;
        }
        let counter = u64::from_be_bytes(plaintext[1..HEADER_LEN].try_into().expect("8 bytes"));
        if !self.received[slot].accept(counter, topic != TOPIC_POINTER) {
            return Inbound::Dropped;
        }
        match DataMessage::decode(&plaintext[HEADER_LEN..]) {
            Ok(msg) if msg.topic() == topic => Inbound::Message(msg),
            Ok(_) | Err(DecodeError::Empty | DecodeError::Malformed) => Inbound::Dropped,
            Err(DecodeError::UnknownVersion(v)) => Inbound::UnknownVersion(v),
        }
    }
}

/// Returns the counter slot of `topic`, or `None` for unknown topics.
pub(crate) fn topic_index(topic: &str) -> Option<usize> {
    TOPICS.iter().position(|t| *t == topic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use surf_rac_protocol::data::ClipboardKind;

    fn channel(side: Side) -> PeerChannel {
        PeerChannel::new("s1".into(), SessionKey::from_bytes([4; 32]), side)
    }

    fn pair() -> (PeerChannel, PeerChannel) {
        (channel(Side::Viewer), channel(Side::Host))
    }

    /// Seals a raw plaintext with the given header fields under the test key.
    fn raw(side: Side, counter: u64, topic: &str, body: &[u8]) -> Vec<u8> {
        let mut p = vec![side.byte()];
        p.extend_from_slice(&counter.to_be_bytes());
        p.extend_from_slice(body);
        crypto::seal(&SessionKey::from_bytes([4; 32]), topic, "s1", &p)
    }

    #[test]
    fn channel_round_trip() {
        let (mut tx, mut rx) = pair();
        let msg = DataMessage::Key {
            code: 30,
            down: true,
        };
        let sealed = tx.seal(&msg).unwrap();
        assert_eq!(rx.open(TOPIC_INPUT, &sealed), Inbound::Message(msg));
    }

    #[test]
    fn channel_rejects_topic_mismatch() {
        let (mut tx, mut rx) = pair();
        let msg = DataMessage::Key {
            code: 30,
            down: true,
        };
        let sealed = tx.seal(&msg).unwrap();
        assert_ne!(
            rx.open(TOPIC_POINTER, &sealed),
            Inbound::Message(msg.clone())
        );
        assert_eq!(rx.open(TOPIC_INPUT, &sealed), Inbound::Message(msg));
        let wrong = raw(
            Side::Viewer,
            0,
            TOPIC_POINTER,
            &DataMessage::Key {
                code: 1,
                down: true,
            }
            .encode(),
        );
        assert_eq!(rx.open(TOPIC_POINTER, &wrong), Inbound::Dropped);
        assert_eq!(rx.open("other/topic", &wrong), Inbound::Dropped);
    }

    #[test]
    fn replayed_message_is_dropped() {
        let (mut tx, mut rx) = pair();
        let sealed = tx
            .seal(&DataMessage::Key {
                code: 30,
                down: true,
            })
            .unwrap();
        assert!(matches!(rx.open(TOPIC_INPUT, &sealed), Inbound::Message(_)));
        assert_eq!(rx.open(TOPIC_INPUT, &sealed), Inbound::Dropped);
        let next = tx
            .seal(&DataMessage::Key {
                code: 30,
                down: false,
            })
            .unwrap();
        assert!(matches!(rx.open(TOPIC_INPUT, &next), Inbound::Message(_)));
    }

    #[test]
    fn reflected_message_is_dropped() {
        let (mut viewer, _) = pair();
        let mut other_viewer = channel(Side::Viewer);
        let sealed = viewer
            .seal(&DataMessage::Key {
                code: 30,
                down: true,
            })
            .unwrap();
        assert_eq!(other_viewer.open(TOPIC_INPUT, &sealed), Inbound::Dropped);
    }

    #[test]
    fn lossy_reordering_within_window_is_accepted() {
        let (mut tx, mut rx) = pair();
        let moves: Vec<_> = (0..5)
            .map(|i| {
                tx.seal(&DataMessage::PointerMove {
                    x: i,
                    y: 0,
                    monitor: 0,
                })
                .unwrap()
            })
            .collect();
        for i in [1, 0, 4, 2] {
            assert!(
                matches!(rx.open(TOPIC_POINTER, &moves[i]), Inbound::Message(_)),
                "{i}"
            );
        }
        assert_eq!(rx.open(TOPIC_POINTER, &moves[2]), Inbound::Dropped);
        assert!(matches!(
            rx.open(TOPIC_POINTER, &moves[3]),
            Inbound::Message(_)
        ));
        let late = raw(
            Side::Viewer,
            0,
            TOPIC_POINTER,
            &DataMessage::PointerMove {
                x: 0,
                y: 0,
                monitor: 0,
            }
            .encode(),
        );
        let far = raw(
            Side::Viewer,
            200,
            TOPIC_POINTER,
            &DataMessage::PointerMove {
                x: 0,
                y: 0,
                monitor: 0,
            }
            .encode(),
        );
        assert!(matches!(rx.open(TOPIC_POINTER, &far), Inbound::Message(_)));
        assert_eq!(rx.open(TOPIC_POINTER, &late), Inbound::Dropped);
    }

    #[test]
    fn reliable_topics_reject_reordering() {
        let (mut tx, mut rx) = pair();
        let first = tx
            .seal(&DataMessage::Key {
                code: 30,
                down: true,
            })
            .unwrap();
        let second = tx
            .seal(&DataMessage::Key {
                code: 30,
                down: false,
            })
            .unwrap();
        assert!(matches!(rx.open(TOPIC_INPUT, &second), Inbound::Message(_)));
        assert_eq!(rx.open(TOPIC_INPUT, &first), Inbound::Dropped);
        let c1 = tx
            .seal(&DataMessage::Clipboard {
                kind: ClipboardKind::Text,
                bytes: b"a".to_vec(),
            })
            .unwrap();
        let c2 = tx
            .seal(&DataMessage::Clipboard {
                kind: ClipboardKind::Text,
                bytes: b"b".to_vec(),
            })
            .unwrap();
        assert!(matches!(rx.open(TOPIC_CLIPBOARD, &c2), Inbound::Message(_)));
        assert_eq!(rx.open(TOPIC_CLIPBOARD, &c1), Inbound::Dropped);
    }

    #[test]
    fn topics_count_independently() {
        let (mut tx, mut rx) = pair();
        let key = tx
            .seal(&DataMessage::Key {
                code: 1,
                down: true,
            })
            .unwrap();
        let clip = tx
            .seal(&DataMessage::Clipboard {
                kind: ClipboardKind::Text,
                bytes: b"x".to_vec(),
            })
            .unwrap();
        assert!(matches!(
            rx.open(TOPIC_CLIPBOARD, &clip),
            Inbound::Message(_)
        ));
        assert!(matches!(rx.open(TOPIC_INPUT, &key), Inbound::Message(_)));
    }

    #[test]
    fn channel_crypto_limit_after_ten() {
        let (mut tx, mut rx) = pair();
        for _ in 0..CRYPTO_FAILURE_LIMIT - 1 {
            assert_eq!(
                rx.open(TOPIC_INPUT, b"garbage-garbage-garbage"),
                Inbound::Dropped
            );
        }
        let good = tx.seal(&DataMessage::Wheel { dx: 1, dy: 1 }).unwrap();
        assert!(matches!(rx.open(TOPIC_INPUT, &good), Inbound::Message(_)));
        for _ in 0..CRYPTO_FAILURE_LIMIT - 1 {
            assert_eq!(
                rx.open(TOPIC_INPUT, b"garbage-garbage-garbage"),
                Inbound::Dropped
            );
        }
        assert_eq!(
            rx.open(TOPIC_INPUT, b"garbage-garbage-garbage"),
            Inbound::CryptoLimit
        );
    }

    #[test]
    fn channel_unknown_version() {
        let (_, mut rx) = pair();
        let sealed = raw(Side::Viewer, 0, TOPIC_INPUT, &[99, 1, 2]);
        assert_eq!(rx.open(TOPIC_INPUT, &sealed), Inbound::UnknownVersion(99));
    }

    #[test]
    fn clipboard_over_limit_refused() {
        let (mut tx, mut rx) = pair();
        let big = DataMessage::Clipboard {
            kind: ClipboardKind::Image,
            bytes: vec![0; MAX_CLIPBOARD_BYTES + 1],
        };
        assert_eq!(
            tx.seal(&big),
            Err(SendError::ClipboardTooLarge {
                size: MAX_CLIPBOARD_BYTES + 1
            })
        );
        let max = DataMessage::Clipboard {
            kind: ClipboardKind::Image,
            bytes: vec![0; MAX_CLIPBOARD_BYTES],
        };
        let sealed = tx.seal(&max).unwrap();
        assert!(matches!(
            rx.open(TOPIC_CLIPBOARD, &sealed),
            Inbound::Message(_)
        ));
    }
}
