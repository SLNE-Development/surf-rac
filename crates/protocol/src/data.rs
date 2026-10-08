//! Data messages exchanged between host and viewer inside a session.
//!
//! A message is encoded as one version byte followed by its postcard
//! serialization. Each message belongs to one topic: pointer motion travels
//! lossy, everything else reliable, clipboard items on their own topic.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Version byte that starts every encoded data message.
pub const DATA_VERSION: u8 = 1;

/// Topic of lossy pointer-motion messages.
pub const TOPIC_POINTER: &str = "surf-rac/pointer";

/// Topic of reliable input and control messages.
pub const TOPIC_INPUT: &str = "surf-rac/input";

/// Topic of reliable clipboard messages.
pub const TOPIC_CLIPBOARD: &str = "surf-rac/clipboard";

/// Largest clipboard item, in bytes, that may be sent.
pub const MAX_CLIPBOARD_BYTES: usize = 8 * 1024 * 1024;

/// A message on one of the session's data topics.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum DataMessage {
    /// Absolute pointer position on a monitor.
    PointerMove {
        /// Horizontal position in monitor pixels.
        x: i32,
        /// Vertical position in monitor pixels.
        y: i32,
        /// Index of the monitor the position refers to.
        monitor: u8,
    },
    /// A pointer button was pressed or released.
    PointerButton {
        /// Which button.
        button: MouseButton,
        /// True when pressed, false when released.
        down: bool,
    },
    /// Scroll wheel movement.
    Wheel {
        /// Horizontal scroll amount.
        dx: i32,
        /// Vertical scroll amount.
        dy: i32,
    },
    /// A key was pressed or released.
    Key {
        /// Platform-independent key code.
        code: u32,
        /// True when pressed, false when released.
        down: bool,
    },
    /// Session control.
    Control(Control),
    /// A clipboard item.
    Clipboard {
        /// What the bytes hold.
        kind: ClipboardKind,
        /// The clipboard contents.
        bytes: Vec<u8>,
    },
}

/// A pointer button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseButton {
    /// Primary button.
    Left,
    /// Secondary button.
    Right,
    /// Wheel button.
    Middle,
    /// Back side button.
    Back,
    /// Forward side button.
    Forward,
}

/// Session control messages.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Control {
    /// The host's media encryption key at a key index.
    MediaKey {
        /// Key index in the frame-encryption key ring.
        index: u8,
        /// The key material.
        key: [u8; 32],
    },
    /// The sender ends the session.
    Hangup,
}

/// Kind of a clipboard item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClipboardKind {
    /// UTF-8 text.
    Text,
    /// An encoded image.
    Image,
}

impl fmt::Debug for DataMessage {
    /// Writes the message with clipboard contents replaced by their length.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataMessage::PointerMove { x, y, monitor } => f
                .debug_struct("PointerMove")
                .field("x", x)
                .field("y", y)
                .field("monitor", monitor)
                .finish(),
            DataMessage::PointerButton { button, down } => f
                .debug_struct("PointerButton")
                .field("button", button)
                .field("down", down)
                .finish(),
            DataMessage::Wheel { dx, dy } => {
                f.debug_struct("Wheel").field("dx", dx).field("dy", dy).finish()
            }
            DataMessage::Key { code, down } => {
                f.debug_struct("Key").field("code", code).field("down", down).finish()
            }
            DataMessage::Control(c) => f.debug_tuple("Control").field(c).finish(),
            DataMessage::Clipboard { kind, bytes } => f
                .debug_struct("Clipboard")
                .field("kind", kind)
                .field("bytes", &format_args!("{} bytes", bytes.len()))
                .finish(),
        }
    }
}

impl fmt::Debug for Control {
    /// Writes the control message with key material omitted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Control::MediaKey { index, .. } => f
                .debug_struct("MediaKey")
                .field("index", index)
                .finish_non_exhaustive(),
            Control::Hangup => f.write_str("Hangup"),
        }
    }
}

/// Why bytes could not be decoded into a [`DataMessage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// There were no bytes.
    Empty,
    /// The version byte is not [`DATA_VERSION`].
    UnknownVersion(u8),
    /// The bytes after the version byte are not a valid message.
    Malformed,
}

impl fmt::Display for DecodeError {
    /// Writes a short description of the decoding failure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Empty => f.write_str("empty data message"),
            DecodeError::UnknownVersion(v) => write!(f, "unknown data message version {v}"),
            DecodeError::Malformed => f.write_str("malformed data message"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl DataMessage {
    /// Returns the topic this message travels on.
    pub fn topic(&self) -> &'static str {
        match self {
            DataMessage::PointerMove { .. } => TOPIC_POINTER,
            DataMessage::Clipboard { .. } => TOPIC_CLIPBOARD,
            _ => TOPIC_INPUT,
        }
    }

    /// Returns whether this message needs reliable, ordered delivery.
    pub fn is_reliable(&self) -> bool {
        !matches!(self, DataMessage::PointerMove { .. })
    }

    /// Encodes the message as the version byte followed by its postcard bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![DATA_VERSION];
        postcard::to_io(self, &mut out).expect("writing to a Vec cannot fail");
        out
    }

    /// Decodes a message produced by [`DataMessage::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (&version, body) = bytes.split_first().ok_or(DecodeError::Empty)?;
        if version != DATA_VERSION {
            return Err(DecodeError::UnknownVersion(version));
        }
        match postcard::take_from_bytes(body) {
            Ok((msg, [])) => Ok(msg),
            _ => Err(DecodeError::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_every_variant() {
        for m in [
            DataMessage::PointerMove { x: -5, y: 7, monitor: 1 },
            DataMessage::PointerButton { button: MouseButton::Right, down: true },
            DataMessage::Wheel { dx: 0, dy: -120 },
            DataMessage::Key { code: 0x1E, down: false },
            DataMessage::Control(Control::MediaKey { index: 3, key: [9; 32] }),
            DataMessage::Control(Control::Hangup),
            DataMessage::Clipboard { kind: ClipboardKind::Text, bytes: b"hi".to_vec() },
        ] {
            let bytes = m.encode();
            assert_eq!(bytes[0], DATA_VERSION);
            assert_eq!(DataMessage::decode(&bytes).unwrap(), m);
        }
    }

    #[test]
    fn debug_hides_media_key() {
        let msg = DataMessage::Control(Control::MediaKey { index: 2, key: [0xAB; 32] });
        let text = format!("{msg:?}");
        assert!(text.contains("index: 2"), "{text}");
        assert!(!text.contains("171"), "{text}");
    }

    #[test]
    fn debug_hides_clipboard_contents() {
        let msg = DataMessage::Clipboard { kind: ClipboardKind::Text, bytes: b"hunter2".to_vec() };
        let text = format!("{msg:?}");
        assert!(text.contains("7 bytes"), "{text}");
        assert!(!text.contains("104"), "{text}");
    }

    #[test]
    fn unknown_version_is_reported() {
        let mut b = DataMessage::Key { code: 1, down: true }.encode();
        b[0] = 99;
        assert_eq!(DataMessage::decode(&b), Err(DecodeError::UnknownVersion(99)));
    }

    #[test]
    fn empty_and_garbage_fail() {
        assert_eq!(DataMessage::decode(&[]), Err(DecodeError::Empty));
        assert_eq!(DataMessage::decode(&[DATA_VERSION, 250, 250]), Err(DecodeError::Malformed));
        let mut trailing = DataMessage::Key { code: 1, down: true }.encode();
        trailing.push(0);
        assert_eq!(DataMessage::decode(&trailing), Err(DecodeError::Malformed));
    }

    #[test]
    fn topics_and_reliability() {
        let pointer = DataMessage::PointerMove { x: 0, y: 0, monitor: 0 };
        assert_eq!(pointer.topic(), TOPIC_POINTER);
        assert!(!pointer.is_reliable());
        let clip = DataMessage::Clipboard { kind: ClipboardKind::Image, bytes: vec![] };
        assert_eq!(clip.topic(), TOPIC_CLIPBOARD);
        assert!(clip.is_reliable());
        assert_eq!(DataMessage::Control(Control::Hangup).topic(), TOPIC_INPUT);
        assert_eq!(DataMessage::Key { code: 1, down: true }.topic(), TOPIC_INPUT);
    }
}
