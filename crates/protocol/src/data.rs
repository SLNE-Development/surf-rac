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
        /// Windows set-1 scan code in the low byte, with `0x100` set for
        /// E0-extended keys; `0x45` is Pause.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// The host's current screen: its monitors, the shared selection and capture status.
    ScreenState(ScreenState),
    /// A viewer asks the host to show the monitor with this index.
    SelectMonitor {
        /// Index of the monitor in [`ScreenState::monitors`].
        index: u8,
    },
    /// A viewer asks the host to switch the quality mode.
    SetQuality {
        /// The requested mode.
        mode: QualityMode,
    },
    /// What the receiving viewer may currently do on the host.
    InputState(InputState),
    /// A viewer asks the host to turn follow mode on or off.
    SetFollow {
        /// True to follow where the host is working.
        on: bool,
    },
    /// The host paused or resumed the receiving viewer's view of its screen.
    ViewPaused {
        /// True while the view is paused, false once it is shown again.
        paused: bool,
    },
}

/// A viewer's input permissions and the host-wide input status.
///
/// The default grants nothing, with pointing on and no lock or follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputState {
    /// Whether the viewer may move, click and scroll with the real cursor.
    pub pointer: bool,
    /// Whether the viewer may type.
    pub keyboard: bool,
    /// Whether all remote input is locked out because the host is using its input.
    pub locked: bool,
    /// Whether the shared monitor follows where the host is working.
    pub follow: bool,
    /// Whether the host shows or injects the viewer's pointer at all; true
    /// when the sender did not include it.
    #[serde(default = "pointing_default")]
    pub pointing: bool,
}

impl Default for InputState {
    /// Returns a state with no pointer or keyboard grant, no lock, follow
    /// off and pointing on.
    fn default() -> InputState {
        InputState {
            pointer: false,
            keyboard: false,
            locked: false,
            follow: false,
            pointing: true,
        }
    }
}

/// Returns the value of [`InputState::pointing`] when it is missing: true.
fn pointing_default() -> bool {
    true
}

/// The layout of [`InputState`] without [`InputState::pointing`].
#[derive(Deserialize)]
struct InputStateWithoutPointing {
    /// See [`InputState::pointer`].
    pointer: bool,
    /// See [`InputState::keyboard`].
    keyboard: bool,
    /// See [`InputState::locked`].
    locked: bool,
    /// See [`InputState::follow`].
    follow: bool,
}

/// Leading body bytes of an encoded [`Control::InputState`] message: the
/// [`DataMessage::Control`] tag followed by the [`Control::InputState`] tag.
const INPUT_STATE_PREFIX: [u8; 2] = [4, 5];

/// Most monitors a [`ScreenState`] lists.
pub const MAX_MONITORS: usize = 16;

/// Longest monitor name, in bytes, a [`MonitorInfo`] carries.
pub const MAX_MONITOR_NAME_BYTES: usize = 64;

/// The screen a host shares, as every viewer sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenState {
    /// The host's monitors, at most [`MAX_MONITORS`].
    pub monitors: Vec<MonitorInfo>,
    /// Index of the monitor being shared.
    pub selected: u8,
    /// The quality mode the video is encoded with.
    pub mode: QualityMode,
    /// Whether frames are being captured.
    pub capture: CaptureState,
}

/// One monitor of the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorInfo {
    /// Position in [`ScreenState::monitors`]; used to select it.
    pub index: u8,
    /// Display name, at most [`MAX_MONITOR_NAME_BYTES`].
    pub name: String,
    /// Native width in pixels.
    pub width: u32,
    /// Native height in pixels.
    pub height: u32,
    /// Whether it is the primary monitor.
    pub primary: bool,
}

/// Trade-off between picture quality and speed, shared by all viewers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum QualityMode {
    /// Native resolution and the highest bitrate.
    Quality,
    /// Resolution capped at 1920 pixels on the longest side.
    #[default]
    Balanced,
    /// Resolution capped at 1280 pixels on the longest side and the lowest bitrate.
    Speed,
}

/// Whether the host is capturing its screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureState {
    /// Frames are captured and sent.
    Active,
    /// No frames are sent; viewers keep the last one.
    Paused {
        /// Why capture is paused.
        reason: PauseReason,
    },
}

/// Why capture is paused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PauseReason {
    /// No capture method works on the host.
    Unavailable,
    /// Capture failed and is being retried.
    Recovering,
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
            DataMessage::Wheel { dx, dy } => f
                .debug_struct("Wheel")
                .field("dx", dx)
                .field("dy", dy)
                .finish(),
            DataMessage::Key { code, down } => f
                .debug_struct("Key")
                .field("code", code)
                .field("down", down)
                .finish(),
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
            Control::ScreenState(state) => f.debug_tuple("ScreenState").field(state).finish(),
            Control::SelectMonitor { index } => f
                .debug_struct("SelectMonitor")
                .field("index", index)
                .finish(),
            Control::SetQuality { mode } => {
                f.debug_struct("SetQuality").field("mode", mode).finish()
            }
            Control::InputState(state) => f.debug_tuple("InputState").field(state).finish(),
            Control::SetFollow { on } => f.debug_struct("SetFollow").field("on", on).finish(),
            Control::ViewPaused { paused } => f
                .debug_struct("ViewPaused")
                .field("paused", paused)
                .finish(),
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
            _ => decode_input_state_without_pointing(body).ok_or(DecodeError::Malformed),
        }
    }
}

/// Decodes `body` as a [`Control::InputState`] message that lacks
/// [`InputState::pointing`], filling it in as true; `None` when `body` is
/// not such a message.
fn decode_input_state_without_pointing(body: &[u8]) -> Option<DataMessage> {
    let rest = body.strip_prefix(&INPUT_STATE_PREFIX[..])?;
    match postcard::take_from_bytes::<InputStateWithoutPointing>(rest) {
        Ok((s, [])) => Some(DataMessage::Control(Control::InputState(InputState {
            pointer: s.pointer,
            keyboard: s.keyboard,
            locked: s.locked,
            follow: s.follow,
            pointing: pointing_default(),
        }))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_every_variant() {
        for m in [
            DataMessage::PointerMove {
                x: -5,
                y: 7,
                monitor: 1,
            },
            DataMessage::PointerButton {
                button: MouseButton::Right,
                down: true,
            },
            DataMessage::Wheel { dx: 0, dy: -120 },
            DataMessage::Key {
                code: 0x1E,
                down: false,
            },
            DataMessage::Control(Control::MediaKey {
                index: 3,
                key: [9; 32],
            }),
            DataMessage::Control(Control::Hangup),
            DataMessage::Clipboard {
                kind: ClipboardKind::Text,
                bytes: b"hi".to_vec(),
            },
        ] {
            let bytes = m.encode();
            assert_eq!(bytes[0], DATA_VERSION);
            assert_eq!(DataMessage::decode(&bytes).unwrap(), m);
        }
    }

    #[test]
    fn screen_control_round_trips() {
        let state = ScreenState {
            monitors: vec![
                MonitorInfo {
                    index: 0,
                    name: "DISPLAY1".into(),
                    width: 2560,
                    height: 1440,
                    primary: true,
                },
                MonitorInfo {
                    index: 1,
                    name: "DISPLAY2".into(),
                    width: 1080,
                    height: 1920,
                    primary: false,
                },
            ],
            selected: 1,
            mode: QualityMode::Speed,
            capture: CaptureState::Paused {
                reason: PauseReason::Recovering,
            },
        };
        for m in [
            DataMessage::Control(Control::ScreenState(state)),
            DataMessage::Control(Control::SelectMonitor { index: 1 }),
            DataMessage::Control(Control::SetQuality {
                mode: QualityMode::Quality,
            }),
        ] {
            assert_eq!(DataMessage::decode(&m.encode()).unwrap(), m);
            assert_eq!(m.topic(), TOPIC_INPUT);
            assert!(m.is_reliable());
        }
    }

    #[test]
    fn existing_variant_bytes_unchanged() {
        assert_eq!(DataMessage::Control(Control::Hangup).encode(), [1, 4, 1]);
        assert_eq!(
            DataMessage::Control(Control::MediaKey {
                index: 2,
                key: [7; 32]
            })
            .encode()[..4],
            [1, 4, 0, 2]
        );
    }

    #[test]
    fn input_control_variants_round_trip_and_append() {
        let state = DataMessage::Control(Control::InputState(InputState {
            pointer: true,
            keyboard: false,
            locked: true,
            follow: false,
            pointing: false,
        }));
        assert_eq!(DataMessage::decode(&state.encode()).unwrap(), state);
        assert_eq!(state.encode(), [1, 4, 5, 1, 0, 1, 0, 0]);
        let follow = DataMessage::Control(Control::SetFollow { on: true });
        assert_eq!(DataMessage::decode(&follow.encode()).unwrap(), follow);
        assert_eq!(follow.encode(), [1, 4, 6, 1]);
        assert!(follow.is_reliable());
        assert_eq!(follow.topic(), TOPIC_INPUT);
    }

    /// Checks that an input state with pointing on and off survives encoding.
    #[test]
    fn input_state_pointing_round_trips() {
        for pointing in [true, false] {
            let msg = DataMessage::Control(Control::InputState(InputState {
                pointer: false,
                keyboard: true,
                locked: false,
                follow: true,
                pointing,
            }));
            assert_eq!(DataMessage::decode(&msg.encode()).unwrap(), msg);
        }
    }

    /// Checks that an input state encoded without the pointing field decodes
    /// with pointing on, and that other truncations still fail.
    #[test]
    fn input_state_without_pointing_means_pointing() {
        let decoded = DataMessage::decode(&[1, 4, 5, 1, 0, 1, 0]).unwrap();
        assert_eq!(
            decoded,
            DataMessage::Control(Control::InputState(InputState {
                pointer: true,
                keyboard: false,
                locked: true,
                follow: false,
                pointing: true,
            }))
        );
        assert_eq!(
            DataMessage::decode(&[1, 4, 5, 1, 0, 1]),
            Err(DecodeError::Malformed)
        );
        assert_eq!(
            DataMessage::decode(&[1, 4, 5, 1, 0, 1, 0, 1, 0]),
            Err(DecodeError::Malformed)
        );
        assert_eq!(
            DataMessage::decode(&[1, 4, 6, 1, 0, 1, 0]),
            Err(DecodeError::Malformed)
        );
    }

    /// Checks that a view-pause message round-trips in both states, is
    /// appended after the existing control variants and travels reliably.
    #[test]
    fn view_paused_round_trips_and_appends() {
        for paused in [true, false] {
            let msg = DataMessage::Control(Control::ViewPaused { paused });
            assert_eq!(DataMessage::decode(&msg.encode()).unwrap(), msg);
            assert_eq!(msg.encode(), [1, 4, 7, u8::from(paused)]);
            assert!(msg.is_reliable());
            assert_eq!(msg.topic(), TOPIC_INPUT);
        }
    }

    #[test]
    fn default_quality_mode_is_balanced() {
        assert_eq!(QualityMode::default(), QualityMode::Balanced);
    }

    #[test]
    fn debug_hides_media_key() {
        let msg = DataMessage::Control(Control::MediaKey {
            index: 2,
            key: [0xAB; 32],
        });
        let text = format!("{msg:?}");
        assert!(text.contains("index: 2"), "{text}");
        assert!(!text.contains("171"), "{text}");
    }

    #[test]
    fn debug_hides_clipboard_contents() {
        let msg = DataMessage::Clipboard {
            kind: ClipboardKind::Text,
            bytes: b"hunter2".to_vec(),
        };
        let text = format!("{msg:?}");
        assert!(text.contains("7 bytes"), "{text}");
        assert!(!text.contains("104"), "{text}");
    }

    #[test]
    fn unknown_version_is_reported() {
        let mut b = DataMessage::Key {
            code: 1,
            down: true,
        }
        .encode();
        b[0] = 99;
        assert_eq!(
            DataMessage::decode(&b),
            Err(DecodeError::UnknownVersion(99))
        );
    }

    #[test]
    fn empty_and_garbage_fail() {
        assert_eq!(DataMessage::decode(&[]), Err(DecodeError::Empty));
        assert_eq!(
            DataMessage::decode(&[DATA_VERSION, 250, 250]),
            Err(DecodeError::Malformed)
        );
        let mut trailing = DataMessage::Key {
            code: 1,
            down: true,
        }
        .encode();
        trailing.push(0);
        assert_eq!(DataMessage::decode(&trailing), Err(DecodeError::Malformed));
    }

    #[test]
    fn topics_and_reliability() {
        let pointer = DataMessage::PointerMove {
            x: 0,
            y: 0,
            monitor: 0,
        };
        assert_eq!(pointer.topic(), TOPIC_POINTER);
        assert!(!pointer.is_reliable());
        let clip = DataMessage::Clipboard {
            kind: ClipboardKind::Image,
            bytes: vec![],
        };
        assert_eq!(clip.topic(), TOPIC_CLIPBOARD);
        assert!(clip.is_reliable());
        assert_eq!(DataMessage::Control(Control::Hangup).topic(), TOPIC_INPUT);
        assert_eq!(
            DataMessage::Key {
                code: 1,
                down: true
            }
            .topic(),
            TOPIC_INPUT
        );
    }
}
