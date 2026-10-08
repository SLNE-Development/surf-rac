//! Headless remote-desktop sessions over LiveKit with end-to-end encryption.
//!
//! A host publishes its screen in its own LiveKit room and admits viewers it
//! accepted through the signaling server. Media is protected with LiveKit
//! frame encryption under a host media key; data messages are sealed with a
//! pairwise key that host and viewer derive from their device keys.

pub mod channel;
mod config;
pub mod crypto;
pub mod host;
pub mod pinning;
mod reconnect;
mod room;
pub mod signaling;
pub mod video;
pub mod viewer;

pub use channel::{CRYPTO_FAILURE_LIMIT, SendError};
pub use config::{EndReason, MAX_VIEWERS, SessionConfig};
pub use crypto::{CryptoError, DeviceKeys, PublicKey, SessionKey};
pub use pinning::{KeyChanged, KnownKeys};
pub use video::{Frame, FrameError, PixelFormat};
