//! Headless remote-desktop sessions over LiveKit with end-to-end encryption.

pub mod channel;
pub mod crypto;
pub mod pinning;
mod reconnect;
pub mod signaling;
pub mod video;

pub use channel::{CRYPTO_FAILURE_LIMIT, SendError};
pub use crypto::{CryptoError, DeviceKeys, PublicKey, SessionKey};
pub use pinning::{KeyChanged, KnownKeys};
pub use video::{Frame, FrameError, PixelFormat};
