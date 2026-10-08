//! Headless remote-desktop sessions over LiveKit with end-to-end encryption.

pub mod crypto;
pub mod pinning;

pub use crypto::{CryptoError, DeviceKeys, PublicKey, SessionKey};
pub use pinning::{KeyChanged, KnownKeys};
