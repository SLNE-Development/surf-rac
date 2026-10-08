//! Screen capture for a host session: captures the selected monitor, encodes
//! it as H.264 and keeps the screen state every viewer sees.

pub mod convert;
#[cfg(windows)]
pub mod desktop;
pub mod mode;
pub mod share;
pub mod source;
pub mod state;

pub use share::{ScreenShare, ShareError, ShareOptions};
pub use source::{CaptureError, FrameSource, SourceMonitor};
