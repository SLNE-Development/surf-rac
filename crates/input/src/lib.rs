//! Remote input on the host: merges viewer input, injects it, locks it out
//! while the person at the host uses their own input, and shows ghost
//! pointers for viewers that may not control the cursor.

pub mod arbiter;
pub mod host;
pub mod inject;
#[cfg(windows)]
pub mod ui;

pub use arbiter::{Action, Arbiter, Grants, InputStatus, ViewerStatus};
pub use host::{InputError, InputHost, route};
