//! Where captured frames come from.

use crate::convert::BgraFrame;

/// A monitor as a frame source reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMonitor {
    /// Display name.
    pub name: String,
    /// Native width in pixels.
    pub width: u32,
    /// Native height in pixels.
    pub height: u32,
    /// Whether it is the primary monitor.
    pub primary: bool,
}

/// Why a frame source could not deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CaptureError {
    /// Capture failed this time and may work on a retry.
    #[error("capture temporarily failed")]
    Temporary,
    /// No capture method works.
    #[error("capture unavailable")]
    Unavailable,
}

/// Captures one monitor at a time as BGRA frames.
///
/// A source is created and driven on the share's capture thread.
pub trait FrameSource: 'static {
    /// Lists the monitors that can be captured, in a stable order.
    fn monitors(&mut self) -> Result<Vec<SourceMonitor>, CaptureError>;

    /// Switches capture to the monitor at `index` of the last [`FrameSource::monitors`] list.
    fn select(&mut self, index: usize) -> Result<(), CaptureError>;

    /// Captures the selected monitor; `None` when no new frame is ready yet.
    fn capture(&mut self) -> Result<Option<BgraFrame>, CaptureError>;
}

#[cfg(any(test, feature = "test-source"))]
pub use synthetic::{SyntheticControl, SyntheticSource};

#[cfg(any(test, feature = "test-source"))]
mod synthetic {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::{CaptureError, FrameSource, SourceMonitor};
    use crate::convert::BgraFrame;

    /// A frame source with fixed monitors that draws a solid colour per monitor.
    pub struct SyntheticSource {
        /// Monitor sizes; the first one is primary.
        sizes: Vec<(u32, u32)>,
        /// Index of the selected monitor; `None` until a selection succeeded.
        selected: Option<usize>,
        /// Failures still to report.
        control: SyntheticControl,
    }

    /// Lets a test make a [`SyntheticSource`] fail.
    #[derive(Clone, Default)]
    pub struct SyntheticControl {
        /// Number of upcoming captures that fail temporarily.
        fail_next: Arc<AtomicU32>,
        /// Number of upcoming monitor selections that fail temporarily.
        fail_select: Arc<AtomicU32>,
    }

    impl SyntheticControl {
        /// Makes the next `n` captures fail with [`CaptureError::Temporary`].
        pub fn fail_next(&self, n: u32) {
            self.fail_next.store(n, Ordering::SeqCst);
        }

        /// Makes the next `n` monitor selections fail with [`CaptureError::Temporary`].
        pub fn fail_select(&self, n: u32) {
            self.fail_select.store(n, Ordering::SeqCst);
        }
    }

    impl SyntheticSource {
        /// Creates a source with monitors of `sizes`, the first primary, and its control.
        pub fn new(sizes: Vec<(u32, u32)>) -> (SyntheticSource, SyntheticControl) {
            let control = SyntheticControl::default();
            let source = SyntheticSource {
                sizes,
                selected: None,
                control: control.clone(),
            };
            (source, control)
        }
    }

    impl FrameSource for SyntheticSource {
        /// Returns the fixed monitors named `SYNTH0`, `SYNTH1`, ...
        fn monitors(&mut self) -> Result<Vec<SourceMonitor>, CaptureError> {
            Ok(self
                .sizes
                .iter()
                .enumerate()
                .map(|(i, &(width, height))| SourceMonitor {
                    name: format!("SYNTH{i}"),
                    width,
                    height,
                    primary: i == 0,
                })
                .collect())
        }

        /// Selects monitor `index`; fails when there is no such monitor or a failure is pending.
        fn select(&mut self, index: usize) -> Result<(), CaptureError> {
            let fail = &self.control.fail_select;
            if fail.load(Ordering::SeqCst) > 0 {
                fail.fetch_sub(1, Ordering::SeqCst);
                return Err(CaptureError::Temporary);
            }
            if index >= self.sizes.len() {
                return Err(CaptureError::Unavailable);
            }
            self.selected = Some(index);
            Ok(())
        }

        /// Returns a frame of the selected monitor, or a pending failure; fails
        /// until a monitor has been selected.
        fn capture(&mut self) -> Result<Option<BgraFrame>, CaptureError> {
            let fail = &self.control.fail_next;
            if fail.load(Ordering::SeqCst) > 0 {
                fail.fetch_sub(1, Ordering::SeqCst);
                return Err(CaptureError::Temporary);
            }
            let Some(selected) = self.selected else {
                return Err(CaptureError::Unavailable);
            };
            let Some(&(width, height)) = self.sizes.get(selected) else {
                return Err(CaptureError::Unavailable);
            };
            let shade = 40u8.wrapping_add(60u8.wrapping_mul(selected as u8));
            let mut data = vec![shade; (width * height * 4) as usize];
            for px in data.chunks_mut(4) {
                px[3] = 255;
            }
            Ok(Some(BgraFrame {
                width,
                height,
                stride: width * 4,
                data,
            }))
        }
    }
}
