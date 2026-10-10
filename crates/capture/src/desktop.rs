//! Capture of this machine's monitors through libwebrtc's desktop capturer.
//!
//! libwebrtc picks the capture method (Windows Graphics Capture, DirectX
//! duplication or GDI) and composites the cursor into the frame. Monitor
//! names, sizes and the primary flag come from DXGI, because the capturer's
//! own source list carries only IDs.

use std::sync::{Arc, Mutex};

use livekit::webrtc::desktop_capturer::{
    CaptureError as LkCaptureError, DesktopCaptureSourceType, DesktopCapturer,
    DesktopCapturerOptions,
};
use windows::Win32::Graphics::Dxgi::{CreateDXGIFactory1, IDXGIFactory1};

use crate::convert::BgraFrame;
use crate::source::{CaptureError, FrameSource, SourceMonitor};

/// The outcome of the latest capture, as the capturer's callback stored it.
type Slot = Arc<Mutex<Option<Result<BgraFrame, CaptureError>>>>;

/// A monitor attached to the desktop, as DXGI reports it.
#[derive(Debug, Clone)]
struct Output {
    /// Device name without the `\\.\` prefix, e.g. `DISPLAY1`.
    name: String,
    /// Width in desktop pixels.
    width: u32,
    /// Height in desktop pixels.
    height: u32,
    /// Whether the monitor's top-left corner is the desktop origin.
    primary: bool,
    /// Left edge in desktop pixels.
    left: i32,
    /// Top edge in desktop pixels.
    top: i32,
    /// The monitor handle as an integer.
    hmonitor: u64,
}

/// Captures one of this machine's monitors at a time.
///
/// Must be used on the thread that created it.
pub struct DesktopSource {
    /// The running capturer, once a monitor is selected.
    capturer: Option<DesktopCapturer>,
    /// Where the capturer's callback leaves each result.
    slot: Slot,
    /// Capturer source ID of each monitor in the last [`FrameSource::monitors`] list.
    source_ids: Vec<u64>,
}

impl DesktopSource {
    /// Creates a source; fails when no screen capturer can be created on this machine.
    pub fn new() -> Result<DesktopSource, CaptureError> {
        new_capturer()?;
        Ok(DesktopSource {
            capturer: None,
            slot: Arc::default(),
            source_ids: Vec::new(),
        })
    }
}

impl FrameSource for DesktopSource {
    /// Lists the monitors the capturer can capture, in DXGI order.
    ///
    /// Monitors without a matching capturer source are left out; see [`match_sources`].
    fn monitors(&mut self) -> Result<Vec<SourceMonitor>, CaptureError> {
        let outputs = dxgi_outputs().map_err(|_| CaptureError::Temporary)?;
        let sources: Vec<(u64, String)> = new_capturer()?
            .get_source_list()
            .iter()
            .map(|s| (s.id(), s.title()))
            .collect();
        let ids = match_sources(&outputs, &sources);
        let mut monitors = Vec::new();
        self.source_ids.clear();
        for (out, id) in outputs.iter().zip(ids) {
            if let Some(id) = id {
                self.source_ids.push(id);
                monitors.push(SourceMonitor {
                    name: out.name.clone(),
                    width: out.width,
                    height: out.height,
                    primary: out.primary,
                    left: out.left,
                    top: out.top,
                });
            }
        }
        Ok(monitors)
    }

    /// Starts a new capturer on the monitor at `index`.
    fn select(&mut self, index: usize) -> Result<(), CaptureError> {
        let id = *self.source_ids.get(index).ok_or(CaptureError::Unavailable)?;
        let mut capturer = new_capturer()?;
        let source = capturer
            .get_source_list()
            .into_iter()
            .find(|s| s.id() == id)
            .ok_or(CaptureError::Temporary)?;
        let slot = Arc::clone(&self.slot);
        capturer.start_capture(Some(source), move |result| {
            let result = result
                .map(|f| BgraFrame {
                    width: f.width().max(0) as u32,
                    height: f.height().max(0) as u32,
                    stride: f.stride(),
                    data: f.data().to_vec(),
                })
                .map_err(|e| match e {
                    LkCaptureError::Temporary => CaptureError::Temporary,
                    LkCaptureError::Permanent => CaptureError::Unavailable,
                });
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
        });
        *self.slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.capturer = Some(capturer);
        Ok(())
    }

    /// Captures the selected monitor; `None` when the capturer delivered nothing.
    fn capture(&mut self) -> Result<Option<BgraFrame>, CaptureError> {
        let capturer = self.capturer.as_mut().ok_or(CaptureError::Unavailable)?;
        capturer.capture_frame();
        let result = self.slot.lock().unwrap_or_else(|e| e.into_inner()).take();
        match result {
            Some(Ok(frame)) if frame.width >= 2 && frame.height >= 2 => Ok(Some(frame)),
            Some(Ok(_)) | None => Ok(None),
            Some(Err(e)) => Err(e),
        }
    }
}

/// Returns the capturer source ID of each output, `None` where no source matches.
///
/// A source matches an output when its title is the output's device name
/// (`\\.\DISPLAYn`) or its ID is the output's monitor handle. Sources
/// without a title are otherwise taken in order, the way the duplication
/// capturer numbers the outputs. No source is given to two outputs.
fn match_sources(outputs: &[Output], sources: &[(u64, String)]) -> Vec<Option<u64>> {
    let mut used = vec![false; sources.len()];
    let take = |i: usize, used: &mut Vec<bool>| {
        if used[i] {
            None
        } else {
            used[i] = true;
            Some(sources[i].0)
        }
    };
    outputs
        .iter()
        .enumerate()
        .map(|(position, out)| {
            let device = format!(r"\\.\{}", out.name);
            let named = sources
                .iter()
                .position(|(_, title)| *title == device || *title == out.name);
            let handle = sources.iter().position(|(id, _)| *id == out.hmonitor);
            let ordered = sources
                .get(position)
                .filter(|(_, title)| title.is_empty())
                .map(|_| position);
            named
                .or(handle)
                .or(ordered)
                .and_then(|i| take(i, &mut used))
        })
        .collect()
}

/// Creates a screen capturer that composites the cursor into frames.
fn new_capturer() -> Result<DesktopCapturer, CaptureError> {
    let mut options = DesktopCapturerOptions::new(DesktopCaptureSourceType::Screen);
    options.set_include_cursor(true);
    DesktopCapturer::new(options).ok_or(CaptureError::Unavailable)
}

/// Lists the outputs attached to the desktop, adapter by adapter.
fn dxgi_outputs() -> windows::core::Result<Vec<Output>> {
    // SAFETY: plain COM calls on interfaces this function owns.
    unsafe {
        let factory: IDXGIFactory1 = CreateDXGIFactory1()?;
        let mut outputs = Vec::new();
        let mut a = 0;
        while let Ok(adapter) = factory.EnumAdapters1(a) {
            let mut o = 0;
            while let Ok(output) = adapter.EnumOutputs(o) {
                let desc = output.GetDesc()?;
                if desc.AttachedToDesktop.as_bool() {
                    let r = desc.DesktopCoordinates;
                    let name = String::from_utf16_lossy(&desc.DeviceName);
                    let name = name.trim_end_matches('\0');
                    outputs.push(Output {
                        name: name.trim_start_matches(r"\\.\").to_owned(),
                        width: (r.right - r.left).max(0) as u32,
                        height: (r.bottom - r.top).max(0) as u32,
                        primary: r.left == 0 && r.top == 0,
                        left: r.left,
                        top: r.top,
                        hmonitor: desc.Monitor.0 as usize as u64,
                    });
                }
                o += 1;
            }
            a += 1;
        }
        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns an output named `name` with monitor handle `hmonitor`.
    fn out(name: &str, hmonitor: u64) -> Output {
        Output {
            name: name.into(),
            width: 1920,
            height: 1080,
            primary: false,
            left: 0,
            top: 0,
            hmonitor,
        }
    }

    /// Sources are matched to outputs by monitor handle regardless of their order.
    #[test]
    fn matches_by_monitor_handle() {
        let outputs = [out("DISPLAY1", 0x1001), out("DISPLAY2", 0x2002)];
        let sources = [(0x2002, String::new()), (0x1001, String::new())];
        assert_eq!(match_sources(&outputs, &sources), [Some(0x1001), Some(0x2002)]);
    }

    /// Sources whose titles name a display device are matched to the output with that device name.
    #[test]
    fn matches_by_device_name_title() {
        let outputs = [out("DISPLAY1", 1), out("DISPLAY3", 3)];
        let sources = [(5, r"\\.\DISPLAY3".to_owned()), (0, r"\\.\DISPLAY1".to_owned())];
        assert_eq!(match_sources(&outputs, &sources), [Some(0), Some(5)]);
    }

    /// Untitled sources without matching handles are matched to outputs by position.
    #[test]
    fn falls_back_to_position_without_titles() {
        let outputs = [out("DISPLAY1", 11), out("DISPLAY2", 22)];
        let sources = [(0, String::new()), (1, String::new())];
        assert_eq!(match_sources(&outputs, &sources), [Some(0), Some(1)]);
    }

    /// A titled source naming no known output is left unmatched instead of being matched by
    /// position.
    #[test]
    fn titled_sources_are_never_matched_by_position() {
        let outputs = [out("DISPLAY1", 11), out("DISPLAY2", 22)];
        let sources = [(7, r"\\.\DISPLAY9".to_owned()), (8, r"\\.\DISPLAY2".to_owned())];
        assert_eq!(match_sources(&outputs, &sources), [None, Some(8)]);
    }

    /// Each source is matched to at most one output, leaving later outputs unmatched.
    #[test]
    fn a_source_is_used_once() {
        let outputs = [out("DISPLAY1", 0), out("DISPLAY2", 22)];
        let sources = [(0, String::new())];
        assert_eq!(match_sources(&outputs, &sources), [Some(0), None]);
    }
}
