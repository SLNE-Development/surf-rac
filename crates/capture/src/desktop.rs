//! Capture of this machine's monitors through libwebrtc's desktop capturer.
//!
//! libwebrtc picks the capture method (Windows Graphics Capture, DirectX
//! duplication or GDI) and composites the cursor into the frame. Monitor
//! names, sizes and the primary flag come from DXGI, because the capturer's
//! own source list carries only IDs.

use std::sync::{Arc, Mutex};

use livekit::webrtc::desktop_capturer::{
    CaptureError as LkCaptureError, CaptureSource, DesktopCaptureSourceType, DesktopCapturer,
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
    /// A monitor is matched to a capturer source by its monitor handle, or
    /// otherwise by its position among the attached outputs.
    fn monitors(&mut self) -> Result<Vec<SourceMonitor>, CaptureError> {
        let outputs = dxgi_outputs().map_err(|_| CaptureError::Temporary)?;
        let sources = new_capturer()?.get_source_list();
        let ids: Vec<u64> = sources.iter().map(CaptureSource::id).collect();
        let mut monitors = Vec::new();
        self.source_ids.clear();
        for (i, out) in outputs.iter().enumerate() {
            let id = ids
                .iter()
                .copied()
                .find(|id| *id == out.hmonitor)
                .or_else(|| ids.get(i).copied());
            if let Some(id) = id {
                self.source_ids.push(id);
                monitors.push(SourceMonitor {
                    name: out.name.clone(),
                    width: out.width,
                    height: out.height,
                    primary: out.primary,
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
