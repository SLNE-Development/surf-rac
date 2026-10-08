//! A running screen share: captures the selected monitor, publishes it on a
//! host session and keeps every viewer informed about the screen state.

use std::collections::HashSet;
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use surf_rac_protocol::DeviceId;
use surf_rac_protocol::data::{CaptureState, Control, DataMessage, PauseReason, QualityMode, ScreenState};
use surf_rac_session::host::HostSession;
use surf_rac_session::{EncodedFrame, Frame, FrameError, RateRequest, SendError, VideoInput};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::convert::{self, BgraFrame};
use crate::h264::{EncodeError, EncodedAu};
use crate::mode::{self, FRAME_RATE};
use crate::source::{CaptureError, FrameSource};
use crate::state::{Controller, Outgoing};

/// How often the monitor list is refreshed.
const ENUMERATE_INTERVAL: Duration = Duration::from_secs(2);

/// First wait before capture is retried after a failure.
const BACKOFF_START: Duration = Duration::from_millis(250);

/// Longest wait between capture retries.
const BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Environment variable that forces the software encoder when set to `1`.
pub const FORCE_SOFTWARE_ENV: &str = "SURF_RAC_FORCE_SOFTWARE_ENCODER";

/// An H.264 encoder for frames of one size.
pub(crate) trait HwEncoder {
    /// Returns the encoder's display name.
    fn name(&self) -> &str;
    /// Returns the frame size it encodes.
    fn size(&self) -> (u32, u32);
    /// Encodes one NV12 frame; returns the access units that are ready.
    fn encode(&mut self, nv12: &[u8], timestamp_us: i64, force_keyframe: bool) -> Result<Vec<EncodedAu>, EncodeError>;
    /// Sets the target bitrate in bits per second.
    fn set_bitrate(&mut self, bitrate_bps: u64) -> Result<(), EncodeError>;
}

#[cfg(windows)]
impl HwEncoder for crate::mf::MfEncoder {
    /// Returns the Media Foundation encoder's name.
    fn name(&self) -> &str {
        self.adapter_name()
    }

    /// Returns the size the encoder was opened for.
    fn size(&self) -> (u32, u32) {
        crate::mf::MfEncoder::size(self)
    }

    /// Forwards to [`crate::mf::MfEncoder::encode`].
    fn encode(&mut self, nv12: &[u8], timestamp_us: i64, force_keyframe: bool) -> Result<Vec<EncodedAu>, EncodeError> {
        crate::mf::MfEncoder::encode(self, nv12, timestamp_us, force_keyframe)
    }

    /// Forwards to [`crate::mf::MfEncoder::set_bitrate`].
    fn set_bitrate(&mut self, bitrate_bps: u64) -> Result<(), EncodeError> {
        crate::mf::MfEncoder::set_bitrate(self, bitrate_bps)
    }
}

/// Opens a hardware encoder for `width` x `height` at a bitrate.
pub(crate) type HwFactory =
    Box<dyn FnMut(u32, u32, u64) -> Result<Box<dyn HwEncoder>, EncodeError> + Send>;

/// Settings a share starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShareOptions {
    /// Initial quality mode (default Balanced).
    pub mode: QualityMode,
    /// Initial monitor index; the primary monitor when `None` or out of range.
    pub monitor: Option<u8>,
    /// Encode in software even when a hardware encoder is available.
    pub force_software_encoder: bool,
}

/// Why a share could not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShareError {
    /// This platform has no screen capture.
    #[error("screen capture is only supported on Windows")]
    Unsupported,
    /// No capture method could be created.
    #[error("capture unavailable: {0}")]
    Capture(String),
}

/// A request to the share loop.
enum Command {
    /// A viewer sent a control message.
    Control(DeviceId, Control),
    /// A viewer joined and needs the current state.
    Joined(DeviceId),
    /// End the share.
    Stop,
}

/// A screen share running on its own capture thread.
pub struct ScreenShare {
    /// Requests to the capture thread.
    commands: std_mpsc::Sender<Command>,
    /// The latest screen state.
    state: watch::Receiver<ScreenState>,
    /// The capture thread.
    thread: Option<thread::JoinHandle<()>>,
    /// Delivers state messages to viewers.
    deliver: JoinHandle<()>,
}

impl ScreenShare {
    /// Starts sharing this machine's screen on `host`.
    ///
    /// Fails with [`ShareError::Unsupported`] on platforms without screen capture,
    /// and with [`ShareError::Capture`] when no screen capturer can be created.
    ///
    /// A hardware H.264 encoder is used when one is available, unless
    /// `options.force_software_encoder` is set or the environment variable
    /// [`FORCE_SOFTWARE_ENV`] is `1`.
    pub async fn start(host: HostSession, options: ShareOptions) -> Result<ScreenShare, ShareError> {
        #[cfg(windows)]
        {
            let forced = options.force_software_encoder
                || std::env::var(FORCE_SOFTWARE_ENV).is_ok_and(|v| v == "1");
            let hardware: Option<HwFactory> = (!forced).then(|| {
                Box::new(|w, h, bps| {
                    crate::mf::MfEncoder::new(w, h, bps, FRAME_RATE)
                        .map(|e| Box::new(e) as Box<dyn HwEncoder>)
                }) as HwFactory
            });
            let make_source = || {
                crate::desktop::DesktopSource::new()
                    .map(|s| Box::new(s) as Box<dyn FrameSource>)
                    .map_err(|e| ShareError::Capture(e.to_string()))
            };
            Self::start_inner(host, options, make_source, hardware).await
        }
        #[cfg(not(windows))]
        {
            let _ = (host, options);
            Err(ShareError::Unsupported)
        }
    }

    /// Starts sharing on `host` from the source `make_source` creates, encoding in software.
    ///
    /// `make_source` runs on the capture thread, which then owns the source.
    pub async fn start_with_source<F>(
        host: HostSession,
        options: ShareOptions,
        make_source: F,
    ) -> Result<ScreenShare, ShareError>
    where
        F: FnOnce() -> Result<Box<dyn FrameSource>, ShareError> + Send + 'static,
    {
        Self::start_inner(host, options, make_source, None).await
    }

    /// Starts the capture thread with `make_source` and, when given, a hardware encoder factory.
    async fn start_inner<F>(
        host: HostSession,
        options: ShareOptions,
        make_source: F,
        hardware: Option<HwFactory>,
    ) -> Result<ScreenShare, ShareError>
    where
        F: FnOnce() -> Result<Box<dyn FrameSource>, ShareError> + Send + 'static,
    {
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let sink = HostSink {
            host: host.clone(),
            runtime: Handle::current(),
        };
        let (commands, command_rx) = std_mpsc::channel();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let thread = thread::Builder::new()
            .name("surf-rac-capture".into())
            .spawn(move || {
                let source = match make_source() {
                    Ok(source) => source,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let mut share = ShareLoop::new(source, sink, options, out_tx, Instant::now());
                share.hardware = hardware;
                if share.hardware.is_none() {
                    tracing::info!("encoder: software");
                }
                if ready_tx.send(Ok(share.state_rx())).is_ok() {
                    share.run(command_rx);
                }
            })
            .map_err(|e| ShareError::Capture(e.to_string()))?;
        let state = match ready_rx.await {
            Ok(Ok(state)) => state,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(ShareError::Capture("capture thread ended".into())),
        };
        let deliver = tokio::spawn(deliver(host, out_rx));
        tracing::info!(mode = ?options.mode, "screen share started");
        Ok(ScreenShare {
            commands,
            state,
            thread: Some(thread),
            deliver,
        })
    }

    /// Hands the share a control message a viewer sent; screen requests are applied.
    pub fn handle_control(&self, from: DeviceId, control: &Control) {
        let _ = self.commands.send(Command::Control(from, control.clone()));
    }

    /// Tells the share that `viewer` joined, so it is sent the current state.
    pub fn viewer_joined(&self, viewer: DeviceId) {
        let _ = self.commands.send(Command::Joined(viewer));
    }

    /// Returns the current screen state.
    pub fn state(&self) -> ScreenState {
        self.state.borrow().clone()
    }

    /// Returns a receiver that sees every change of the screen state.
    pub fn subscribe(&self) -> watch::Receiver<ScreenState> {
        self.state.clone()
    }

    /// Stops capturing and waits for the capture thread to end. The host session keeps running.
    pub async fn stop(mut self) {
        let _ = self.commands.send(Command::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
        }
        let _ = (&mut self.deliver).await;
        tracing::info!("screen share stopped");
    }
}

impl Drop for ScreenShare {
    /// Asks the capture thread to end when the share is dropped without [`ScreenShare::stop`].
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Stop);
    }
}

/// Sends screen states to viewers until the capture thread ends.
///
/// Remembers every viewer a state was sent to individually and drops viewers
/// that are no longer connected.
async fn deliver(host: HostSession, mut rx: mpsc::UnboundedReceiver<Outgoing>) {
    let mut viewers: HashSet<DeviceId> = HashSet::new();
    while let Some(out) = rx.recv().await {
        let (targets, state) = match out {
            Outgoing::To(viewer, state) => {
                viewers.insert(viewer);
                (vec![viewer], state)
            }
            Outgoing::All(state) => (viewers.iter().copied().collect(), state),
        };
        let msg = DataMessage::Control(Control::ScreenState(state));
        for viewer in targets {
            if let Err(SendError::NotConnected) = host.send(viewer, &msg).await {
                viewers.remove(&viewer);
            }
        }
    }
}

/// Where the share loop publishes video.
pub(crate) trait VideoSink: Send + 'static {
    /// Publishes a raw frame.
    fn publish_raw(&self, frame: &Frame) -> Result<(), FrameError>;
    /// Publishes an encoded access unit.
    fn publish_encoded(&self, frame: &EncodedFrame<'_>) -> Result<(), FrameError>;
    /// Switches what the video track takes.
    fn switch_input(&self, input: VideoInput, width: u32, height: u32) -> Result<(), String>;
    /// Returns and clears a pending keyframe request.
    fn take_keyframe_request(&self) -> bool;
    /// Returns and clears a pending rate request.
    fn take_rate_request(&self) -> Option<RateRequest>;
}

/// Publishes on a host session from the capture thread.
struct HostSink {
    /// The session.
    host: HostSession,
    /// Runtime that runs the session's async calls.
    runtime: Handle,
}

impl VideoSink for HostSink {
    /// Publishes `frame` on the session's raw track.
    fn publish_raw(&self, frame: &Frame) -> Result<(), FrameError> {
        self.host.publish_frame(frame)
    }

    /// Publishes `frame` on the session's pass-through track.
    fn publish_encoded(&self, frame: &EncodedFrame<'_>) -> Result<(), FrameError> {
        self.host.publish_encoded(frame)
    }

    /// Replaces the session's video track, blocking the capture thread until done.
    fn switch_input(&self, input: VideoInput, width: u32, height: u32) -> Result<(), String> {
        self.runtime
            .block_on(self.host.set_video_input(input, width, height))
            .map_err(|e| e.to_string())
    }

    /// Forwards to [`HostSession::take_keyframe_request`].
    fn take_keyframe_request(&self) -> bool {
        self.host.take_keyframe_request()
    }

    /// Forwards to [`HostSession::take_rate_request`].
    fn take_rate_request(&self) -> Option<RateRequest> {
        self.host.take_rate_request()
    }
}

/// Exponentially growing wait between capture retries.
#[derive(Debug, Clone)]
pub(crate) struct Backoff {
    /// The wait the next call returns.
    next: Duration,
}

impl Backoff {
    /// Creates a backoff that starts at 250 ms.
    pub(crate) fn new() -> Backoff {
        Backoff {
            next: BACKOFF_START,
        }
    }

    /// Returns the next wait: 250 ms, doubling up to 5 s.
    pub(crate) fn next(&mut self) -> Duration {
        let wait = self.next;
        self.next = (self.next * 2).min(BACKOFF_MAX);
        wait
    }

    /// Starts over at 250 ms.
    pub(crate) fn reset(&mut self) {
        self.next = BACKOFF_START;
    }
}

/// The capture thread's state: source, encoder output, screen state and timing.
pub(crate) struct ShareLoop<K: VideoSink> {
    /// Where frames come from.
    source: Box<dyn FrameSource>,
    /// Where video goes.
    sink: K,
    /// The screen state.
    ctl: Controller,
    /// State messages for viewers.
    out: mpsc::UnboundedSender<Outgoing>,
    /// Publishes every state change.
    state_tx: watch::Sender<ScreenState>,
    /// Waits between retries while capture is paused.
    backoff: Backoff,
    /// When capture is retried next; `Some` while paused.
    retry_at: Option<Instant>,
    /// When the monitor list is refreshed next.
    next_enumerate: Instant,
    /// Opens hardware encoders; `None` once the share encodes in software.
    pub(crate) hardware: Option<HwFactory>,
    /// The open hardware encoder.
    hw: Option<Box<dyn HwEncoder>>,
    /// What the session's track currently takes.
    input: VideoInput,
    /// Whether the next hardware frame must be a keyframe.
    force_keyframe: bool,
    /// The latest bitrate the network asked for.
    requested_bps: Option<u64>,
}

impl<K: VideoSink> ShareLoop<K> {
    /// Creates the loop and lists the monitors of `source` at `now`.
    pub(crate) fn new(
        mut source: Box<dyn FrameSource>,
        sink: K,
        options: ShareOptions,
        out: mpsc::UnboundedSender<Outgoing>,
        now: Instant,
    ) -> ShareLoop<K> {
        let monitors = source.monitors();
        let mut ctl = Controller::new(
            monitors.as_ref().map(Vec::clone).unwrap_or_default(),
            options.monitor,
            options.mode,
        );
        let mut retry_at = None;
        let mut backoff = Backoff::new();
        let selected = match &monitors {
            Ok(list) if !list.is_empty() => source.select(usize::from(ctl.state().selected)),
            Ok(_) => Err(CaptureError::Unavailable),
            Err(e) => Err(*e),
        };
        if let Err(e) = selected {
            ctl.set_capture(paused(e));
            retry_at = Some(now + backoff.next());
        }
        let (state_tx, _) = watch::channel(ctl.state().clone());
        ShareLoop {
            source,
            sink,
            ctl,
            out,
            state_tx,
            backoff,
            retry_at,
            next_enumerate: now + ENUMERATE_INTERVAL,
            hardware: None,
            hw: None,
            input: VideoInput::Raw,
            force_keyframe: false,
            requested_bps: None,
        }
    }

    /// Returns a receiver of the screen state.
    pub(crate) fn state_rx(&self) -> watch::Receiver<ScreenState> {
        self.state_tx.subscribe()
    }

    /// Runs the loop until [`Command::Stop`] arrives or every command sender is gone.
    fn run(&mut self, commands: std_mpsc::Receiver<Command>) {
        let interval = Duration::from_secs(1) / FRAME_RATE;
        let mut next_tick = Instant::now();
        loop {
            let now = Instant::now();
            if now >= next_tick {
                self.tick(now);
                next_tick += interval;
                let after = Instant::now();
                if next_tick < after {
                    next_tick = after + interval;
                }
            }
            let wait = next_tick.saturating_duration_since(Instant::now());
            match commands.recv_timeout(wait) {
                Ok(Command::Stop) | Err(std_mpsc::RecvTimeoutError::Disconnected) => return,
                Ok(cmd) => self.command(cmd),
                Err(std_mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }

    /// Applies a viewer join or control message.
    fn command(&mut self, cmd: Command) {
        match cmd {
            Command::Joined(viewer) => {
                let out = self.ctl.viewer_joined(viewer);
                self.emit(Some(out));
            }
            Command::Control(from, control) => {
                let before = self.ctl.state().selected;
                let out = self.ctl.handle(from, &control);
                if self.ctl.state().selected != before {
                    tracing::info!(monitor = self.ctl.state().selected, "monitor selected");
                    self.select_current();
                }
                if let Control::SetQuality { mode } = control {
                    tracing::info!(?mode, "quality mode requested");
                    self.apply_bitrate();
                }
                self.emit(out);
            }
            Command::Stop => {}
        }
    }

    /// Captures and publishes one frame at `now`, handling pauses and monitor refreshes.
    pub(crate) fn tick(&mut self, now: Instant) {
        if now >= self.next_enumerate {
            self.enumerate(now);
        }
        if self.retry_at.is_some_and(|at| now < at) {
            return;
        }
        match self.source.capture() {
            Ok(Some(frame)) => {
                if self.retry_at.take().is_some() {
                    self.backoff.reset();
                    self.force_keyframe = true;
                    tracing::info!("capture resumed");
                    let out = self.ctl.set_capture(CaptureState::Active);
                    self.emit(out);
                }
                self.publish(&frame);
            }
            Ok(None) => {}
            Err(e) => self.fail(e, now),
        }
    }

    /// Pauses capture after `err` and schedules a retry.
    fn fail(&mut self, err: CaptureError, now: Instant) {
        let wait = self.backoff.next();
        self.retry_at = Some(now + wait);
        let out = self.ctl.set_capture(paused(err));
        if out.is_some() {
            tracing::info!(error = %err, "capture paused");
        }
        self.emit(out);
        self.enumerate(now);
    }

    /// Refreshes the monitor list at `now` and follows a changed selection.
    fn enumerate(&mut self, now: Instant) {
        self.next_enumerate = now + ENUMERATE_INTERVAL;
        let Ok(monitors) = self.source.monitors() else {
            return;
        };
        let out = self.ctl.set_monitors(monitors);
        if out.is_some() {
            tracing::info!(
                monitors = self.ctl.state().monitors.len(),
                selected = self.ctl.state().selected,
                "monitor list changed"
            );
            self.select_current();
        }
        self.emit(out);
    }

    /// Points the source at the selected monitor.
    fn select_current(&mut self) {
        if self.ctl.state().monitors.is_empty() {
            return;
        }
        if let Err(e) = self.source.select(usize::from(self.ctl.state().selected)) {
            tracing::warn!(error = %e, "selecting monitor failed");
        }
    }

    /// Converts `frame` for the current mode and publishes it, on the hardware
    /// encoder while one works and in software otherwise.
    fn publish(&mut self, frame: &BgraFrame) {
        let (w, h) = mode::target_size(self.ctl.state().mode, frame.width, frame.height);
        let timestamp_us = now_micros();
        if self.hardware.is_some() {
            match self.encode_hardware(frame, w, h, timestamp_us) {
                Ok(()) => return,
                Err(e) => self.fall_back(e, w, h),
            }
        }
        let raw = convert::to_i420(frame, w, h, timestamp_us);
        if let Err(e) = self.sink.publish_raw(&raw) {
            tracing::debug!(error = %e, "frame not published");
        }
    }

    /// Encodes `frame` at `w` x `h` on the hardware encoder and publishes the
    /// access units, opening the encoder and switching the track when needed.
    fn encode_hardware(&mut self, frame: &BgraFrame, w: u32, h: u32, timestamp_us: i64) -> Result<(), EncodeError> {
        if self.hw.as_ref().map(|e| e.size()) != Some((w, h)) {
            self.hw = None;
            let bps = self.bitrate();
            let factory = self.hardware.as_mut().ok_or(EncodeError::NoHardware)?;
            let enc = factory(w, h, bps)?;
            if self.input != VideoInput::Encoded {
                tracing::info!(encoder = enc.name(), "encoder: hardware");
                self.sink
                    .switch_input(VideoInput::Encoded, w, h)
                    .map_err(|_| EncodeError::Stalled)?;
                self.input = VideoInput::Encoded;
            }
            self.hw = Some(enc);
            self.force_keyframe = true;
        }
        if let Some(rate) = self.sink.take_rate_request() {
            self.requested_bps = Some(rate.bitrate_bps);
            self.apply_bitrate();
        }
        let force = self.sink.take_keyframe_request() | std::mem::take(&mut self.force_keyframe);
        let nv12 = convert::to_nv12(frame, w, h);
        let enc = self.hw.as_mut().ok_or(EncodeError::NoHardware)?;
        for au in enc.encode(&nv12, timestamp_us, force)? {
            let encoded = EncodedFrame {
                width: w,
                height: h,
                timestamp_us: au.timestamp_us,
                keyframe: au.keyframe,
                data: &au.data,
            };
            if let Err(e) = self.sink.publish_encoded(&encoded) {
                tracing::debug!(error = %e, "access unit not published");
            }
        }
        Ok(())
    }

    /// Returns the bitrate the hardware encoder targets: the network's request,
    /// capped by the quality mode.
    fn bitrate(&self) -> u64 {
        let cap = mode::bitrate_cap(self.ctl.state().mode);
        self.requested_bps.map_or(cap, |bps| bps.min(cap))
    }

    /// Passes the current target bitrate to the open hardware encoder.
    fn apply_bitrate(&mut self) {
        let bps = self.bitrate();
        if let Some(enc) = self.hw.as_mut() {
            if let Err(e) = enc.set_bitrate(bps) {
                tracing::debug!(error = %e, "bitrate change refused");
            }
        }
    }

    /// Stops using hardware encoding for the rest of the share after `err`.
    fn fall_back(&mut self, err: EncodeError, w: u32, h: u32) {
        self.hw = None;
        self.hardware = None;
        if err == EncodeError::NoHardware {
            tracing::info!("encoder: software (no hardware H.264 encoder)");
        } else {
            tracing::warn!(error = %err, "hardware encoder failed, switching to software");
        }
        if self.input != VideoInput::Raw {
            match self.sink.switch_input(VideoInput::Raw, w, h) {
                Ok(()) => self.input = VideoInput::Raw,
                Err(e) => tracing::warn!(error = %e, "switching the track to raw frames failed"),
            }
        }
    }

    /// Queues `out` for delivery and publishes the new state when it is a broadcast.
    fn emit(&self, out: Option<Outgoing>) {
        let Some(out) = out else { return };
        if let Outgoing::All(state) = &out {
            self.state_tx.send_replace(state.clone());
        }
        let _ = self.out.send(out);
    }
}

/// Returns the paused state for a capture failure.
fn paused(err: CaptureError) -> CaptureState {
    CaptureState::Paused {
        reason: match err {
            CaptureError::Temporary => PauseReason::Recovering,
            CaptureError::Unavailable => PauseReason::Unavailable,
        },
    }
}

/// Returns the current wall-clock time in microseconds since the Unix epoch.
fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as i64)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::source::{SyntheticControl, SyntheticSource};

    /// Records what the loop publishes and plays back queued network requests.
    #[derive(Clone, Default)]
    struct Recorder {
        /// Sizes of published raw frames.
        raw: Arc<Mutex<Vec<(u32, u32)>>>,
        /// Published access units as `(width, height, keyframe)`.
        encoded: Arc<Mutex<Vec<(u32, u32, bool)>>>,
        /// Track input switches.
        switches: Arc<Mutex<Vec<VideoInput>>>,
        /// Whether the next keyframe poll reports a request.
        keyframe: Arc<Mutex<bool>>,
        /// The rate the next rate poll reports.
        rate: Arc<Mutex<Option<u64>>>,
    }

    impl VideoSink for Recorder {
        /// Records the frame's size.
        fn publish_raw(&self, frame: &Frame) -> Result<(), FrameError> {
            self.raw.lock().unwrap().push((frame.width, frame.height));
            Ok(())
        }

        /// Records the access unit's size and type.
        fn publish_encoded(&self, frame: &EncodedFrame<'_>) -> Result<(), FrameError> {
            self.encoded
                .lock()
                .unwrap()
                .push((frame.width, frame.height, frame.keyframe));
            Ok(())
        }

        /// Records the switch.
        fn switch_input(&self, input: VideoInput, _w: u32, _h: u32) -> Result<(), String> {
            self.switches.lock().unwrap().push(input);
            Ok(())
        }

        /// Returns and clears the queued keyframe request.
        fn take_keyframe_request(&self) -> bool {
            std::mem::take(&mut *self.keyframe.lock().unwrap())
        }

        /// Returns and clears the queued rate.
        fn take_rate_request(&self) -> Option<RateRequest> {
            self.rate.lock().unwrap().take().map(|bps| RateRequest {
                bitrate_bps: bps,
                framerate: 30.0,
            })
        }
    }

    /// What a fake encoder saw.
    #[derive(Clone, Default)]
    struct FakeLog {
        /// Sizes encoders were opened at, with their initial bitrate.
        opened: Arc<Mutex<Vec<(u32, u32, u64)>>>,
        /// `force_keyframe` of every encode call.
        forced: Arc<Mutex<Vec<bool>>>,
        /// Every bitrate set after opening.
        bitrates: Arc<Mutex<Vec<u64>>>,
    }

    /// An encoder that emits one access unit per frame and fails after `fail_after` frames.
    struct FakeEncoder {
        /// Frame size.
        size: (u32, u32),
        /// Frames encoded so far.
        frames: u32,
        /// Frames after which encoding fails.
        fail_after: u32,
        /// Shared record.
        log: FakeLog,
    }

    impl HwEncoder for FakeEncoder {
        /// Returns a fixed name.
        fn name(&self) -> &str {
            "fake"
        }

        /// Returns the opened size.
        fn size(&self) -> (u32, u32) {
            self.size
        }

        /// Emits one access unit, a keyframe when forced, or fails.
        fn encode(&mut self, _nv12: &[u8], ts: i64, force: bool) -> Result<Vec<EncodedAu>, EncodeError> {
            self.log.forced.lock().unwrap().push(force);
            if self.frames >= self.fail_after {
                return Err(EncodeError::Hresult(0x8000_4005));
            }
            self.frames += 1;
            Ok(vec![EncodedAu {
                data: vec![0, 0, 1, 0x65],
                keyframe: force,
                timestamp_us: ts,
            }])
        }

        /// Records the bitrate.
        fn set_bitrate(&mut self, bps: u64) -> Result<(), EncodeError> {
            self.log.bitrates.lock().unwrap().push(bps);
            Ok(())
        }
    }

    /// Returns a factory of fake encoders that fail after `fail_after` frames each.
    fn fake_factory(fail_after: u32, log: FakeLog) -> HwFactory {
        Box::new(move |w, h, bps| {
            log.opened.lock().unwrap().push((w, h, bps));
            Ok(Box::new(FakeEncoder {
                size: (w, h),
                frames: 0,
                fail_after,
                log: log.clone(),
            }) as Box<dyn HwEncoder>)
        })
    }

    /// Returns a loop over two synthetic monitors, its control, recorder and state messages.
    fn setup() -> (
        ShareLoop<Recorder>,
        SyntheticControl,
        Recorder,
        mpsc::UnboundedReceiver<Outgoing>,
        Instant,
    ) {
        let (source, control) = SyntheticSource::new(vec![(1920, 1080), (640, 480)]);
        let rec = Recorder::default();
        let (tx, rx) = mpsc::unbounded_channel();
        let t0 = Instant::now();
        let lp = ShareLoop::new(Box::new(source), rec.clone(), ShareOptions::default(), tx, t0);
        (lp, control, rec, rx, t0)
    }

    /// Returns every queued state message.
    fn drain(rx: &mut mpsc::UnboundedReceiver<Outgoing>) -> Vec<Outgoing> {
        std::iter::from_fn(|| rx.try_recv().ok()).collect()
    }

    /// Returns a test device ID.
    fn dev(n: u32) -> DeviceId {
        DeviceId::new(100_000_000 + n).unwrap()
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let mut b = Backoff::new();
        let waits: Vec<u64> = (0..7).map(|_| b.next().as_millis() as u64).collect();
        assert_eq!(waits, [250, 500, 1000, 2000, 4000, 5000, 5000]);
        b.reset();
        assert_eq!(b.next(), Duration::from_millis(250));
    }

    #[test]
    fn publishes_at_mode_size() {
        let (mut lp, _, rec, _, t0) = setup();
        lp.tick(t0);
        lp.command(Command::Control(
            dev(1),
            Control::SetQuality {
                mode: QualityMode::Speed,
            },
        ));
        lp.tick(t0);
        lp.command(Command::Control(dev(1), Control::SelectMonitor { index: 1 }));
        lp.tick(t0);
        assert_eq!(*rec.raw.lock().unwrap(), [(1920, 1080), (1280, 720), (640, 480)]);
    }

    #[test]
    fn join_and_requests_reach_viewers() {
        let (mut lp, _, _, mut rx, _) = setup();
        lp.command(Command::Joined(dev(1)));
        lp.command(Command::Control(dev(1), Control::SelectMonitor { index: 7 }));
        lp.command(Command::Control(dev(1), Control::SelectMonitor { index: 1 }));
        let out = drain(&mut rx);
        assert!(matches!(&out[0], Outgoing::To(v, s) if *v == dev(1) && s.selected == 0));
        assert!(matches!(&out[1], Outgoing::To(v, s) if *v == dev(1) && s.selected == 0));
        assert!(matches!(&out[2], Outgoing::All(s) if s.selected == 1));
        assert_eq!(lp.state_rx().borrow().selected, 1);
    }

    #[test]
    fn pause_broadcast_once_and_backoff_caps() {
        let (mut lp, control, rec, mut rx, t0) = setup();
        control.fail_next(20);
        let mut now = t0;
        let mut waits = Vec::new();
        for _ in 0..8 {
            lp.tick(now);
            let at = lp.retry_at.expect("paused");
            waits.push(at.duration_since(now).as_millis() as u64);
            lp.tick(at - Duration::from_millis(1));
            now = at;
        }
        assert_eq!(waits, [250, 500, 1000, 2000, 4000, 5000, 5000, 5000]);
        let pauses = drain(&mut rx)
            .into_iter()
            .filter(|o| matches!(o, Outgoing::All(s) if s.capture != CaptureState::Active))
            .count();
        assert_eq!(pauses, 1);
        assert!(rec.raw.lock().unwrap().is_empty());

        control.fail_next(0);
        lp.tick(now);
        assert!(lp.retry_at.is_none());
        let out = drain(&mut rx);
        assert!(matches!(&out[..], [Outgoing::All(s)] if s.capture == CaptureState::Active));
        assert_eq!(rec.raw.lock().unwrap().len(), 1);
        control.fail_next(1);
        lp.tick(now);
        assert_eq!(lp.retry_at.unwrap().duration_since(now), BACKOFF_START);
    }

    #[test]
    fn hardware_publishes_encoded_with_keyframe_first() {
        let (mut lp, _, rec, _, t0) = setup();
        let log = FakeLog::default();
        lp.hardware = Some(fake_factory(u32::MAX, log.clone()));
        lp.tick(t0);
        lp.tick(t0);
        assert_eq!(*rec.switches.lock().unwrap(), [VideoInput::Encoded]);
        assert_eq!(*rec.encoded.lock().unwrap(), [(1920, 1080, true), (1920, 1080, false)]);
        assert!(rec.raw.lock().unwrap().is_empty());
        assert_eq!(*log.opened.lock().unwrap(), [(1920, 1080, 5_000_000)]);
    }

    #[test]
    fn keyframe_and_rate_requests_reach_the_encoder() {
        let (mut lp, _, rec, _, t0) = setup();
        let log = FakeLog::default();
        lp.hardware = Some(fake_factory(u32::MAX, log.clone()));
        lp.tick(t0);
        *rec.rate.lock().unwrap() = Some(9_000_000);
        lp.tick(t0);
        *rec.rate.lock().unwrap() = Some(3_000_000);
        *rec.keyframe.lock().unwrap() = true;
        lp.tick(t0);
        lp.command(Command::Control(
            dev(1),
            Control::SetQuality {
                mode: QualityMode::Quality,
            },
        ));
        assert_eq!(*log.forced.lock().unwrap(), [true, false, true]);
        assert_eq!(*log.bitrates.lock().unwrap(), [5_000_000, 3_000_000, 3_000_000]);
    }

    #[test]
    fn size_change_reopens_encoder_with_keyframe() {
        let (mut lp, _, rec, _, t0) = setup();
        let log = FakeLog::default();
        lp.hardware = Some(fake_factory(u32::MAX, log.clone()));
        lp.tick(t0);
        lp.tick(t0);
        lp.command(Command::Control(dev(1), Control::SelectMonitor { index: 1 }));
        lp.tick(t0);
        assert_eq!(
            log.opened.lock().unwrap().iter().map(|o| (o.0, o.1)).collect::<Vec<_>>(),
            [(1920, 1080), (640, 480)]
        );
        assert_eq!(rec.encoded.lock().unwrap()[2], (640, 480, true));
        assert_eq!(*rec.switches.lock().unwrap(), [VideoInput::Encoded]);
    }

    #[test]
    fn hardware_error_falls_back_to_software() {
        let (mut lp, _, rec, _, t0) = setup();
        let log = FakeLog::default();
        lp.hardware = Some(fake_factory(2, log.clone()));
        for _ in 0..5 {
            lp.tick(t0);
        }
        assert_eq!(*rec.switches.lock().unwrap(), [VideoInput::Encoded, VideoInput::Raw]);
        assert_eq!(rec.encoded.lock().unwrap().len(), 2);
        assert_eq!(rec.raw.lock().unwrap().len(), 3);
        assert_eq!(log.opened.lock().unwrap().len(), 1);
        assert!(lp.hardware.is_none());
    }

    #[test]
    fn no_hardware_stays_software_without_switching() {
        let (mut lp, _, rec, _, t0) = setup();
        lp.hardware = Some(Box::new(|_, _, _| Err(EncodeError::NoHardware)));
        lp.tick(t0);
        lp.tick(t0);
        assert!(rec.switches.lock().unwrap().is_empty());
        assert_eq!(rec.raw.lock().unwrap().len(), 2);
        assert!(lp.hardware.is_none());
    }

    #[test]
    fn resume_forces_a_keyframe() {
        let (mut lp, control, rec, _, t0) = setup();
        let log = FakeLog::default();
        lp.hardware = Some(fake_factory(u32::MAX, log.clone()));
        lp.tick(t0);
        lp.tick(t0);
        control.fail_next(1);
        lp.tick(t0);
        let at = lp.retry_at.unwrap();
        lp.tick(at);
        assert_eq!(*log.forced.lock().unwrap(), [true, false, true]);
        assert_eq!(rec.encoded.lock().unwrap().len(), 3);
    }

    #[test]
    fn no_monitors_starts_paused_unavailable() {
        let (source, _) = SyntheticSource::new(vec![]);
        let (tx, _rx) = mpsc::unbounded_channel();
        let lp = ShareLoop::new(Box::new(source), Recorder::default(), ShareOptions::default(), tx, Instant::now());
        assert_eq!(
            lp.ctl.state().capture,
            CaptureState::Paused {
                reason: PauseReason::Unavailable
            }
        );
    }
}
