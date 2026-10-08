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
use crate::h264::EncodeError;
use crate::hw::{HwFactory, HwWorker, Job};
use crate::mode::{self, FRAME_RATE};
use crate::source::{CaptureError, FrameSource};
use crate::state::{Controller, Outgoing};

/// How often the monitor list is refreshed.
const ENUMERATE_INTERVAL: Duration = Duration::from_secs(2);

/// First wait before capture is retried after a failure.
const BACKOFF_START: Duration = Duration::from_millis(250);

/// Longest wait between capture retries.
const BACKOFF_MAX: Duration = Duration::from_secs(5);

/// How often the share logs its frame counters.
const STATS_INTERVAL: Duration = Duration::from_secs(10);

/// Environment variable that forces the software encoder when set to `1`.
pub const FORCE_SOFTWARE_ENV: &str = "SURF_RAC_FORCE_SOFTWARE_ENCODER";

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
                        .map(|e| Box::new(e) as Box<dyn crate::hw::HwEncoder>)
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

/// Publishes on a host session from the capture and encoding threads.
#[derive(Clone)]
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

/// Frame counters and processing times since the last stats log line.
#[derive(Debug)]
pub(crate) struct Stats {
    /// Frames the source delivered.
    captured: u32,
    /// Ticks skipped because the previous frame took too long.
    dropped: u32,
    /// Time from captured frame to published frame, per frame.
    process: Vec<Duration>,
    /// Start of the current period.
    since: Instant,
}

impl Stats {
    /// Starts counting at `now`.
    pub(crate) fn new(now: Instant) -> Stats {
        Stats {
            captured: 0,
            dropped: 0,
            process: Vec::new(),
            since: now,
        }
    }

    /// Returns the median processing time of the current period.
    pub(crate) fn median(&self) -> Option<Duration> {
        let mut times = self.process.clone();
        times.sort_unstable();
        times.get(times.len() / 2).copied()
    }

    /// Logs the counters when 10 s have passed since the last line, then starts over.
    fn log_if_due(&mut self, now: Instant) {
        if now.duration_since(self.since) < STATS_INTERVAL {
            return;
        }
        tracing::debug!(
            captured = self.captured,
            published = self.process.len(),
            dropped = self.dropped,
            median_process_ms = self.median().map_or(0.0, |d| d.as_secs_f64() * 1000.0),
            "screen share stats"
        );
        *self = Stats::new(now);
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
    /// Opens hardware encoders until the encoding thread takes it over.
    pub(crate) hardware: Option<HwFactory>,
    /// The hardware encoding thread; `None` while encoding in software.
    worker: Option<HwWorker>,
    /// Whether the next hardware frame must be a keyframe.
    force_keyframe: bool,
    /// The latest bitrate the network asked for.
    requested_bps: Option<u64>,
    /// Frame counters for the periodic stats line.
    stats: Stats,
}

impl<K: VideoSink + Clone> ShareLoop<K> {
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
            worker: None,
            force_keyframe: false,
            requested_bps: None,
            stats: Stats::new(now),
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
                    let behind = after.duration_since(next_tick).as_micros() / interval.as_micros();
                    self.stats.dropped += behind as u32 + 1;
                    next_tick = after + interval;
                }
                self.stats.log_if_due(after);
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
                self.stats.captured += 1;
                let started = Instant::now();
                self.publish(&frame);
                self.stats.process.push(started.elapsed());
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

    /// Converts `frame` for the current mode and publishes it: through the
    /// hardware encoding thread while hardware encoding works, in software otherwise.
    fn publish(&mut self, frame: &BgraFrame) {
        let (w, h) = mode::target_size(self.ctl.state().mode, frame.width, frame.height);
        let timestamp_us = now_micros();
        if let Some(err) = self.worker.as_ref().and_then(HwWorker::failure) {
            self.fall_back(err);
        }
        if self.worker.is_none() {
            if let Some(factory) = self.hardware.take() {
                self.worker = Some(HwWorker::start(factory, self.sink.clone()));
            }
        }
        if let Some(worker) = &self.worker {
            if let Some(rate) = self.sink.take_rate_request() {
                self.requested_bps = Some(rate.bitrate_bps);
            }
            let requested = self.sink.take_keyframe_request();
            if requested {
                tracing::debug!("keyframe requested by the network");
            }
            let force = requested | std::mem::take(&mut self.force_keyframe);
            let job = Job {
                nv12: convert::to_nv12(frame, w, h),
                width: w,
                height: h,
                timestamp_us,
                force_keyframe: force,
                bitrate_bps: self.bitrate(),
            };
            if !worker.submit(job) {
                self.stats.dropped += 1;
                self.force_keyframe |= force;
            }
            return;
        }
        let raw = convert::to_i420(frame, w, h, timestamp_us);
        if let Err(e) = self.sink.publish_raw(&raw) {
            tracing::debug!(error = %e, "frame not published");
        }
    }

    /// Returns the bitrate the hardware encoder targets: the network's request,
    /// capped by the quality mode.
    fn bitrate(&self) -> u64 {
        let cap = mode::bitrate_cap(self.ctl.state().mode);
        self.requested_bps.map_or(cap, |bps| bps.min(cap))
    }

    /// Encodes in software for the rest of the share after the hardware encoder failed with `err`.
    ///
    /// The encoding thread has already switched the track back to raw frames.
    fn fall_back(&mut self, err: EncodeError) {
        self.worker = None;
        self.hardware = None;
        if err == EncodeError::NoHardware {
            tracing::info!("encoder: software (no hardware H.264 encoder)");
        } else {
            tracing::warn!(error = %err, "hardware encoder failed, switching to software");
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
    use crate::h264::EncodedAu;
    use crate::hw::HwEncoder;
    use crate::source::{SyntheticControl, SyntheticSource};

    /// Waits up to 2 s for `cond` to hold.
    fn wait_for(cond: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !cond() {
            assert!(Instant::now() < deadline, "condition not met within 2 s");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

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
        /// Access units the next poll returns.
        pending: Arc<Mutex<u32>>,
        /// How long each encode call takes.
        delay: Arc<Mutex<Duration>>,
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
            let delay = *self.log.delay.lock().unwrap();
            let started = Instant::now();
            while started.elapsed() < delay && !self.log.delay.lock().unwrap().is_zero() {
                std::thread::sleep(Duration::from_millis(1));
            }
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

        /// Returns the pending access units.
        fn poll(&mut self) -> Result<Vec<EncodedAu>, EncodeError> {
            let n = std::mem::take(&mut *self.log.pending.lock().unwrap());
            Ok((0..n)
                .map(|_| EncodedAu {
                    data: vec![0, 0, 1, 0x41],
                    keyframe: false,
                    timestamp_us: 0,
                })
                .collect())
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
    fn stats_median_and_reset() {
        let t0 = Instant::now();
        let mut stats = Stats::new(t0);
        assert_eq!(stats.median(), None);
        for ms in [9, 1, 5] {
            stats.process.push(Duration::from_millis(ms));
        }
        assert_eq!(stats.median(), Some(Duration::from_millis(5)));
        stats.log_if_due(t0 + Duration::from_secs(1));
        assert_eq!(stats.process.len(), 3);
        stats.log_if_due(t0 + STATS_INTERVAL);
        assert!(stats.process.is_empty());
        assert_eq!(stats.since, t0 + STATS_INTERVAL);
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

    /// Ticks `lp` at `now` and waits until the recorder holds `encoded` access units.
    fn tick_encoded(lp: &mut ShareLoop<Recorder>, rec: &Recorder, now: Instant, encoded: usize) {
        lp.tick(now);
        wait_for(|| rec.encoded.lock().unwrap().len() >= encoded);
    }

    #[test]
    fn hardware_publishes_encoded_with_keyframe_first() {
        let (mut lp, _, rec, _, t0) = setup();
        let log = FakeLog::default();
        lp.hardware = Some(fake_factory(u32::MAX, log.clone()));
        tick_encoded(&mut lp, &rec, t0, 1);
        tick_encoded(&mut lp, &rec, t0, 2);
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
        tick_encoded(&mut lp, &rec, t0, 1);
        *rec.rate.lock().unwrap() = Some(9_000_000);
        tick_encoded(&mut lp, &rec, t0, 2);
        *rec.rate.lock().unwrap() = Some(3_000_000);
        *rec.keyframe.lock().unwrap() = true;
        tick_encoded(&mut lp, &rec, t0, 3);
        lp.command(Command::Control(
            dev(1),
            Control::SetQuality {
                mode: QualityMode::Speed,
            },
        ));
        tick_encoded(&mut lp, &rec, t0, 4);
        assert_eq!(*log.forced.lock().unwrap(), [true, false, true, true]);
        assert_eq!(
            *log.opened.lock().unwrap(),
            [(1920, 1080, 5_000_000), (1280, 720, 2_500_000)]
        );
        assert_eq!(*log.bitrates.lock().unwrap(), [3_000_000]);
    }

    #[test]
    fn size_change_reopens_encoder_with_keyframe() {
        let (mut lp, _, rec, _, t0) = setup();
        let log = FakeLog::default();
        lp.hardware = Some(fake_factory(u32::MAX, log.clone()));
        tick_encoded(&mut lp, &rec, t0, 1);
        tick_encoded(&mut lp, &rec, t0, 2);
        lp.command(Command::Control(dev(1), Control::SelectMonitor { index: 1 }));
        tick_encoded(&mut lp, &rec, t0, 3);
        assert_eq!(
            log.opened.lock().unwrap().iter().map(|o| (o.0, o.1)).collect::<Vec<_>>(),
            [(1920, 1080), (640, 480)]
        );
        assert_eq!(rec.encoded.lock().unwrap()[2], (640, 480, true));
        assert_eq!(*rec.switches.lock().unwrap(), [VideoInput::Encoded]);
    }

    #[test]
    fn polling_publishes_pending_access_units() {
        let (mut lp, _, rec, _, t0) = setup();
        let log = FakeLog::default();
        lp.hardware = Some(fake_factory(u32::MAX, log.clone()));
        tick_encoded(&mut lp, &rec, t0, 1);
        *log.pending.lock().unwrap() = 2;
        wait_for(|| rec.encoded.lock().unwrap().len() == 3);
    }

    #[test]
    fn busy_worker_drops_frames_and_keeps_the_keyframe() {
        let (mut lp, _, rec, _, t0) = setup();
        let log = FakeLog::default();
        lp.hardware = Some(fake_factory(u32::MAX, log.clone()));
        *log.delay.lock().unwrap() = Duration::from_millis(200);
        lp.tick(t0);
        wait_for(|| log.forced.lock().unwrap().len() == 1);
        lp.tick(t0);
        *rec.keyframe.lock().unwrap() = true;
        lp.tick(t0);
        assert_eq!(lp.stats.dropped, 1);
        assert!(lp.force_keyframe, "the dropped frame's keyframe request was lost");
        *log.delay.lock().unwrap() = Duration::ZERO;
        wait_for(|| rec.encoded.lock().unwrap().len() == 2);
        tick_encoded(&mut lp, &rec, t0, 3);
        assert_eq!(*log.forced.lock().unwrap(), [true, false, true]);
    }

    #[test]
    fn hardware_error_falls_back_to_software() {
        let (mut lp, _, rec, _, t0) = setup();
        let log = FakeLog::default();
        lp.hardware = Some(fake_factory(2, log.clone()));
        tick_encoded(&mut lp, &rec, t0, 1);
        tick_encoded(&mut lp, &rec, t0, 2);
        lp.tick(t0);
        wait_for(|| rec.switches.lock().unwrap().len() == 2);
        lp.tick(t0);
        lp.tick(t0);
        assert_eq!(*rec.switches.lock().unwrap(), [VideoInput::Encoded, VideoInput::Raw]);
        assert_eq!(rec.encoded.lock().unwrap().len(), 2);
        assert_eq!(rec.raw.lock().unwrap().len(), 2);
        assert_eq!(log.opened.lock().unwrap().len(), 1);
        assert!(lp.hardware.is_none() && lp.worker.is_none());
    }

    #[test]
    fn no_hardware_stays_software_without_switching() {
        let (mut lp, _, rec, _, t0) = setup();
        lp.hardware = Some(Box::new(|_, _, _| Err(EncodeError::NoHardware)));
        let deadline = Instant::now() + Duration::from_secs(2);
        while rec.raw.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "no raw frame within 2 s");
            lp.tick(t0);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(rec.switches.lock().unwrap().is_empty());
        assert!(lp.hardware.is_none() && lp.worker.is_none());
    }

    #[test]
    fn resume_forces_a_keyframe() {
        let (mut lp, control, rec, _, t0) = setup();
        let log = FakeLog::default();
        lp.hardware = Some(fake_factory(u32::MAX, log.clone()));
        tick_encoded(&mut lp, &rec, t0, 1);
        tick_encoded(&mut lp, &rec, t0, 2);
        control.fail_next(1);
        lp.tick(t0);
        let at = lp.retry_at.unwrap();
        tick_encoded(&mut lp, &rec, at, 3);
        assert_eq!(*log.forced.lock().unwrap(), [true, false, true]);
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
