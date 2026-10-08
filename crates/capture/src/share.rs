//! A running screen share: captures the selected monitor, publishes it on a
//! host session and keeps every viewer informed about the screen state.

use std::collections::HashSet;
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use surf_rac_protocol::DeviceId;
use surf_rac_protocol::data::{CaptureState, Control, DataMessage, PauseReason, QualityMode, ScreenState};
use surf_rac_session::host::HostSession;
use surf_rac_session::{Frame, FrameError, SendError};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::convert::{self, BgraFrame};
use crate::mode::{self, FRAME_RATE};
use crate::source::{CaptureError, FrameSource};
use crate::state::{Controller, Outgoing};

/// How often the monitor list is refreshed.
const ENUMERATE_INTERVAL: Duration = Duration::from_secs(2);

/// First wait before capture is retried after a failure.
const BACKOFF_START: Duration = Duration::from_millis(250);

/// Longest wait between capture retries.
const BACKOFF_MAX: Duration = Duration::from_secs(5);

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
    /// Fails with [`ShareError::Unsupported`] on platforms without screen capture.
    pub async fn start(host: HostSession, options: ShareOptions) -> Result<ScreenShare, ShareError> {
        let _ = (host, options);
        Err(ShareError::Unsupported)
    }

    /// Starts sharing frames from `source` on `host`.
    pub async fn start_with_source(
        host: HostSession,
        source: Box<dyn FrameSource>,
        options: ShareOptions,
    ) -> Result<ScreenShare, ShareError> {
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let deliver = tokio::spawn(deliver(host.clone(), out_rx));
        let sink = HostSink { host };
        let (commands, command_rx) = std_mpsc::channel();
        let mut share = ShareLoop::new(source, sink, options, out_tx, Instant::now());
        let state = share.state_rx();
        tracing::info!(mode = ?options.mode, "screen share started");
        let thread = thread::Builder::new()
            .name("surf-rac-capture".into())
            .spawn(move || share.run(command_rx))
            .map_err(|e| ShareError::Capture(e.to_string()))?;
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
}

/// Publishes on a host session from the capture thread.
struct HostSink {
    /// The session.
    host: HostSession,
}

impl VideoSink for HostSink {
    /// Publishes `frame` on the session's raw track.
    fn publish_raw(&self, frame: &Frame) -> Result<(), FrameError> {
        self.host.publish_frame(frame)
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

    /// Converts `frame` for the current mode and publishes it.
    fn publish(&mut self, frame: &BgraFrame) {
        let (w, h) = mode::target_size(self.ctl.state().mode, frame.width, frame.height);
        let raw = convert::to_i420(frame, w, h, now_micros());
        if let Err(e) = self.sink.publish_raw(&raw) {
            tracing::debug!(error = %e, "frame not published");
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

    /// Records what the loop publishes.
    #[derive(Clone, Default)]
    struct Recorder {
        /// Sizes of published raw frames.
        raw: Arc<Mutex<Vec<(u32, u32)>>>,
    }

    impl VideoSink for Recorder {
        /// Records the frame's size.
        fn publish_raw(&self, frame: &Frame) -> Result<(), FrameError> {
            self.raw.lock().unwrap().push((frame.width, frame.height));
            Ok(())
        }
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
