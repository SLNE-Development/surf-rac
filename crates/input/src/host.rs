//! Runs input arbitration for a host session: feeds viewer events and host
//! signals into the arbiter and carries out its actions.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use surf_rac_capture::{MonitorRect, ScreenShare, ShareHandle};
use surf_rac_protocol::DeviceId;
use surf_rac_protocol::data::{Control, DataMessage, InputState};
use surf_rac_session::host::{HostEvent, HostSession};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::arbiter::{Action, Arbiter, Grants, InputStatus};

/// Viewer input messages queued for arbitration; further ones are dropped.
pub const INPUT_CAPACITY: usize = 256;

/// How often lockouts, ghosts, follow and host input detection are checked.
const TICK: Duration = Duration::from_millis(50);

/// How often the input stats line is logged at most.
const STATS_INTERVAL: Duration = Duration::from_secs(1);

/// Why input could not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InputError {
    /// This platform has no input injection.
    #[error("remote input is only supported on Windows")]
    Unsupported,
    /// Host input detection or the overlay could not be set up.
    #[error("remote input unavailable: {0}")]
    Platform(String),
}

/// What the host machine provides: injection, ghost drawing and host input signals.
pub trait Platform: Send + 'static {
    /// Injects an input action; failures are logged by the platform.
    fn perform(&mut self, action: &Action);
    /// Replaces the ghost pointers shown: color slot and desktop position each.
    fn ghosts(&mut self, ghosts: Vec<(u8, i32, i32)>);
    /// Returns when the last physical host input happened.
    fn host_input(&self) -> Option<Instant>;
    /// Returns the sequence number and position of the last physical host mouse event.
    fn host_mouse(&self) -> Option<(u64, i32, i32)>;
    /// Returns the sequence number of the last foreground change and the centre of its monitor.
    fn foreground(&self) -> Option<(u64, i32, i32)>;
    /// Returns whether host input detection works.
    fn alive(&self) -> bool;
}

/// What the screen share provides to input arbitration.
pub trait Share: Send + 'static {
    /// Returns the desktop rectangle of each monitor, indexed like the screen state's monitors.
    fn geometry(&self) -> Vec<MonitorRect>;
    /// Returns the index of the shared monitor.
    fn selected(&self) -> u8;
    /// Makes monitor `index` the shared monitor.
    fn select_monitor(&self, index: u8);
}

impl Share for ShareHandle {
    /// Forwards to [`ShareHandle::geometry`].
    fn geometry(&self) -> Vec<MonitorRect> {
        ShareHandle::geometry(self)
    }

    /// Returns the selected index of the current screen state.
    fn selected(&self) -> u8 {
        self.state().selected
    }

    /// Forwards to [`ShareHandle::select_monitor`].
    fn select_monitor(&self, index: u8) {
        ShareHandle::select_monitor(self, index);
    }
}

/// A request to the arbitration task that must not be dropped.
#[derive(Debug)]
enum Command {
    /// A viewer joined.
    Joined(DeviceId),
    /// A viewer left.
    Left(DeviceId),
    /// A control message from a viewer.
    Message(DeviceId, DataMessage),
    /// The host changed a viewer's grants.
    Grants(DeviceId, Grants),
    /// The host turned follow mode on or off.
    Follow(bool),
    /// End arbitration and release everything held.
    Stop,
}

/// Input arbitration running for one host session.
pub struct InputHost {
    /// Lifecycle and control requests.
    control: mpsc::UnboundedSender<Command>,
    /// Viewer input messages.
    input: mpsc::Sender<(DeviceId, DataMessage)>,
    /// The latest status.
    status: watch::Receiver<InputStatus>,
    /// Input messages dropped because the queue was full.
    dropped: Arc<AtomicU64>,
    /// The arbitration task.
    task: JoinHandle<()>,
    /// Sends input states to viewers.
    sender: JoinHandle<()>,
}

impl InputHost {
    /// Starts injecting viewer input on this machine for `host`, using `share`
    /// for monitor geometry and follow mode.
    ///
    /// Fails with [`InputError::Unsupported`] off Windows and with
    /// [`InputError::Platform`] when host input detection cannot be set up.
    pub async fn start(host: HostSession, share: ShareHandle) -> Result<InputHost, InputError> {
        #[cfg(windows)]
        {
            let platform = WindowsPlatform::start()?;
            Ok(Self::start_with(host, share, platform))
        }
        #[cfg(not(windows))]
        {
            let _ = (host, share);
            Err(InputError::Unsupported)
        }
    }

    /// Starts arbitration on `platform` and sends input states through `host`.
    fn start_with<P: Platform, S: Share>(host: HostSession, share: S, platform: P) -> InputHost {
        let (control, control_rx) = mpsc::unbounded_channel();
        let (input, input_rx) = mpsc::channel(INPUT_CAPACITY);
        let (sends, mut sends_rx) = mpsc::unbounded_channel::<(DeviceId, InputState)>();
        let (status_tx, status) = watch::channel(InputStatus::default());
        let dropped = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn(run(
            platform,
            share,
            control_rx,
            input_rx,
            sends,
            status_tx,
            Arc::clone(&dropped),
        ));
        let sender = tokio::spawn(async move {
            while let Some((viewer, state)) = sends_rx.recv().await {
                let msg = DataMessage::Control(Control::InputState(state));
                if let Err(e) = host.send(viewer, &msg).await {
                    tracing::debug!(viewer = %viewer, error = %e, "input state not sent");
                }
            }
        });
        tracing::info!("remote input started");
        InputHost {
            control,
            input,
            status,
            dropped,
            task,
            sender,
        }
    }

    /// Takes a host session event: joins, leaves, input and follow requests.
    ///
    /// Other events are ignored. Input messages are dropped when the queue is full.
    pub fn handle_event(&self, event: &HostEvent) {
        match event {
            HostEvent::ViewerJoined { viewer } => {
                let _ = self.control.send(Command::Joined(*viewer));
            }
            HostEvent::ViewerLeft { viewer } => {
                let _ = self.control.send(Command::Left(*viewer));
            }
            HostEvent::DataReceived { viewer, message } => match message {
                DataMessage::PointerMove { .. }
                | DataMessage::PointerButton { .. }
                | DataMessage::Wheel { .. }
                | DataMessage::Key { .. } => {
                    enqueue(&self.input, &self.dropped, *viewer, message.clone());
                }
                DataMessage::Control(Control::SetFollow { .. }) => {
                    let _ = self.control.send(Command::Message(*viewer, message.clone()));
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// Sets what `viewer` may do; revoking releases what it holds.
    pub fn set_grants(&self, viewer: DeviceId, grants: Grants) {
        let _ = self.control.send(Command::Grants(viewer, grants));
    }

    /// Turns follow mode on or off for every viewer.
    pub fn set_follow(&self, on: bool) {
        let _ = self.control.send(Command::Follow(on));
    }

    /// Returns a receiver that sees every change of the input status.
    pub fn subscribe(&self) -> watch::Receiver<InputStatus> {
        self.status.clone()
    }

    /// Releases everything viewers hold, hides ghosts and ends arbitration.
    pub async fn stop(self) {
        let _ = self.control.send(Command::Stop);
        let _ = self.task.await;
        let _ = self.sender.await;
        tracing::info!("remote input stopped");
    }
}

/// Passes a host session event to the screen share and to input arbitration.
///
/// Monitor and quality requests go to the share, joins to both, and input,
/// follow requests and leaves to `input`.
pub fn route(event: &HostEvent, share: &ScreenShare, input: &InputHost) {
    match event {
        HostEvent::ViewerJoined { viewer } => {
            share.viewer_joined(*viewer);
            input.handle_event(event);
        }
        HostEvent::DataReceived {
            viewer,
            message: DataMessage::Control(control @ (Control::SelectMonitor { .. } | Control::SetQuality { .. })),
        } => share.handle_control(*viewer, control),
        _ => input.handle_event(event),
    }
}

/// Queues an input message, counting it in `dropped` when the queue is full;
/// returns whether it was queued.
fn enqueue(
    input: &mpsc::Sender<(DeviceId, DataMessage)>,
    dropped: &AtomicU64,
    viewer: DeviceId,
    message: DataMessage,
) -> bool {
    let queued = input.try_send((viewer, message)).is_ok();
    if !queued {
        dropped.fetch_add(1, Ordering::Relaxed);
    }
    queued
}

/// Returns the current time on the runtime's clock.
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// The arbitration task's state.
struct Runner<P: Platform, S: Share> {
    /// Injection and host signals.
    platform: P,
    /// Monitor geometry and selection.
    share: S,
    /// The arbiter.
    arbiter: Arbiter,
    /// Monitor geometry, refreshed every tick.
    geometry: Vec<MonitorRect>,
    /// Shown ghosts by viewer.
    ghosts: BTreeMap<DeviceId, (u8, i32, i32)>,
    /// Input states to send.
    sends: mpsc::UnboundedSender<(DeviceId, InputState)>,
    /// Publishes the status.
    status: watch::Sender<InputStatus>,
    /// The last host input instant passed to the arbiter.
    host_input: Option<Instant>,
    /// Sequence number of the last host mouse event handled.
    mouse_seq: u64,
    /// Sequence number of the last foreground change handled.
    foreground_seq: u64,
    /// Why host input detection stopped, once it has.
    degraded: Option<String>,
    /// Input messages handled since the last stats line.
    handled: u32,
    /// Longest handling time since the last stats line.
    slowest: Duration,
    /// When the last stats line was logged.
    stats_at: Instant,
}

impl<P: Platform, S: Share> Runner<P, S> {
    /// Reads the host signals and applies host input, follow focus and loss of detection.
    fn poll(&mut self, now: Instant) {
        if self.degraded.is_none() && !self.platform.alive() {
            tracing::error!("host input detection stopped; remote input is locked");
            self.degraded = Some("host input detection stopped".into());
            let out = self.arbiter.set_degraded(now);
            self.apply(out, now);
        }
        if let Some(at) = self.platform.host_input()
            && self.host_input != Some(at)
        {
            self.host_input = Some(at);
            let out = self.arbiter.host_input(at, now);
            self.apply(out, now);
        }
        if let Some((seq, x, y)) = self.platform.host_mouse()
            && seq != self.mouse_seq
        {
            self.mouse_seq = seq;
            self.focus(x, y, now);
        }
        if let Some((seq, x, y)) = self.platform.foreground()
            && seq != self.foreground_seq
        {
            self.foreground_seq = seq;
            self.focus(x, y, now);
        }
    }

    /// Follows the host's focus point `(x, y)` when follow mode is on.
    fn focus(&mut self, x: i32, y: i32, now: Instant) {
        let selected = self.share.selected();
        let out = self.arbiter.host_focus(x, y, &self.geometry, selected);
        self.apply(out, now);
    }

    /// Carries out the arbiter's actions and publishes a changed status.
    fn apply(&mut self, actions: Vec<Action>, now: Instant) {
        let mut ghosts_changed = false;
        for action in actions {
            match action {
                Action::Ghost { viewer, slot, at } => {
                    ghosts_changed = true;
                    match at {
                        Some((x, y)) => self.ghosts.insert(viewer, (slot, x, y)),
                        None => self.ghosts.remove(&viewer),
                    };
                }
                Action::Send(viewer, state) => {
                    let _ = self.sends.send((viewer, state));
                }
                Action::SelectMonitor(index) => self.share.select_monitor(index),
                input => self.platform.perform(&input),
            }
        }
        if ghosts_changed {
            self.platform.ghosts(self.ghosts.values().copied().collect());
        }
        let mut status = self.arbiter.status(now);
        status.degraded = self.degraded.clone();
        self.status.send_if_modified(|s| {
            let changed = *s != status;
            if changed {
                *s = status;
            }
            changed
        });
    }

    /// Applies a lifecycle or control command; returns false for [`Command::Stop`].
    fn command(&mut self, cmd: Command, now: Instant) -> bool {
        self.poll(now);
        let out = match cmd {
            Command::Joined(viewer) => self.arbiter.viewer_joined(viewer, now),
            Command::Left(viewer) => self.arbiter.viewer_left(viewer, now),
            Command::Message(viewer, msg) => self.arbiter.message(viewer, &msg, &self.geometry, now),
            Command::Grants(viewer, grants) => self.arbiter.set_grants(viewer, grants, now),
            Command::Follow(on) => self.arbiter.set_follow(on, now),
            Command::Stop => {
                let viewers: Vec<DeviceId> = self.arbiter.status(now).viewers.into_keys().collect();
                for viewer in viewers {
                    let out = self.arbiter.viewer_left(viewer, now);
                    self.apply(out, now);
                }
                return false;
            }
        };
        self.apply(out, now);
        true
    }

    /// Applies one viewer input message.
    fn input(&mut self, viewer: DeviceId, msg: &DataMessage, now: Instant) {
        let started = Instant::now();
        self.poll(now);
        let out = self.arbiter.message(viewer, msg, &self.geometry, now);
        self.apply(out, now);
        self.handled += 1;
        self.slowest = self.slowest.max(started.elapsed());
    }

    /// Refreshes geometry, polls the host signals, expires lockouts and ghosts,
    /// and logs stats when due.
    fn tick(&mut self, now: Instant, dropped: &AtomicU64) {
        self.geometry = self.share.geometry();
        self.poll(now);
        let out = self.arbiter.tick(now);
        self.apply(out, now);
        if now.duration_since(self.stats_at) >= STATS_INTERVAL {
            let dropped = dropped.swap(0, Ordering::Relaxed);
            if self.handled > 0 || dropped > 0 {
                tracing::debug!(
                    handled = self.handled,
                    dropped,
                    slowest_us = self.slowest.as_micros() as u64,
                    "remote input stats"
                );
            }
            self.handled = 0;
            self.slowest = Duration::ZERO;
            self.stats_at = now;
        }
    }
}

/// Runs arbitration until [`Command::Stop`] arrives or the host is dropped.
///
/// Lifecycle and control commands take priority over queued input, so a
/// viewer's join is applied before its first input.
async fn run<P: Platform, S: Share>(
    platform: P,
    share: S,
    mut control: mpsc::UnboundedReceiver<Command>,
    mut input: mpsc::Receiver<(DeviceId, DataMessage)>,
    sends: mpsc::UnboundedSender<(DeviceId, InputState)>,
    status: watch::Sender<InputStatus>,
    dropped: Arc<AtomicU64>,
) {
    let start = now();
    let geometry = share.geometry();
    let mut r = Runner {
        platform,
        share,
        arbiter: Arbiter::new(),
        geometry,
        ghosts: BTreeMap::new(),
        sends,
        status,
        host_input: None,
        mouse_seq: 0,
        foreground_seq: 0,
        degraded: None,
        handled: 0,
        slowest: Duration::ZERO,
        stats_at: start,
    };
    r.poll(start);
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            cmd = control.recv() => match cmd {
                Some(cmd) => {
                    if !r.command(cmd, now()) {
                        return;
                    }
                }
                None => {
                    r.command(Command::Stop, now());
                    return;
                }
            },
            Some((viewer, msg)) = input.recv() => r.input(viewer, &msg, now()),
            _ = ticker.tick() => r.tick(now(), &dropped),
        }
    }
}

/// The Windows host: SendInput injection plus the hook and overlay thread.
#[cfg(windows)]
struct WindowsPlatform {
    /// The hook and overlay thread.
    ui: crate::ui::UiThread,
    /// What the hooks observe.
    signals: Arc<crate::ui::Signals>,
    /// When the last injection warning was logged.
    warned_at: Option<Instant>,
}

#[cfg(windows)]
impl WindowsPlatform {
    /// Starts the hook and overlay thread.
    fn start() -> Result<WindowsPlatform, InputError> {
        let ui = crate::ui::UiThread::start(Instant::now()).map_err(InputError::Platform)?;
        let signals = ui.signals();
        Ok(WindowsPlatform {
            ui,
            signals,
            warned_at: None,
        })
    }
}

#[cfg(windows)]
impl Platform for WindowsPlatform {
    /// Injects `action`; blocked input is logged at most once per second.
    fn perform(&mut self, action: &Action) {
        if let Err(e) = crate::inject::perform(action) {
            let now = Instant::now();
            if self.warned_at.is_none_or(|at| now.duration_since(at) >= Duration::from_secs(1)) {
                self.warned_at = Some(now);
                tracing::warn!(error = %e, "remote input blocked");
            }
        }
    }

    /// Forwards to [`crate::ui::UiThread::set_ghosts`].
    fn ghosts(&mut self, ghosts: Vec<(u8, i32, i32)>) {
        self.ui.set_ghosts(ghosts);
    }

    /// Forwards to [`crate::ui::Signals::last_host_input`].
    fn host_input(&self) -> Option<Instant> {
        self.signals.last_host_input()
    }

    /// Forwards to [`crate::ui::Signals::host_mouse`].
    fn host_mouse(&self) -> Option<(u64, i32, i32)> {
        self.signals.host_mouse()
    }

    /// Forwards to [`crate::ui::Signals::foreground`].
    fn foreground(&self) -> Option<(u64, i32, i32)> {
        self.signals.foreground()
    }

    /// Forwards to [`crate::ui::Signals::alive`].
    fn alive(&self) -> bool {
        self.signals.alive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use surf_rac_protocol::data::MouseButton;

    use super::*;

    /// What the fake platform reports and records.
    #[derive(Default)]
    struct FakeState {
        /// Injected actions.
        performed: Vec<Action>,
        /// The last ghost list shown.
        ghosts: Vec<(u8, i32, i32)>,
        /// Reported host input.
        host_input: Option<Instant>,
        /// Reported host mouse event.
        host_mouse: Option<(u64, i32, i32)>,
        /// Whether detection is reported dead.
        dead: bool,
    }

    /// A platform backed by shared [`FakeState`].
    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<FakeState>>);

    impl Platform for Fake {
        /// Records the action.
        fn perform(&mut self, action: &Action) {
            self.0.lock().unwrap().performed.push(action.clone());
        }
        /// Records the ghosts.
        fn ghosts(&mut self, ghosts: Vec<(u8, i32, i32)>) {
            self.0.lock().unwrap().ghosts = ghosts;
        }
        /// Returns the configured host input.
        fn host_input(&self) -> Option<Instant> {
            self.0.lock().unwrap().host_input
        }
        /// Returns the configured host mouse event.
        fn host_mouse(&self) -> Option<(u64, i32, i32)> {
            self.0.lock().unwrap().host_mouse
        }
        /// Reports no foreground changes.
        fn foreground(&self) -> Option<(u64, i32, i32)> {
            None
        }
        /// Returns whether detection is configured alive.
        fn alive(&self) -> bool {
            !self.0.lock().unwrap().dead
        }
    }

    /// A share with two monitors side by side that records selections.
    #[derive(Clone, Default)]
    struct FakeShare(Arc<Mutex<Vec<u8>>>);

    impl Share for FakeShare {
        /// Returns two 1920x1080 monitors side by side.
        fn geometry(&self) -> Vec<MonitorRect> {
            vec![
                MonitorRect { left: 0, top: 0, width: 1920, height: 1080 },
                MonitorRect { left: 1920, top: 0, width: 1920, height: 1080 },
            ]
        }
        /// Returns the last selected monitor, 0 before any.
        fn selected(&self) -> u8 {
            self.0.lock().unwrap().last().copied().unwrap_or(0)
        }
        /// Records the selection.
        fn select_monitor(&self, index: u8) {
            self.0.lock().unwrap().push(index);
        }
    }

    /// Channels and fakes of a running arbitration task.
    struct Harness {
        /// Lifecycle and control requests.
        control: mpsc::UnboundedSender<Command>,
        /// Viewer input.
        input: mpsc::Sender<(DeviceId, DataMessage)>,
        /// Input states the task sent.
        sends: mpsc::UnboundedReceiver<(DeviceId, InputState)>,
        /// The published status.
        status: watch::Receiver<InputStatus>,
        /// The fake platform.
        fake: Fake,
        /// The fake share.
        share: FakeShare,
        /// The task.
        task: JoinHandle<()>,
    }

    /// Starts the arbitration task on fakes.
    fn harness() -> Harness {
        let fake = Fake::default();
        let share = FakeShare::default();
        let (control, control_rx) = mpsc::unbounded_channel();
        let (input, input_rx) = mpsc::channel(INPUT_CAPACITY);
        let (sends_tx, sends) = mpsc::unbounded_channel();
        let (status_tx, status) = watch::channel(InputStatus::default());
        let task = tokio::spawn(run(
            fake.clone(),
            share.clone(),
            control_rx,
            input_rx,
            sends_tx,
            status_tx,
            Arc::new(AtomicU64::new(0)),
        ));
        Harness { control, input, sends, status, fake, share, task }
    }

    /// Returns a test device ID.
    fn v(n: u32) -> DeviceId {
        DeviceId::new(100_000_000 + n).unwrap()
    }

    /// Lets the task run until it is idle.
    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    /// Returns every input state sent so far.
    fn drain(h: &mut Harness) -> Vec<(DeviceId, InputState)> {
        std::iter::from_fn(|| h.sends.try_recv().ok()).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn host_input_before_message_blocks_it() {
        let mut h = harness();
        h.control.send(Command::Joined(v(1))).unwrap();
        settle().await;
        assert!(!drain(&mut h)[0].1.locked);
        h.fake.0.lock().unwrap().host_input = Some(now());
        let down = DataMessage::PointerButton { button: MouseButton::Left, down: true };
        h.input.send((v(1), down)).await.unwrap();
        settle().await;
        assert!(h.fake.0.lock().unwrap().performed.is_empty());
        assert!(drain(&mut h).iter().any(|(_, s)| s.locked));
        assert!(h.status.borrow().locked);
    }

    #[tokio::test(start_paused = true)]
    async fn lockout_ends_via_tick() {
        let mut h = harness();
        h.control.send(Command::Joined(v(1))).unwrap();
        h.fake.0.lock().unwrap().host_input = Some(now());
        settle().await;
        drain(&mut h);
        tokio::time::sleep(crate::arbiter::LOCKOUT + TICK).await;
        settle().await;
        let sent = drain(&mut h);
        assert_eq!(sent.last().map(|(_, s)| s.locked), Some(false));
        assert!(!h.status.borrow().locked);
    }

    #[tokio::test(start_paused = true)]
    async fn follow_selects_through_share() {
        let h = harness();
        h.control.send(Command::Joined(v(1))).unwrap();
        h.control
            .send(Command::Message(v(1), DataMessage::Control(Control::SetFollow { on: true })))
            .unwrap();
        settle().await;
        assert!(h.status.borrow().follow);
        h.fake.0.lock().unwrap().host_mouse = Some((1, 2500, 300));
        tokio::time::sleep(TICK * 2).await;
        settle().await;
        assert_eq!(*h.share.0.lock().unwrap(), [1]);
    }

    #[tokio::test(start_paused = true)]
    async fn dead_platform_degrades() {
        let h = harness();
        h.control.send(Command::Joined(v(1))).unwrap();
        settle().await;
        h.fake.0.lock().unwrap().dead = true;
        tokio::time::sleep(TICK * 2).await;
        settle().await;
        let status = h.status.borrow().clone();
        assert!(status.locked);
        assert!(status.degraded.is_some());
        h.input.send((v(1), DataMessage::Key { code: 0x1E, down: true })).await.unwrap();
        settle().await;
        assert!(h.fake.0.lock().unwrap().performed.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn ghosts_reach_platform_and_stop_releases() {
        let h = harness();
        h.control.send(Command::Joined(v(1))).unwrap();
        h.control.send(Command::Grants(v(1), Grants { pointer: false, keyboard: true })).unwrap();
        settle().await;
        h.input.send((v(1), DataMessage::PointerMove { x: 10, y: 20, monitor: 1 })).await.unwrap();
        h.input.send((v(1), DataMessage::Key { code: 0x2A, down: true })).await.unwrap();
        settle().await;
        assert_eq!(h.fake.0.lock().unwrap().ghosts, [(0, 1930, 20)]);
        h.control.send(Command::Stop).unwrap();
        h.task.await.unwrap();
        let state = h.fake.0.lock().unwrap();
        assert!(state.ghosts.is_empty());
        assert_eq!(state.performed.last(), Some(&Action::Key { code: 0x2A, down: false }));
    }

    #[tokio::test]
    async fn full_channel_drops() {
        let (tx, _rx) = mpsc::channel(INPUT_CAPACITY);
        let dropped = AtomicU64::new(0);
        let msg = DataMessage::Wheel { dx: 0, dy: 120 };
        for _ in 0..INPUT_CAPACITY {
            assert!(enqueue(&tx, &dropped, v(1), msg.clone()));
        }
        assert!(!enqueue(&tx, &dropped, v(1), msg));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }
}
