//! Platform-independent input arbitration: decides what to inject, which
//! ghost pointers to show and which input states to send.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use surf_rac_capture::MonitorRect;
use surf_rac_protocol::DeviceId;
use surf_rac_protocol::data::{Control, DataMessage, InputState, MouseButton};

/// How long physical host input locks out all remote input.
pub const LOCKOUT: Duration = Duration::from_secs(5);

/// How long a ghost pointer stays visible after its last move or click.
pub const GHOST_TIMEOUT: Duration = Duration::from_secs(3);

/// Largest wheel amount per message and axis, in units of 120 per notch.
pub const MAX_WHEEL: i32 = 1200;

/// Largest valid key code: a set-1 scan code with the extended flag `0x100`.
pub const MAX_KEY_CODE: u32 = 0x1FF;

/// Every pointer button, in the order holds are released.
const BUTTONS: [MouseButton; 5] = [
    MouseButton::Left,
    MouseButton::Right,
    MouseButton::Middle,
    MouseButton::Back,
    MouseButton::Forward,
];

/// What a viewer may do with the host's input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grants {
    /// Move, click and scroll with the real cursor.
    pub pointer: bool,
    /// Type.
    pub keyboard: bool,
    /// Have the pointer injected or shown as a ghost at all; when off, moves,
    /// clicks and scrolls are dropped whatever `pointer` says.
    pub pointing: bool,
}

impl Grants {
    /// Returns whether the pointer may move, click and scroll with the real cursor.
    fn controls_pointer(self) -> bool {
        self.pointer && self.pointing
    }
}

impl Default for Grants {
    /// Returns grants with pointer, keyboard and pointing all allowed.
    fn default() -> Grants {
        Grants {
            pointer: true,
            keyboard: true,
            pointing: true,
        }
    }
}

/// Something the host must do as a result of an arbiter call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Move the cursor to an absolute desktop pixel.
    Move {
        /// Horizontal desktop position.
        x: i32,
        /// Vertical desktop position.
        y: i32,
    },
    /// Press or release a pointer button.
    Button {
        /// Which button.
        button: MouseButton,
        /// True to press, false to release.
        down: bool,
    },
    /// Scroll, in units of 120 per notch.
    Wheel {
        /// Horizontal amount.
        dx: i32,
        /// Vertical amount.
        dy: i32,
    },
    /// Press or release a key.
    Key {
        /// Set-1 scan code, with `0x100` for extended keys.
        code: u16,
        /// True to press, false to release.
        down: bool,
    },
    /// Show a viewer's ghost pointer at a desktop pixel, or hide it.
    Ghost {
        /// The viewer.
        viewer: DeviceId,
        /// The viewer's color slot.
        slot: u8,
        /// Desktop position, `None` to hide.
        at: Option<(i32, i32)>,
        /// Whether the viewer clicked at this position.
        click: bool,
    },
    /// Send a viewer its input state.
    Send(DeviceId, InputState),
    /// Make the monitor with this index the shared selected monitor.
    SelectMonitor(u8),
}

/// A viewer's grants and ghost color slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewerStatus {
    /// What the viewer may do.
    pub grants: Grants,
    /// The color slot of its ghost pointer.
    pub slot: u8,
}

/// The input status the host shows its user.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InputStatus {
    /// Every connected viewer.
    pub viewers: BTreeMap<DeviceId, ViewerStatus>,
    /// Whether remote input is locked out.
    pub locked: bool,
    /// Whether follow mode is on.
    pub follow: bool,
    /// Why remote input is permanently disabled, when it is.
    pub degraded: Option<String>,
}

/// One connected viewer.
#[derive(Debug, Clone)]
struct Viewer {
    /// What the viewer may do.
    grants: Grants,
    /// Ghost color slot.
    slot: u8,
    /// The input state last sent to the viewer.
    sent: Option<InputState>,
    /// When its visible ghost pointer expires; `None` while hidden.
    ghost_until: Option<Instant>,
    /// Desktop position of its last valid pointer move.
    last_at: Option<(i32, i32)>,
}

/// Merges input from several viewers and decides what reaches the host.
///
/// Keys and buttons are reference counted across viewers: a press is injected
/// for the first holder (and again for repeats of the same holder), a release
/// only when the last holder lets go. Physical host input locks out remote
/// input for [`LOCKOUT`] and releases everything remote viewers hold.
#[derive(Debug, Default)]
pub struct Arbiter {
    /// Connected viewers.
    viewers: BTreeMap<DeviceId, Viewer>,
    /// Viewers holding each key down.
    keys: BTreeMap<u16, BTreeSet<DeviceId>>,
    /// Viewers holding each button down, indexed like [`BUTTONS`].
    buttons: [BTreeSet<DeviceId>; 5],
    /// When the current lockout ends.
    lock_until: Option<Instant>,
    /// Whether host input detection failed, which locks remote input for good.
    degraded: bool,
    /// Whether follow mode is on.
    follow: bool,
    /// Messages dropped as invalid since the last [`Arbiter::take_invalid`].
    invalid: u64,
}

impl Arbiter {
    /// Creates an arbiter with no viewers, no lockout and follow off.
    pub fn new() -> Arbiter {
        Arbiter::default()
    }

    /// Adds `viewer` with both grants and the lowest free ghost slot, and sends it its state.
    ///
    /// A viewer that is already known only gets its state again if it changed.
    pub fn viewer_joined(&mut self, viewer: DeviceId, now: Instant) -> Vec<Action> {
        if !self.viewers.contains_key(&viewer) {
            let used: BTreeSet<u8> = self.viewers.values().map(|v| v.slot).collect();
            let slot = (0..=u8::MAX).find(|s| !used.contains(s)).unwrap_or(u8::MAX);
            self.viewers.insert(
                viewer,
                Viewer {
                    grants: Grants::default(),
                    slot,
                    sent: None,
                    ghost_until: None,
                    last_at: None,
                },
            );
        }
        self.sync(now)
    }

    /// Removes `viewer`, releasing everything it holds and hiding its ghost.
    pub fn viewer_left(&mut self, viewer: DeviceId, now: Instant) -> Vec<Action> {
        let Some(gone) = self.viewers.remove(&viewer) else {
            return Vec::new();
        };
        let mut out = self.release_viewer(viewer, true, true);
        if gone.ghost_until.is_some() {
            out.push(Action::Ghost {
                viewer,
                slot: gone.slot,
                at: None,
                click: false,
            });
        }
        out.extend(self.sync(now));
        out
    }

    /// Sets `viewer`'s grants; a revoked grant releases what the viewer holds
    /// under it, and revoking pointing hides its ghost at once.
    pub fn set_grants(&mut self, viewer: DeviceId, grants: Grants, now: Instant) -> Vec<Action> {
        let Some(v) = self.viewers.get_mut(&viewer) else {
            return Vec::new();
        };
        let old = std::mem::replace(&mut v.grants, grants);
        let mut out = Vec::new();
        if !grants.pointing && v.ghost_until.take().is_some() {
            out.push(Action::Ghost {
                viewer,
                slot: v.slot,
                at: None,
                click: false,
            });
        }
        out.extend(self.release_viewer(
            viewer,
            old.keyboard && !grants.keyboard,
            old.controls_pointer() && !grants.controls_pointer(),
        ));
        out.extend(self.sync(now));
        out
    }

    /// Turns follow mode on or off.
    pub fn set_follow(&mut self, on: bool, now: Instant) -> Vec<Action> {
        self.follow = on;
        self.sync(now)
    }

    /// Locks out remote input for good because host input can no longer be detected.
    pub fn set_degraded(&mut self, now: Instant) -> Vec<Action> {
        if self.degraded {
            return Vec::new();
        }
        let was_locked = self.locked(now);
        self.degraded = true;
        let mut out = if was_locked { Vec::new() } else { self.release_all() };
        out.extend(self.sync(now));
        out
    }

    /// Records physical host input at `at`, locking out remote input until `at + LOCKOUT`.
    ///
    /// When a lockout starts, everything remote viewers hold is released.
    pub fn host_input(&mut self, at: Instant, now: Instant) -> Vec<Action> {
        let until = at + LOCKOUT;
        if self.lock_until.is_some_and(|t| until <= t) {
            return Vec::new();
        }
        let was_locked = self.locked(now);
        self.lock_until = Some(until);
        let mut out = Vec::new();
        if !was_locked && self.locked(now) {
            out = self.release_all();
        }
        out.extend(self.sync(now));
        out
    }

    /// Selects the monitor containing the host's focus point `(x, y)` when
    /// follow mode is on and it is not already `selected`.
    pub fn host_focus(&mut self, x: i32, y: i32, geometry: &[MonitorRect], selected: u8) -> Vec<Action> {
        if !self.follow {
            return Vec::new();
        }
        match geometry.iter().position(|r| r.contains(x, y)) {
            Some(i) if i != usize::from(selected) && i <= usize::from(u8::MAX) => {
                vec![Action::SelectMonitor(i as u8)]
            }
            _ => Vec::new(),
        }
    }

    /// Applies a data message from `viewer`.
    ///
    /// `geometry` holds the desktop rectangle of each monitor, indexed like the
    /// screen state's monitors. Moves on unknown monitors, oversized key codes
    /// and input the viewer may not give are dropped. Without pointing, moves,
    /// clicks and scrolls are dropped. Moves and button presses the viewer may
    /// not inject become ghost pointer moves and ghost clicks.
    pub fn message(&mut self, viewer: DeviceId, msg: &DataMessage, geometry: &[MonitorRect], now: Instant) -> Vec<Action> {
        let Some(v) = self.viewers.get(&viewer) else {
            self.invalid += 1;
            return Vec::new();
        };
        let grants = v.grants;
        let locked = self.locked(now);
        let pointer = grants.controls_pointer() && !locked;
        let mut out = Vec::new();
        match *msg {
            DataMessage::PointerMove { x, y, monitor } => {
                let Some(at) = geometry.get(usize::from(monitor)).and_then(|r| clamp(r, x, y)) else {
                    self.invalid += 1;
                    return out;
                };
                let v = self.viewers.get_mut(&viewer).expect("viewer checked above");
                if !grants.pointing {
                    return out;
                }
                v.last_at = Some(at);
                if pointer {
                    if v.ghost_until.take().is_some() {
                        out.push(Action::Ghost {
                            viewer,
                            slot: v.slot,
                            at: None,
                            click: false,
                        });
                    }
                    out.push(Action::Move { x: at.0, y: at.1 });
                } else {
                    v.ghost_until = Some(now + GHOST_TIMEOUT);
                    out.push(Action::Ghost {
                        viewer,
                        slot: v.slot,
                        at: Some(at),
                        click: false,
                    });
                }
            }
            DataMessage::PointerButton { button, down } if pointer => {
                let i = button_index(button);
                if let Some(down) = hold(&mut self.buttons[i], viewer, down) {
                    out.push(Action::Button { button, down });
                }
            }
            DataMessage::PointerButton { down: true, .. } if grants.pointing => {
                let v = self.viewers.get_mut(&viewer).expect("viewer checked above");
                if let Some(at) = v.last_at {
                    v.ghost_until = Some(now + GHOST_TIMEOUT);
                    out.push(Action::Ghost {
                        viewer,
                        slot: v.slot,
                        at: Some(at),
                        click: true,
                    });
                }
            }
            DataMessage::Wheel { dx, dy } if pointer => {
                let (dx, dy) = (dx.clamp(-MAX_WHEEL, MAX_WHEEL), dy.clamp(-MAX_WHEEL, MAX_WHEEL));
                if dx != 0 || dy != 0 {
                    out.push(Action::Wheel { dx, dy });
                }
            }
            DataMessage::Key { code, down } if code <= MAX_KEY_CODE && grants.keyboard && !locked => {
                let code = code as u16;
                if let Some(down) = hold(self.keys.entry(code).or_default(), viewer, down) {
                    out.push(Action::Key { code, down });
                }
                self.keys.retain(|_, holders| !holders.is_empty());
            }
            DataMessage::Key { code, .. } if code > MAX_KEY_CODE => self.invalid += 1,
            DataMessage::Control(Control::SetFollow { on }) => self.follow = on,
            _ => {}
        }
        out.extend(self.sync(now));
        out
    }

    /// Ends expired lockouts and ghost pointers.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        for (&viewer, v) in &mut self.viewers {
            if v.ghost_until.is_some_and(|t| now >= t) {
                v.ghost_until = None;
                out.push(Action::Ghost {
                    viewer,
                    slot: v.slot,
                    at: None,
                    click: false,
                });
            }
        }
        out.extend(self.sync(now));
        out
    }

    /// Returns how many messages were dropped as invalid (unknown viewer, unknown
    /// monitor, oversized key code) since the last call, and resets the count.
    pub fn take_invalid(&mut self) -> u64 {
        std::mem::take(&mut self.invalid)
    }

    /// Returns the current status; `degraded` is left `None` for the caller to fill in.
    pub fn status(&self, now: Instant) -> InputStatus {
        InputStatus {
            viewers: self
                .viewers
                .iter()
                .map(|(&id, v)| {
                    (
                        id,
                        ViewerStatus {
                            grants: v.grants,
                            slot: v.slot,
                        },
                    )
                })
                .collect(),
            locked: self.locked(now),
            follow: self.follow,
            degraded: None,
        }
    }

    /// Returns whether remote input is locked out at `now`.
    fn locked(&self, now: Instant) -> bool {
        self.degraded || self.lock_until.is_some_and(|t| now < t)
    }

    /// Sends each viewer its input state where it differs from the last one sent.
    fn sync(&mut self, now: Instant) -> Vec<Action> {
        let locked = self.locked(now);
        let follow = self.follow;
        let mut out = Vec::new();
        for (&viewer, v) in &mut self.viewers {
            let state = InputState {
                pointer: v.grants.pointer,
                keyboard: v.grants.keyboard,
                locked,
                follow,
                pointing: v.grants.pointing,
            };
            if v.sent != Some(state) {
                v.sent = Some(state);
                out.push(Action::Send(viewer, state));
            }
        }
        out
    }

    /// Releases every key and button any viewer holds.
    fn release_all(&mut self) -> Vec<Action> {
        let mut out: Vec<Action> = std::mem::take(&mut self.keys)
            .into_keys()
            .map(|code| Action::Key { code, down: false })
            .collect();
        for (i, holders) in self.buttons.iter_mut().enumerate() {
            if !std::mem::take(holders).is_empty() {
                out.push(Action::Button {
                    button: BUTTONS[i],
                    down: false,
                });
            }
        }
        out
    }

    /// Drops `viewer` from the holders of keys (when `keys`) and buttons (when
    /// `buttons`), releasing those nobody holds anymore.
    fn release_viewer(&mut self, viewer: DeviceId, keys: bool, buttons: bool) -> Vec<Action> {
        let mut out = Vec::new();
        if keys {
            for (&code, holders) in &mut self.keys {
                if holders.remove(&viewer) && holders.is_empty() {
                    out.push(Action::Key { code, down: false });
                }
            }
            self.keys.retain(|_, holders| !holders.is_empty());
        }
        if buttons {
            for (i, holders) in self.buttons.iter_mut().enumerate() {
                if holders.remove(&viewer) && holders.is_empty() {
                    out.push(Action::Button {
                        button: BUTTONS[i],
                        down: false,
                    });
                }
            }
        }
        out
    }
}

/// Applies a press (`down`) or release by `viewer` to the holders of one key
/// or button; returns the press or release to inject, if any.
fn hold(holders: &mut BTreeSet<DeviceId>, viewer: DeviceId, down: bool) -> Option<bool> {
    if down {
        let first = holders.is_empty();
        let repeat = !holders.insert(viewer);
        (first || repeat).then_some(true)
    } else {
        (holders.remove(&viewer) && holders.is_empty()).then_some(false)
    }
}

/// Returns the index of `button` in [`BUTTONS`].
fn button_index(button: MouseButton) -> usize {
    BUTTONS.iter().position(|b| *b == button).expect("every button is listed")
}

/// Clamps monitor pixel `(x, y)` into `rect` and returns it as a desktop
/// pixel; `None` for an empty monitor.
fn clamp(rect: &MonitorRect, x: i32, y: i32) -> Option<(i32, i32)> {
    let w = i32::try_from(rect.width).ok().filter(|w| *w > 0)?;
    let h = i32::try_from(rect.height).ok().filter(|h| *h > 0)?;
    Some((
        rect.left.saturating_add(x.clamp(0, w - 1)),
        rect.top.saturating_add(y.clamp(0, h - 1)),
    ))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use surf_rac_capture::MonitorRect;
    use surf_rac_protocol::DeviceId;
    use surf_rac_protocol::data::{Control, DataMessage, InputState, MouseButton};

    use super::*;

    /// Returns a test device ID.
    fn v(n: u32) -> DeviceId {
        DeviceId::new(100_000_000 + n).unwrap()
    }

    /// Returns a primary 1920x1080 monitor and a 1280x1024 one to its right, 100 px higher.
    fn geo() -> Vec<MonitorRect> {
        vec![
            MonitorRect { left: 0, top: 0, width: 1920, height: 1080 },
            MonitorRect { left: 1920, top: -100, width: 1280, height: 1024 },
        ]
    }

    /// Returns a key message.
    fn key(code: u32, down: bool) -> DataMessage {
        DataMessage::Key { code, down }
    }

    /// Returns a button message.
    fn button(button: MouseButton, down: bool) -> DataMessage {
        DataMessage::PointerButton { button, down }
    }

    /// Returns a move message.
    fn mv(x: i32, y: i32, monitor: u8) -> DataMessage {
        DataMessage::PointerMove { x, y, monitor }
    }

    /// Returns the input state viewers get with default grants.
    fn state(locked: bool, follow: bool) -> InputState {
        InputState { pointer: true, keyboard: true, locked, follow, pointing: true }
    }

    /// Returns an arbiter with viewers 1 and 2 joined, and the time they joined.
    fn two() -> (Arbiter, Instant) {
        let t0 = Instant::now();
        let mut a = Arbiter::new();
        a.viewer_joined(v(1), t0);
        a.viewer_joined(v(2), t0);
        (a, t0)
    }

    #[test]
    fn join_sends_state_and_grants_default_on() {
        let t0 = Instant::now();
        let mut a = Arbiter::new();
        assert_eq!(a.viewer_joined(v(1), t0), [Action::Send(v(1), state(false, false))]);
        assert_eq!(a.viewer_joined(v(1), t0), []);
        let status = a.status(t0);
        assert_eq!(status.viewers[&v(1)], ViewerStatus { grants: Grants::default(), slot: 0 });
        assert!(Grants::default().pointer && Grants::default().keyboard && Grants::default().pointing);
    }

    /// Returns grants with clicks and keyboard on and pointing off.
    fn not_pointing() -> Grants {
        Grants { pointer: true, keyboard: true, pointing: false }
    }

    /// Checks that a viewer without pointing has its moves, clicks and
    /// scrolls dropped, keeps its keyboard and is told pointing is off.
    #[test]
    fn without_pointing_pointer_input_is_dropped() {
        let (mut a, t0) = two();
        assert_eq!(
            a.set_grants(v(1), not_pointing(), t0),
            [Action::Send(v(1), InputState { pointing: false, ..state(false, false) })]
        );
        assert_eq!(a.message(v(1), &mv(5, 5, 0), &geo(), t0), []);
        assert_eq!(a.message(v(1), &button(MouseButton::Left, true), &geo(), t0), []);
        assert_eq!(a.message(v(1), &button(MouseButton::Left, false), &geo(), t0), []);
        assert_eq!(a.message(v(1), &DataMessage::Wheel { dx: 0, dy: 120 }, &geo(), t0), []);
        assert_eq!(a.message(v(1), &key(0x1E, true), &geo(), t0), [Action::Key { code: 0x1E, down: true }]);
        assert_eq!(a.take_invalid(), 0, "dropped pointer input is not invalid");
        assert!(!a.status(t0).viewers[&v(1)].grants.pointing);
    }

    /// Checks that a viewer without pointing shows no ghost while locked out.
    #[test]
    fn without_pointing_no_ghost_during_lockout() {
        let (mut a, t0) = two();
        a.set_grants(v(1), not_pointing(), t0);
        a.host_input(t0, t0);
        assert_eq!(a.message(v(1), &mv(5, 5, 0), &geo(), t0), []);
        assert_eq!(a.message(v(1), &button(MouseButton::Left, true), &geo(), t0), []);
    }

    /// Checks that revoking pointing hides the viewer's ghost at once and
    /// releases the buttons it holds.
    #[test]
    fn revoking_pointing_hides_ghost_and_releases_buttons() {
        let (mut a, t0) = two();
        a.message(v(2), &button(MouseButton::Middle, true), &geo(), t0);
        a.set_grants(v(1), Grants { pointer: false, keyboard: true, pointing: true }, t0);
        a.message(v(1), &mv(7, 8, 0), &geo(), t0);
        assert_eq!(
            a.set_grants(v(1), Grants { pointer: false, keyboard: true, pointing: false }, t0),
            [
                Action::Ghost { viewer: v(1), slot: 0, at: None, click: false },
                Action::Send(v(1), InputState { pointer: false, pointing: false, ..state(false, false) }),
            ]
        );
        assert_eq!(a.tick(t0 + GHOST_TIMEOUT), [], "the ghost is already hidden");
        assert_eq!(
            a.set_grants(v(2), not_pointing(), t0),
            [
                Action::Button { button: MouseButton::Middle, down: false },
                Action::Send(v(2), InputState { pointing: false, ..state(false, false) }),
            ]
        );
    }

    /// Checks that restoring pointing lets moves through again.
    #[test]
    fn restoring_pointing_injects_again() {
        let (mut a, t0) = two();
        a.set_grants(v(1), not_pointing(), t0);
        a.set_grants(v(1), Grants::default(), t0);
        assert_eq!(a.message(v(1), &mv(9, 9, 0), &geo(), t0), [Action::Move { x: 9, y: 9 }]);
    }

    /// Checks that pointing is on for each joining viewer, also after a
    /// viewer with pointing off left and joined again.
    #[test]
    fn pointing_is_on_for_each_join() {
        let (mut a, t0) = two();
        a.set_grants(v(1), not_pointing(), t0);
        a.viewer_left(v(1), t0);
        assert_eq!(a.viewer_joined(v(1), t0), [Action::Send(v(1), state(false, false))]);
        assert!(a.status(t0).viewers[&v(1)].grants.pointing);
    }

    /// Checks that a press that is not injected becomes a ghost click at the
    /// last position, refreshing the ghost's timeout, while releases and
    /// other buttons' releases stay silent.
    #[test]
    fn ghost_click_refreshes_timeout() {
        let (mut a, t0) = two();
        a.set_grants(v(1), Grants { pointer: false, keyboard: true, pointing: true }, t0);
        a.message(v(1), &mv(40, 50, 0), &geo(), t0);
        let t1 = t0 + Duration::from_secs(2);
        assert_eq!(
            a.message(v(1), &button(MouseButton::Right, true), &geo(), t1),
            [Action::Ghost { viewer: v(1), slot: 0, at: Some((40, 50)), click: true }]
        );
        assert_eq!(a.message(v(1), &button(MouseButton::Right, false), &geo(), t1), []);
        assert_eq!(a.tick(t0 + GHOST_TIMEOUT), [], "the click kept the ghost visible");
        assert_eq!(
            a.tick(t1 + GHOST_TIMEOUT),
            [Action::Ghost { viewer: v(1), slot: 0, at: None, click: false }]
        );
    }

    /// Checks that a ghost click during a lockout shows at the position of
    /// the last injected move, and that a press before any move shows nothing.
    #[test]
    fn ghost_click_during_lockout_uses_last_position() {
        let (mut a, t0) = two();
        assert_eq!(a.message(v(2), &button(MouseButton::Left, true), &geo(), t0).len(), 1);
        a.message(v(1), &mv(1930, 20, 0), &geo(), t0);
        a.host_input(t0, t0);
        assert_eq!(
            a.message(v(1), &button(MouseButton::Left, true), &geo(), t0),
            [Action::Ghost { viewer: v(1), slot: 0, at: Some((1919, 20)), click: true }]
        );
        assert_eq!(a.message(v(2), &button(MouseButton::Left, true), &geo(), t0), []);
    }

    #[test]
    fn move_maps_to_desktop_and_clamps() {
        let (mut a, t0) = two();
        assert_eq!(a.message(v(1), &mv(10, 20, 1), &geo(), t0), [Action::Move { x: 1930, y: -80 }]);
        assert_eq!(a.message(v(1), &mv(-5, 5000, 1), &geo(), t0), [Action::Move { x: 1920, y: 923 }]);
        assert_eq!(a.message(v(1), &mv(99999, -1, 0), &geo(), t0), [Action::Move { x: 1919, y: 0 }]);
    }

    #[test]
    fn move_on_unknown_monitor_dropped() {
        let (mut a, t0) = two();
        assert_eq!(a.message(v(1), &mv(1, 1, 2), &geo(), t0), []);
        assert_eq!(a.message(v(1), &mv(1, 1, 1), &geo()[..1], t0), []);
    }

    #[test]
    fn unknown_viewer_dropped() {
        let (mut a, t0) = two();
        assert_eq!(a.message(v(9), &key(0x1E, true), &geo(), t0), []);
    }

    #[test]
    fn shared_key_released_by_last_holder() {
        let (mut a, t0) = two();
        let shift = key(0x2A, true);
        assert_eq!(a.message(v(1), &shift, &geo(), t0), [Action::Key { code: 0x2A, down: true }]);
        assert_eq!(a.message(v(2), &shift, &geo(), t0), []);
        assert_eq!(a.viewer_left(v(1), t0), []);
        assert_eq!(
            a.message(v(2), &key(0x2A, false), &geo(), t0),
            [Action::Key { code: 0x2A, down: false }]
        );
        assert_eq!(a.message(v(2), &key(0x2A, false), &geo(), t0), []);
    }

    #[test]
    fn repeat_down_from_same_viewer_injected() {
        let (mut a, t0) = two();
        let down = Action::Key { code: 0x11E, down: true };
        assert_eq!(a.message(v(1), &key(0x11E, true), &geo(), t0), std::slice::from_ref(&down));
        assert_eq!(a.message(v(1), &key(0x11E, true), &geo(), t0), [down]);
    }

    #[test]
    fn leave_releases_holds() {
        let (mut a, t0) = two();
        a.message(v(1), &key(0x1D, true), &geo(), t0);
        a.message(v(1), &button(MouseButton::Left, true), &geo(), t0);
        a.message(v(1), &mv(5, 5, 0), &geo(), t0);
        assert_eq!(
            a.viewer_left(v(1), t0),
            [
                Action::Key { code: 0x1D, down: false },
                Action::Button { button: MouseButton::Left, down: false },
            ]
        );
        assert!(!a.status(t0).viewers.contains_key(&v(1)));
    }

    #[test]
    fn revoke_pointer_releases_buttons_and_ghosts_moves() {
        let (mut a, t0) = two();
        a.message(v(1), &button(MouseButton::Right, true), &geo(), t0);
        a.message(v(1), &key(0x10, true), &geo(), t0);
        let grants = Grants { pointer: false, keyboard: true, pointing: true };
        assert_eq!(
            a.set_grants(v(1), grants, t0),
            [
                Action::Button { button: MouseButton::Right, down: false },
                Action::Send(v(1), InputState { pointer: false, keyboard: true, locked: false, follow: false, pointing: true }),
            ]
        );
        assert_eq!(
            a.message(v(1), &mv(100, 200, 0), &geo(), t0),
            [Action::Ghost { viewer: v(1), slot: 0, at: Some((100, 200)), click: false }]
        );
        assert_eq!(
            a.message(v(1), &button(MouseButton::Left, true), &geo(), t0),
            [Action::Ghost { viewer: v(1), slot: 0, at: Some((100, 200)), click: true }]
        );
        assert_eq!(a.message(v(1), &button(MouseButton::Left, false), &geo(), t0), []);
        assert_eq!(a.message(v(1), &DataMessage::Wheel { dx: 0, dy: 120 }, &geo(), t0), []);
        assert_eq!(a.message(v(1), &key(0x10, false), &geo(), t0), [Action::Key { code: 0x10, down: false }]);
    }

    #[test]
    fn revoke_keyboard_releases_keys() {
        let (mut a, t0) = two();
        a.message(v(2), &key(0x2A, true), &geo(), t0);
        let out = a.set_grants(v(2), Grants { pointer: true, keyboard: false, pointing: true }, t0);
        assert_eq!(out[0], Action::Key { code: 0x2A, down: false });
        assert_eq!(a.message(v(2), &key(0x1E, true), &geo(), t0), []);
        assert_eq!(a.set_grants(v(9), Grants::default(), t0), []);
    }

    #[test]
    fn real_move_clears_ghost() {
        let (mut a, t0) = two();
        a.set_grants(v(2), Grants { pointer: false, keyboard: true, pointing: true }, t0);
        a.message(v(2), &mv(1, 1, 0), &geo(), t0);
        a.set_grants(v(2), Grants::default(), t0);
        assert_eq!(
            a.message(v(2), &mv(2, 2, 0), &geo(), t0),
            [Action::Ghost { viewer: v(2), slot: 1, at: None, click: false }, Action::Move { x: 2, y: 2 }]
        );
    }

    #[test]
    fn lockout_releases_and_swallows_late_up() {
        let (mut a, t0) = two();
        a.message(v(1), &button(MouseButton::Left, true), &geo(), t0);
        let t1 = t0 + Duration::from_millis(10);
        assert_eq!(
            a.host_input(t1, t1),
            [
                Action::Button { button: MouseButton::Left, down: false },
                Action::Send(v(1), state(true, false)),
                Action::Send(v(2), state(true, false)),
            ]
        );
        assert_eq!(a.message(v(1), &button(MouseButton::Left, false), &geo(), t1), []);
        assert_eq!(a.message(v(2), &key(0x1E, true), &geo(), t1), []);
        assert_eq!(
            a.message(v(1), &mv(3, 4, 0), &geo(), t1),
            [Action::Ghost { viewer: v(1), slot: 0, at: Some((3, 4)), click: false }]
        );
    }

    #[test]
    fn lockout_ends_after_exactly_five_seconds() {
        let (mut a, t0) = two();
        a.host_input(t0, t0);
        let t2 = t0 + Duration::from_secs(2);
        assert_eq!(a.host_input(t2, t2), []);
        assert_eq!(a.tick(t2 + Duration::from_millis(4999)), []);
        let end = t2 + LOCKOUT;
        assert_eq!(
            a.tick(end),
            [Action::Send(v(1), state(false, false)), Action::Send(v(2), state(false, false))]
        );
        assert_eq!(a.message(v(1), &key(0x1E, true), &geo(), end), [Action::Key { code: 0x1E, down: true }]);
        assert_eq!(a.host_input(t0, end), [], "stale host input does not lock again");
    }

    /// Checks that a ghost hides exactly [`GHOST_TIMEOUT`] after its last move,
    /// and that a leaving viewer's ghost is hidden.
    #[test]
    fn ghost_expires_after_timeout() {
        assert_eq!(GHOST_TIMEOUT, Duration::from_secs(3));
        let (mut a, t0) = two();
        a.set_grants(v(1), Grants { pointer: false, keyboard: false, pointing: true }, t0);
        a.message(v(1), &mv(1, 1, 0), &geo(), t0);
        assert_eq!(a.tick(t0 + GHOST_TIMEOUT - Duration::from_millis(1)), []);
        assert_eq!(
            a.tick(t0 + GHOST_TIMEOUT),
            [Action::Ghost { viewer: v(1), slot: 0, at: None, click: false }]
        );
        assert_eq!(a.tick(t0 + GHOST_TIMEOUT * 2), []);
        a.message(v(1), &mv(1, 1, 0), &geo(), t0);
        assert_eq!(a.viewer_left(v(1), t0), [Action::Ghost { viewer: v(1), slot: 0, at: None, click: false }]);
    }

    #[test]
    fn wheel_clamped() {
        let (mut a, t0) = two();
        assert_eq!(
            a.message(v(1), &DataMessage::Wheel { dx: -99999, dy: 240 }, &geo(), t0),
            [Action::Wheel { dx: -MAX_WHEEL, dy: 240 }]
        );
        assert_eq!(a.message(v(1), &DataMessage::Wheel { dx: 0, dy: 0 }, &geo(), t0), []);
    }

    #[test]
    fn oversized_key_dropped() {
        let (mut a, t0) = two();
        assert_eq!(a.message(v(1), &key(0x200, true), &geo(), t0), []);
        assert_eq!(a.message(v(1), &key(u32::MAX, true), &geo(), t0), []);
        assert_eq!(a.message(v(1), &key(MAX_KEY_CODE, true), &geo(), t0).len(), 1);
        assert_eq!(a.take_invalid(), 2);
        assert_eq!(a.take_invalid(), 0);
    }

    #[test]
    fn invalid_messages_counted() {
        let (mut a, t0) = two();
        a.message(v(9), &key(0x1E, true), &geo(), t0);
        a.message(v(1), &mv(1, 1, 7), &geo(), t0);
        a.set_grants(v(1), Grants { pointer: true, keyboard: false, pointing: true }, t0);
        a.message(v(1), &key(0x1E, true), &geo(), t0);
        assert_eq!(a.take_invalid(), 2, "a key without the grant is not invalid");
    }

    #[test]
    fn input_state_only_on_change() {
        let (mut a, t0) = two();
        let off = Grants { pointer: false, keyboard: true, pointing: true };
        assert_eq!(a.set_grants(v(1), off, t0).len(), 1);
        assert_eq!(a.set_grants(v(1), off, t0), []);
        assert_eq!(a.set_grants(v(1), Grants::default(), t0).len(), 1);
        assert_eq!(a.set_grants(v(1), Grants::default(), t0), []);
        assert_eq!(a.tick(t0), []);
    }

    #[test]
    fn follow_selects_containing_monitor() {
        let (mut a, t0) = two();
        assert_eq!(a.host_focus(2000, 0, &geo(), 0), [], "follow is off");
        assert_eq!(
            a.message(v(1), &DataMessage::Control(Control::SetFollow { on: true }), &geo(), t0),
            [Action::Send(v(1), state(false, true)), Action::Send(v(2), state(false, true))]
        );
        assert!(a.status(t0).follow);
        assert_eq!(a.host_focus(2000, -50, &geo(), 0), [Action::SelectMonitor(1)]);
        assert_eq!(a.host_focus(-1, 0, &geo(), 0), [], "outside every monitor");
    }

    #[test]
    fn follow_only_on_change() {
        let (mut a, t0) = two();
        a.set_follow(true, t0);
        assert_eq!(a.host_focus(5, 5, &geo(), 0), []);
        assert_eq!(a.set_follow(true, t0), []);
    }

    #[test]
    fn degraded_locks_and_releases() {
        let (mut a, t0) = two();
        a.message(v(2), &key(0x38, true), &geo(), t0);
        assert_eq!(
            a.set_degraded(t0),
            [
                Action::Key { code: 0x38, down: false },
                Action::Send(v(1), state(true, false)),
                Action::Send(v(2), state(true, false)),
            ]
        );
        assert_eq!(a.set_degraded(t0), []);
        let later = t0 + Duration::from_secs(60);
        assert_eq!(a.tick(later), []);
        assert_eq!(a.message(v(1), &key(0x1E, true), &geo(), later), []);
        assert!(a.status(later).locked);
    }

    #[test]
    fn ghost_slots_reuse_lowest_free() {
        let (mut a, t0) = two();
        a.viewer_joined(v(3), t0);
        a.viewer_left(v(1), t0);
        a.viewer_joined(v(4), t0);
        let status = a.status(t0);
        assert_eq!(status.viewers[&v(4)].slot, 0);
        assert_eq!(status.viewers[&v(2)].slot, 1);
        assert_eq!(status.viewers[&v(3)].slot, 2);
    }

    #[test]
    fn other_controls_ignored() {
        let (mut a, t0) = two();
        let msg = DataMessage::Control(Control::SelectMonitor { index: 1 });
        assert_eq!(a.message(v(1), &msg, &geo(), t0), []);
    }
}
