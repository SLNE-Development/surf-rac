//! The host-wide screen state and how viewer requests change it.

use surf_rac_protocol::DeviceId;
use surf_rac_protocol::data::{
    CaptureState, Control, MAX_MONITOR_NAME_BYTES, MAX_MONITORS, MonitorInfo, QualityMode,
    ScreenState,
};

use crate::source::{MonitorRect, SourceMonitor};

/// A screen state to send, and to whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outgoing {
    /// Send to one viewer.
    To(DeviceId, ScreenState),
    /// Send to every viewer.
    All(ScreenState),
}

/// Owns the screen state and applies monitor lists, capture status and viewer requests to it.
#[derive(Debug, Clone)]
pub struct Controller {
    /// The current state.
    state: ScreenState,
    /// Desktop rectangle of each monitor in `state.monitors`, in the same order.
    geometry: Vec<MonitorRect>,
}

impl Controller {
    /// Creates the state for `monitors`, showing `initial_monitor` when it exists and
    /// the primary monitor otherwise, in `mode`, with capture active.
    pub fn new(
        monitors: Vec<SourceMonitor>,
        initial_monitor: Option<u8>,
        mode: QualityMode,
    ) -> Controller {
        let geometry = rects(&monitors);
        let monitors = bounded(monitors);
        let selected = initial_monitor
            .filter(|i| usize::from(*i) < monitors.len())
            .unwrap_or_else(|| primary(&monitors));
        Controller {
            state: ScreenState {
                monitors,
                selected,
                mode,
                capture: CaptureState::Active,
            },
            geometry,
        }
    }

    /// Returns the desktop rectangle of each monitor, indexed like the state's monitors.
    pub fn geometry(&self) -> &[MonitorRect] {
        &self.geometry
    }

    /// Selects monitor `index` on the host's behalf; returns the broadcast when
    /// the selection changed and `None` when it did not or the monitor does not exist.
    pub fn select(&mut self, index: u8) -> Option<Outgoing> {
        if usize::from(index) >= self.state.monitors.len() || index == self.state.selected {
            return None;
        }
        self.state.selected = index;
        Some(Outgoing::All(self.state.clone()))
    }

    /// Returns the current state.
    pub fn state(&self) -> &ScreenState {
        &self.state
    }

    /// Returns the state message for a viewer that just joined.
    pub fn viewer_joined(&self, viewer: DeviceId) -> Outgoing {
        Outgoing::To(viewer, self.state.clone())
    }

    /// Applies a viewer's control message.
    ///
    /// A change is broadcast. A request that changes nothing or names a monitor
    /// that does not exist is answered with the current state to the requester
    /// only. Control messages that are not screen requests return `None`.
    pub fn handle(&mut self, from: DeviceId, control: &Control) -> Option<Outgoing> {
        let changed = match *control {
            Control::SelectMonitor { index } => {
                let valid = usize::from(index) < self.state.monitors.len();
                let changed = valid && index != self.state.selected;
                if changed {
                    self.state.selected = index;
                }
                changed
            }
            Control::SetQuality { mode } => {
                let changed = mode != self.state.mode;
                self.state.mode = mode;
                changed
            }
            _ => return None,
        };
        Some(if changed {
            Outgoing::All(self.state.clone())
        } else {
            Outgoing::To(from, self.state.clone())
        })
    }

    /// Replaces the monitor list; returns the broadcast when anything viewers see changed.
    ///
    /// The selection follows the selected monitor by name. When it is gone, the
    /// primary monitor is selected. Moved monitor origins update the geometry
    /// without a broadcast.
    pub fn set_monitors(&mut self, monitors: Vec<SourceMonitor>) -> Option<Outgoing> {
        self.geometry = rects(&monitors);
        let monitors = bounded(monitors);
        if monitors == self.state.monitors {
            return None;
        }
        let current = self
            .state
            .monitors
            .get(usize::from(self.state.selected))
            .map(|m| m.name.clone());
        self.state.selected = current
            .and_then(|name| monitors.iter().find(|m| m.name == name))
            .map(|m| m.index)
            .unwrap_or_else(|| primary(&monitors));
        self.state.monitors = monitors;
        Some(Outgoing::All(self.state.clone()))
    }

    /// Sets the capture status; returns the broadcast only when the status changed.
    pub fn set_capture(&mut self, capture: CaptureState) -> Option<Outgoing> {
        if capture == self.state.capture {
            return None;
        }
        self.state.capture = capture;
        Some(Outgoing::All(self.state.clone()))
    }
}

/// Returns the desktop rectangles of the first [`MAX_MONITORS`] source monitors.
fn rects(monitors: &[SourceMonitor]) -> Vec<MonitorRect> {
    monitors.iter().take(MAX_MONITORS).map(MonitorRect::from).collect()
}

/// Converts source monitors to at most [`MAX_MONITORS`] entries with names of at
/// most [`MAX_MONITOR_NAME_BYTES`].
fn bounded(monitors: Vec<SourceMonitor>) -> Vec<MonitorInfo> {
    monitors
        .into_iter()
        .take(MAX_MONITORS)
        .enumerate()
        .map(|(i, m)| MonitorInfo {
            index: i as u8,
            name: truncate(m.name, MAX_MONITOR_NAME_BYTES),
            width: m.width,
            height: m.height,
            primary: m.primary,
        })
        .collect()
}

/// Shortens `s` to at most `max` bytes without splitting a character.
fn truncate(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

/// Returns the index of the primary monitor, or 0 when none is marked primary.
fn primary(monitors: &[MonitorInfo]) -> u8 {
    monitors.iter().find(|m| m.primary).map_or(0, |m| m.index)
}

#[cfg(test)]
mod tests {
    use surf_rac_protocol::data::PauseReason;

    use super::*;

    /// Returns a monitor named `name` of `w` x `h`.
    fn mon(name: &str, w: u32, h: u32, primary: bool) -> SourceMonitor {
        SourceMonitor {
            name: name.into(),
            width: w,
            height: h,
            primary,
            left: 0,
            top: 0,
        }
    }

    /// Returns a controller over a secondary 1920x1080 and a primary 2560x1440 monitor.
    fn two() -> Controller {
        Controller::new(
            vec![mon("A", 1920, 1080, false), mon("B", 2560, 1440, true)],
            None,
            QualityMode::Balanced,
        )
    }

    /// Returns a test device ID.
    fn dev(n: u32) -> DeviceId {
        DeviceId::new(100_000_000 + n).unwrap()
    }

    #[test]
    fn starts_on_primary_unless_asked() {
        assert_eq!(two().state().selected, 1);
        let c = Controller::new(
            vec![mon("A", 1, 1, false), mon("B", 1, 1, true)],
            Some(0),
            QualityMode::Speed,
        );
        assert_eq!(c.state().selected, 0);
        assert_eq!(c.state().mode, QualityMode::Speed);
        assert_eq!(c.state().capture, CaptureState::Active);
        let c = Controller::new(vec![mon("A", 1, 1, true)], Some(9), QualityMode::Speed);
        assert_eq!(c.state().selected, 0);
    }

    #[test]
    fn join_sends_state_to_viewer() {
        let c = two();
        assert_eq!(c.viewer_joined(dev(1)), Outgoing::To(dev(1), c.state().clone()));
    }

    #[test]
    fn select_valid_broadcasts() {
        let mut c = two();
        let out = c.handle(dev(1), &Control::SelectMonitor { index: 0 });
        assert_eq!(c.state().selected, 0);
        assert_eq!(out, Some(Outgoing::All(c.state().clone())));
    }

    #[test]
    fn invalid_monitor_resends_state() {
        let mut c = two();
        let before = c.state().clone();
        let out = c.handle(dev(2), &Control::SelectMonitor { index: 200 });
        assert_eq!(out, Some(Outgoing::To(dev(2), before.clone())));
        assert_eq!(c.state(), &before);
        let mut empty = Controller::new(vec![], None, QualityMode::Balanced);
        let out = empty.handle(dev(2), &Control::SelectMonitor { index: 0 });
        assert!(matches!(out, Some(Outgoing::To(..))));
    }

    #[test]
    fn unchanged_request_answers_requester_only() {
        let mut c = two();
        let out = c.handle(dev(3), &Control::SelectMonitor { index: 1 });
        assert_eq!(out, Some(Outgoing::To(dev(3), c.state().clone())));
        let out = c.handle(
            dev(3),
            &Control::SetQuality {
                mode: QualityMode::Balanced,
            },
        );
        assert!(matches!(out, Some(Outgoing::To(..))));
    }

    #[test]
    fn set_quality_broadcasts() {
        let mut c = two();
        let out = c.handle(
            dev(1),
            &Control::SetQuality {
                mode: QualityMode::Speed,
            },
        );
        assert_eq!(c.state().mode, QualityMode::Speed);
        assert_eq!(out, Some(Outgoing::All(c.state().clone())));
    }

    #[test]
    fn select_ignores_invalid_and_unchanged() {
        let mut c = two();
        assert_eq!(c.select(1), None);
        assert_eq!(c.select(9), None);
        assert_eq!(c.select(0), Some(Outgoing::All(c.state().clone())));
        assert_eq!(c.state().selected, 0);
    }

    #[test]
    fn geometry_tracks_origins() {
        let mut a = mon("A", 1920, 1080, true);
        let mut b = mon("B", 1280, 1024, false);
        b.left = 1920;
        b.top = -100;
        let mut c = Controller::new(vec![a.clone(), b.clone()], None, QualityMode::Balanced);
        assert_eq!(
            c.geometry(),
            [
                MonitorRect { left: 0, top: 0, width: 1920, height: 1080 },
                MonitorRect { left: 1920, top: -100, width: 1280, height: 1024 },
            ]
        );
        a.left = 1280;
        b.left = 0;
        b.top = 0;
        assert_eq!(c.set_monitors(vec![a, b]), None, "only origins moved");
        assert_eq!(c.geometry()[0].left, 1280);
    }

    #[test]
    fn rect_contains_half_open() {
        let r = MonitorRect { left: -10, top: 5, width: 20, height: 10 };
        assert!(r.contains(-10, 5));
        assert!(r.contains(9, 14));
        assert!(!r.contains(10, 14));
        assert!(!r.contains(0, 15));
    }

    #[test]
    fn other_controls_are_not_screen_requests() {
        assert_eq!(two().handle(dev(1), &Control::Hangup), None);
    }

    #[test]
    fn monitor_vanished_falls_back_to_primary() {
        let mut c = two();
        c.handle(dev(1), &Control::SelectMonitor { index: 0 });
        let out = c.set_monitors(vec![mon("C", 800, 600, false), mon("B", 2560, 1440, true)]);
        assert_eq!(c.state().selected, 1);
        assert_eq!(c.state().monitors[0].name, "C");
        assert_eq!(out, Some(Outgoing::All(c.state().clone())));
    }

    #[test]
    fn selection_follows_monitor_by_name() {
        let mut c = two();
        c.set_monitors(vec![mon("B", 2560, 1440, true), mon("A", 1920, 1080, false)]);
        assert_eq!(c.state().selected, 0);
        assert_eq!(c.state().monitors[0].name, "B");
    }

    #[test]
    fn unchanged_monitors_send_nothing() {
        let mut c = two();
        assert_eq!(
            c.set_monitors(vec![mon("A", 1920, 1080, false), mon("B", 2560, 1440, true)]),
            None
        );
    }

    #[test]
    fn capture_transition_broadcasts_once() {
        let mut c = two();
        let paused = CaptureState::Paused {
            reason: PauseReason::Recovering,
        };
        assert!(matches!(c.set_capture(paused), Some(Outgoing::All(_))));
        assert_eq!(c.set_capture(paused), None);
        assert!(matches!(
            c.set_capture(CaptureState::Active),
            Some(Outgoing::All(_))
        ));
        assert_eq!(c.set_capture(CaptureState::Active), None);
    }

    #[test]
    fn names_and_count_are_bounded() {
        let long = "é".repeat(50);
        let many = (0..20).map(|_| mon(&long, 10, 10, false)).collect();
        let c = Controller::new(many, None, QualityMode::Balanced);
        assert_eq!(c.state().monitors.len(), MAX_MONITORS);
        for (i, m) in c.state().monitors.iter().enumerate() {
            assert_eq!(usize::from(m.index), i);
            assert!(m.name.len() <= MAX_MONITOR_NAME_BYTES);
            assert_eq!(m.name.len(), 64);
        }
    }
}
