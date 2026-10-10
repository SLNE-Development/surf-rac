//! The UI thread on the real desktop: hooks and the ghost overlay. These
//! tests inject input and show a window, so they are ignored by default; run
//! them on Windows with
//! `cargo test -p surf-rac-input --test windows_hooks -- --ignored --test-threads=1`.
#![cfg(windows)]

use std::time::{Duration, Instant};

use surf_rac_capture::FrameSource;
use surf_rac_capture::desktop::DesktopSource;
use surf_rac_input::{Action, Ghost};
use surf_rac_input::inject::perform;
use surf_rac_input::ui::{PALETTE, UiThread};

/// Returns an unlabelled ghost of `slot` with its tip at `(x, y)`.
fn ghost(slot: u8, x: i32, y: i32) -> Ghost {
    Ghost { slot, x, y, label: String::new(), pulse: false }
}

/// Waits up to 2 s for `cond` to hold.
fn wait_for(cond: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !cond() {
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

#[test]
#[ignore = "injects keys on the real desktop"]
fn injected_key_is_not_host_input() {
    let ui = UiThread::start(Instant::now()).expect("UI thread");
    let signals = ui.signals();
    assert!(signals.alive());
    // F24 has no default action.
    perform(&Action::Key { code: 0x76, down: true }).unwrap();
    perform(&Action::Key { code: 0x76, down: false }).unwrap();
    assert!(wait_for(|| signals.last_injected_key() == Some((0x76, false))));
    perform(&Action::Key { code: 0x11D, down: true }).unwrap();
    perform(&Action::Key { code: 0x11D, down: false }).unwrap();
    assert!(wait_for(|| signals.last_injected_key() == Some((0x1D, true))), "right Ctrl is extended");
    perform(&Action::Move { x: 5, y: 5 }).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(signals.last_host_input(), None, "injected input counted as host input");
    drop(ui);
    assert!(!signals.alive());
}

#[test]
#[ignore = "shows a window on the real desktop"]
fn overlay_shows_and_hides() {
    let ui = UiThread::start(Instant::now()).expect("UI thread");
    assert!(!ui.overlay_visible());
    ui.set_ghosts(vec![ghost(0, 300, 300)]);
    assert!(wait_for(|| ui.overlay_visible()));
    ui.set_ghosts(Vec::new());
    assert!(wait_for(|| !ui.overlay_visible()));
}

#[test]
#[ignore = "captures the real desktop"]
fn ghost_visible_in_capture() {
    let ui = UiThread::start(Instant::now()).expect("UI thread");
    let mut source = DesktopSource::new().expect("capturer");
    let monitors = source.monitors().expect("monitors");
    let index = monitors.iter().position(|m| m.primary).unwrap_or(0);
    let m = &monitors[index];
    let (cx, cy) = (m.left + m.width as i32 / 2, m.top + m.height as i32 / 2);
    ui.set_ghosts(vec![ghost(0, cx, cy)]);
    assert!(wait_for(|| ui.overlay_visible()));
    std::thread::sleep(Duration::from_millis(300));
    source.select(index).expect("select");
    let deadline = Instant::now() + Duration::from_secs(3);
    let frame = loop {
        if let Some(frame) = source.capture().expect("capture") {
            break frame;
        }
        assert!(Instant::now() < deadline, "no frame");
        std::thread::sleep(Duration::from_millis(33));
    };
    // A point inside the arrow's fill, relative to the monitor.
    let (px, py) = ((cx - m.left + 3) as usize, (cy - m.top + 9) as usize);
    let at = py * frame.stride as usize + px * 4;
    let (b, g, r) = (frame.data[at], frame.data[at + 1], frame.data[at + 2]);
    let (er, eg, eb) = PALETTE[0];
    let close = |a: u8, e: u8| a.abs_diff(e) <= 40;
    assert!(close(r, er) && close(g, eg) && close(b, eb), "pixel {r},{g},{b} is not the ghost color");
}
