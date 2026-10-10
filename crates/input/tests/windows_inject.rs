//! Injection on the real desktop. These tests move the cursor, so they are
//! ignored by default; run them on Windows with
//! `cargo test -p surf-rac-input --test windows_inject -- --ignored --test-threads=1`.
#![cfg(windows)]

use surf_rac_input::Action;
use surf_rac_input::inject::{ensure_dpi_awareness, perform};
use windows::Win32::Foundation::{POINT, RECT};
use windows::Win32::Graphics::Gdi::{EnumDisplayMonitors, HDC, HMONITOR};
use windows::Win32::UI::WindowsAndMessaging::{GetCursorPos, SetCursorPos};
use windows::core::BOOL;

/// Collects each monitor rectangle into the `Vec<RECT>` behind `data`.
unsafe extern "system" fn collect(_: HMONITOR, _: HDC, rect: *mut RECT, data: windows::Win32::Foundation::LPARAM) -> BOOL {
    // SAFETY: `data` is the address of the Vec passed to EnumDisplayMonitors and
    // `rect` points to a valid RECT for the duration of the callback.
    unsafe { (*(data.0 as *mut Vec<RECT>)).push(*rect) };
    true.into()
}

/// Returns the desktop rectangle of every monitor.
fn monitors() -> Vec<RECT> {
    let mut rects: Vec<RECT> = Vec::new();
    // SAFETY: the callback only writes into `rects`, which outlives the call.
    unsafe {
        let _ = EnumDisplayMonitors(None, None, Some(collect), windows::Win32::Foundation::LPARAM(&mut rects as *mut _ as isize));
    }
    rects
}

/// Returns the cursor position.
fn cursor() -> (i32, i32) {
    let mut p = POINT::default();
    // SAFETY: `p` is a valid POINT.
    unsafe { GetCursorPos(&mut p).unwrap() };
    (p.x, p.y)
}

/// Checks that injected moves put the cursor exactly on the corners and an inner
/// point of every monitor, then restores the cursor.
#[test]
#[ignore = "moves the real cursor"]
fn injected_move_lands_on_pixel() {
    assert!(ensure_dpi_awareness(), "process is not per-monitor DPI aware");
    let before = cursor();
    let rects = monitors();
    assert!(!rects.is_empty());
    let mut misses = Vec::new();
    for r in &rects {
        let points = [
            (r.left, r.top),
            (r.right - 1, r.top),
            (r.left, r.bottom - 1),
            (r.right - 1, r.bottom - 1),
            ((r.left + r.right) / 2 + 17, (r.top + r.bottom) / 2 + 23),
        ];
        for (x, y) in points {
            perform(&Action::Move { x, y }).unwrap();
            let got = cursor();
            if got != (x, y) {
                misses.push(((x, y), got));
            }
        }
    }
    // SAFETY: plain Win32 call.
    unsafe { SetCursorPos(before.0, before.1).unwrap() };
    assert!(misses.is_empty(), "wanted/got: {misses:?}");
}
