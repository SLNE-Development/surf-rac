//! Injects pointer, wheel and key input into the host's desktop.

/// Converts desktop pixel `p` on an axis starting at `origin` with `size`
/// pixels to the 0..=65535 absolute coordinate that lands exactly on it.
pub fn normalize(p: i32, origin: i32, size: i32) -> i32 {
    let size = i64::from(size.max(1));
    let rel = (i64::from(p) - i64::from(origin)).clamp(0, size - 1);
    ((rel * 65536 + size - 1) / size).min(65535) as i32
}

#[cfg(windows)]
pub use platform::{InjectError, ensure_dpi_awareness, perform};

#[cfg(windows)]
mod platform {
    use surf_rac_protocol::data::MouseButton;
    use windows::Win32::UI::HiDpi::{
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, DPI_AWARENESS_PER_MONITOR_AWARE,
        GetAwarenessFromDpiAwarenessContext, GetThreadDpiAwarenessContext,
        SetProcessDpiAwarenessContext,
    };
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS, KEYBDINPUT,
        KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSE_EVENT_FLAGS,
        MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
        MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
        MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN,
        MOUSEEVENTF_XUP, MOUSEINPUT, SendInput, VIRTUAL_KEY, VK_PAUSE,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN, XBUTTON1, XBUTTON2,
    };

    use super::normalize;
    use crate::arbiter::Action;

    /// Scan code that is injected as the Pause key.
    const PAUSE_CODE: u16 = 0x45;

    /// Input that Windows did not take.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    pub enum InjectError {
        /// Fewer events were injected than requested, for example because the
        /// target window runs elevated or the secure desktop is active.
        #[error("injected {sent} of {wanted} input events")]
        Blocked {
            /// Events Windows accepted.
            sent: u32,
            /// Events requested.
            wanted: u32,
        },
    }

    /// Makes this process per-monitor DPI aware so desktop coordinates are
    /// physical pixels; returns whether the calling thread is per-monitor aware.
    pub fn ensure_dpi_awareness() -> bool {
        // SAFETY: plain Win32 calls without pointers.
        unsafe {
            let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext())
                == DPI_AWARENESS_PER_MONITOR_AWARE
        }
    }

    /// Injects `action` when it is input; every other action is ignored.
    pub fn perform(action: &Action) -> Result<(), InjectError> {
        match *action {
            Action::Move { x, y } => {
                // SAFETY: plain Win32 calls without pointers.
                let (vx, vy, vw, vh) = unsafe {
                    (
                        GetSystemMetrics(SM_XVIRTUALSCREEN),
                        GetSystemMetrics(SM_YVIRTUALSCREEN),
                        GetSystemMetrics(SM_CXVIRTUALSCREEN),
                        GetSystemMetrics(SM_CYVIRTUALSCREEN),
                    )
                };
                send(&[mouse(
                    normalize(x, vx, vw),
                    normalize(y, vy, vh),
                    0,
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                )])
            }
            Action::Button { button, down } => {
                let (flags, data) = match (button, down) {
                    (MouseButton::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
                    (MouseButton::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
                    (MouseButton::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
                    (MouseButton::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
                    (MouseButton::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
                    (MouseButton::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
                    (MouseButton::Back, true) => (MOUSEEVENTF_XDOWN, XBUTTON1),
                    (MouseButton::Back, false) => (MOUSEEVENTF_XUP, XBUTTON1),
                    (MouseButton::Forward, true) => (MOUSEEVENTF_XDOWN, XBUTTON2),
                    (MouseButton::Forward, false) => (MOUSEEVENTF_XUP, XBUTTON2),
                };
                send(&[mouse(0, 0, u32::from(data), flags)])
            }
            Action::Wheel { dx, dy } => {
                let mut inputs = Vec::with_capacity(2);
                if dy != 0 {
                    inputs.push(mouse(0, 0, dy as u32, MOUSEEVENTF_WHEEL));
                }
                if dx != 0 {
                    inputs.push(mouse(0, 0, dx as u32, MOUSEEVENTF_HWHEEL));
                }
                send(&inputs)
            }
            Action::Key { code, down } => {
                let up = if down { KEYBD_EVENT_FLAGS(0) } else { KEYEVENTF_KEYUP };
                let input = if code == PAUSE_CODE {
                    key(VK_PAUSE, 0, up)
                } else {
                    let extended = if code & 0x100 != 0 {
                        KEYEVENTF_EXTENDEDKEY
                    } else {
                        KEYBD_EVENT_FLAGS(0)
                    };
                    key(VIRTUAL_KEY(0), code & 0xFF, KEYEVENTF_SCANCODE | extended | up)
                };
                send(&[input])
            }
            Action::Ghost { .. } | Action::Send(..) | Action::SelectMonitor(_) => Ok(()),
        }
    }

    /// Returns a mouse input event.
    fn mouse(dx: i32, dy: i32, data: u32, flags: MOUSE_EVENT_FLAGS) -> INPUT {
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: data,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    /// Returns a keyboard input event.
    fn key(vk: VIRTUAL_KEY, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: scan,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    /// Injects `inputs` in one call.
    fn send(inputs: &[INPUT]) -> Result<(), InjectError> {
        if inputs.is_empty() {
            return Ok(());
        }
        // SAFETY: `inputs` is a valid slice of initialised INPUT structures.
        let sent = unsafe { SendInput(inputs, size_of::<INPUT>() as i32) };
        let wanted = inputs.len() as u32;
        if sent < wanted {
            return Err(InjectError::Blocked { sent, wanted });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_lands_on_every_pixel() {
        for size in [1280, 1920, 3840, 5760, 7680] {
            for p in 0..size {
                let n = normalize(p - 1000, -1000, size);
                assert!((0..=65535).contains(&n), "size {size} pixel {p}: {n}");
                assert_eq!(i64::from(n) * i64::from(size) / 65536, i64::from(p), "size {size}");
            }
        }
    }

    #[test]
    fn normalize_clamps_outside_points() {
        assert_eq!(normalize(-50, 0, 1920), 0);
        assert_eq!(normalize(5000, 0, 1920), normalize(1919, 0, 1920));
        assert_eq!(normalize(0, 0, 0), 0);
    }
}
