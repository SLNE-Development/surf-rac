//! Keyboard capture for viewer windows: a low-level keyboard hook that sends
//! the keys typed into a focused viewer window to its host and keeps them
//! from reaching this machine.

use std::sync::{Arc, Mutex};

use surf_rac_protocol::data::DataMessage;

use crate::keys::KeyTracker;

/// Where captured keys go.
pub type Sink = Arc<dyn Fn(DataMessage) + Send + Sync>;

/// The viewer session that currently receives keys.
struct Target {
    /// The runtime's session number.
    session: u64,
    /// Sends a message in that session.
    sink: Sink,
}

/// State shared between the hook procedure and the UI.
struct HookState {
    /// The receiving session, if a viewer window has the keyboard.
    target: Option<Target>,
    /// Keys sent down and not yet up.
    keys: KeyTracker,
}

/// The hook's state; the hook procedure runs on the UI thread that installed it.
static STATE: Mutex<HookState> = Mutex::new(HookState {
    target: None,
    keys: KeyTracker::new(),
});

/// Locks the hook state, recovering from a poisoned lock.
fn state() -> std::sync::MutexGuard<'static, HookState> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Routes captured keys to `target`'s session, or stops capturing with `None`.
///
/// When the receiving session changes, every key still held is released in
/// the session that had it, so no key stays stuck down on its host.
pub fn set_target(target: Option<(u64, Sink)>) {
    let mut st = state();
    let current = st.target.as_ref().map(|t| t.session);
    if current == target.as_ref().map(|(session, _)| *session) {
        return;
    }
    if let Some(old) = st.target.take() {
        for code in st.keys.release_all() {
            (old.sink)(DataMessage::Key { code, down: false });
        }
    }
    st.target = target.map(|(session, sink)| Target { session, sink });
}

/// Handles one key event; returns whether it was sent and must be swallowed.
fn on_key(scan: u32, extended: bool, down: bool) -> bool {
    let mut guard = state();
    let HookState { target, keys } = &mut *guard;
    let (Some(target), Some(code)) = (target.as_ref(), crate::keys::code(scan, extended)) else {
        return false;
    };
    if down {
        keys.press(code);
    } else {
        keys.release(code);
    }
    (target.sink)(DataMessage::Key { code, down });
    true
}

/// An installed low-level keyboard hook; removed when dropped.
pub struct KeyHook {
    /// The hook handle.
    #[cfg(windows)]
    hook: windows::Win32::UI::WindowsAndMessaging::HHOOK,
}

impl KeyHook {
    /// Installs the hook on the calling thread, which must run a message loop.
    #[cfg(windows)]
    pub fn install() -> Result<KeyHook, String> {
        use windows::Win32::UI::WindowsAndMessaging::{SetWindowsHookExW, WH_KEYBOARD_LL};
        // SAFETY: `hook_proc` matches the HOOKPROC signature and stays valid
        // for the life of the process.
        let hook = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), None, 0) }
            .map_err(|e| e.message())?;
        Ok(KeyHook { hook })
    }

    /// Fails: keyboard capture needs Windows.
    #[cfg(not(windows))]
    pub fn install() -> Result<KeyHook, String> {
        Err("keyboard capture is only supported on Windows".into())
    }
}

impl Drop for KeyHook {
    /// Releases held keys and removes the hook.
    fn drop(&mut self) {
        set_target(None);
        #[cfg(windows)]
        // SAFETY: the handle came from a successful `SetWindowsHookExW`.
        unsafe {
            let _ = windows::Win32::UI::WindowsAndMessaging::UnhookWindowsHookEx(self.hook);
        }
    }
}

/// Returns whether the foreground window belongs to this process.
#[cfg(windows)]
fn foreground_is_ours() -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
    let mut pid = 0u32;
    // SAFETY: both calls only read window information.
    unsafe {
        let hwnd = GetForegroundWindow();
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
    }
    pid == std::process::id()
}

/// The low-level keyboard hook procedure.
#[cfg(windows)]
unsafe extern "system" fn hook_proc(
    code: i32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::Foundation::LRESULT;
    use windows::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, HC_ACTION, KBDLLHOOKSTRUCT, LLKHF_EXTENDED, LLKHF_INJECTED, LLKHF_UP,
    };
    if code == HC_ACTION as i32 {
        // SAFETY: for HC_ACTION, `lparam` points at a KBDLLHOOKSTRUCT.
        let info = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
        let injected = info.flags.0 & LLKHF_INJECTED.0 != 0;
        if !injected && foreground_is_ours() {
            let down = info.flags.0 & LLKHF_UP.0 == 0;
            let extended = info.flags.0 & LLKHF_EXTENDED.0 != 0;
            if on_key(info.scanCode, extended, down) {
                return LRESULT(1);
            }
        }
    }
    // SAFETY: passes the event on unchanged.
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_go_to_the_target_and_are_released_when_it_changes() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&sent);
        let sink: Sink = Arc::new(move |m| log.lock().unwrap().push((1, m)));
        assert!(!on_key(0x1E, false, true), "no target, key passes through");
        set_target(Some((1, sink)));
        assert!(on_key(0x38, false, true));
        assert!(on_key(0x4B, true, true));
        assert!(on_key(0x4B, true, false));
        assert!(!on_key(0, false, true), "scan code 0 passes through");
        set_target(None);
        let sent = sent.lock().unwrap();
        let keys: Vec<(u32, bool)> = sent
            .iter()
            .map(|(_, m)| match m {
                DataMessage::Key { code, down } => (*code, *down),
                _ => panic!("not a key"),
            })
            .collect();
        assert_eq!(
            keys,
            vec![(0x38, true), (0x14B, true), (0x14B, false), (0x38, false)]
        );
    }
}
