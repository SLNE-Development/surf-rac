//! The host's input UI thread: low-level hooks that detect physical host
//! input, foreground tracking for follow mode, and the ghost pointer overlay.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreatePen, CreateSolidBrush, DeleteObject, Ellipse, EndPaint, FillRect,
    GetMonitorInfoW, GetStockObject, InvalidateRect, MONITOR_DEFAULTTONEAREST, MONITORINFO,
    MonitorFromWindow, NULL_BRUSH, PAINTSTRUCT, PS_SOLID, SelectObject,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Accessibility::{HWINEVENTHOOK, SetWinEventHook, UnhookWinEvent};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    EVENT_SYSTEM_FOREGROUND, GetMessageW, GetSystemMetrics, HHOOK, HWND_TOPMOST,
    IsWindowVisible, KBDLLHOOKSTRUCT, LLKHF_EXTENDED, LLKHF_INJECTED, LLMHF_INJECTED,
    LWA_COLORKEY, MSG, MSLLHOOKSTRUCT, PostMessageW, PostQuitMessage, RegisterClassW,
    SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    SW_HIDE, SWP_NOACTIVATE, SWP_SHOWWINDOW, SetLayeredWindowAttributes, SetWindowPos,
    SetWindowsHookExW, ShowWindow, UnhookWindowsHookEx, WH_KEYBOARD_LL, WH_MOUSE_LL,
    WINEVENT_OUTOFCONTEXT, WM_APP, WM_DESTROY, WM_DISPLAYCHANGE, WM_ERASEBKGND, WM_PAINT,
    WNDCLASSW, WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST,
    WS_EX_TRANSPARENT, WS_POPUP,
};
use windows::core::w;

use crate::inject::ensure_dpi_awareness;

/// Ring color of each ghost slot, as RGB; slots beyond the palette reuse it.
pub const PALETTE: [(u8, u8, u8); 5] = [
    (0, 170, 255),
    (255, 140, 0),
    (40, 200, 80),
    (230, 60, 160),
    (250, 220, 0),
];

/// Overlay background that is drawn fully transparent.
const KEY_COLOR: COLORREF = COLORREF(0x00FF_00FF);

/// Outer diameter of a ghost ring, in pixels.
const RING_DIAMETER: i32 = 28;

/// Line width of a ghost ring, in pixels.
const RING_WIDTH: i32 = 4;

/// Message that tells the overlay to redraw the current ghosts.
const WM_GHOSTS: u32 = WM_APP + 1;

/// Message that ends the UI thread.
const WM_STOP: u32 = WM_APP + 2;

/// Ghosts to draw: color slot and desktop position of each, shared with the UI thread.
type SharedGhosts = Arc<Mutex<Vec<(u8, i32, i32)>>>;

/// What the UI thread observed, readable from any thread.
#[derive(Debug)]
pub struct Signals {
    /// Reference point of `host_input_ms`.
    base: Instant,
    /// Milliseconds after `base` of the last physical host input, plus one; 0 when none.
    host_input_ms: AtomicU64,
    /// Increments on every physical host mouse event.
    mouse_seq: AtomicU64,
    /// Desktop position of the last physical host mouse event, packed by [`pack`].
    mouse_at: AtomicI64,
    /// Increments on every foreground window change.
    foreground_seq: AtomicU64,
    /// Centre of the monitor holding the new foreground window, packed by [`pack`].
    foreground_at: AtomicI64,
    /// Scan code of the last injected key event plus `0x100` when extended, plus one; 0 when none.
    injected_key: AtomicU32,
    /// Whether both hooks are installed and the thread is running.
    alive: AtomicBool,
}

impl Signals {
    /// Creates signals counting time from `base`, with nothing observed and not alive.
    fn new(base: Instant) -> Signals {
        Signals {
            base,
            host_input_ms: AtomicU64::new(0),
            mouse_seq: AtomicU64::new(0),
            mouse_at: AtomicI64::new(0),
            foreground_seq: AtomicU64::new(0),
            foreground_at: AtomicI64::new(0),
            injected_key: AtomicU32::new(0),
            alive: AtomicBool::new(false),
        }
    }

    /// Returns when the last physical host input happened, if any.
    pub fn last_host_input(&self) -> Option<Instant> {
        match self.host_input_ms.load(Ordering::Acquire) {
            0 => None,
            ms => Some(self.base + Duration::from_millis(ms - 1)),
        }
    }

    /// Returns the sequence number and desktop position of the last physical host mouse event.
    pub fn host_mouse(&self) -> Option<(u64, i32, i32)> {
        let seq = self.mouse_seq.load(Ordering::Acquire);
        (seq > 0).then(|| {
            let (x, y) = unpack(self.mouse_at.load(Ordering::Acquire));
            (seq, x, y)
        })
    }

    /// Returns the sequence number of the last foreground change and the centre
    /// of the monitor holding the new foreground window.
    pub fn foreground(&self) -> Option<(u64, i32, i32)> {
        let seq = self.foreground_seq.load(Ordering::Acquire);
        (seq > 0).then(|| {
            let (x, y) = unpack(self.foreground_at.load(Ordering::Acquire));
            (seq, x, y)
        })
    }

    /// Returns the scan code and extended flag of the last injected key event the hook saw.
    pub fn last_injected_key(&self) -> Option<(u16, bool)> {
        match self.injected_key.load(Ordering::Acquire) {
            0 => None,
            v => {
                let code = (v - 1) as u16;
                Some((code & 0xFF, code & 0x100 != 0))
            }
        }
    }

    /// Returns whether host input detection is working.
    pub fn alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Records physical host input now.
    fn host_input(&self) {
        let ms = self.base.elapsed().as_millis() as u64 + 1;
        self.host_input_ms.store(ms, Ordering::Release);
    }
}

/// Packs a desktop position into one integer.
fn pack(x: i32, y: i32) -> i64 {
    (i64::from(x) << 32) | i64::from(y as u32)
}

/// Unpacks a desktop position packed by [`pack`].
fn unpack(v: i64) -> (i32, i32) {
    ((v >> 32) as i32, v as i32)
}

thread_local! {
    /// The signals of the UI thread running on this thread.
    static SIGNALS: RefCell<Option<Arc<Signals>>> = const { RefCell::new(None) };
    /// The ghosts the overlay on this thread draws.
    static GHOSTS: RefCell<Option<SharedGhosts>> = const { RefCell::new(None) };
}

/// Runs `f` with this thread's signals, if any.
fn with_signals(f: impl FnOnce(&Signals)) {
    SIGNALS.with(|s| {
        if let Some(s) = s.borrow().as_ref() {
            f(s);
        }
    });
}

/// A running UI thread with its hooks and overlay window.
pub struct UiThread {
    /// What the hooks observe.
    signals: Arc<Signals>,
    /// Ghosts to draw.
    ghosts: SharedGhosts,
    /// The overlay window handle as an integer.
    hwnd: isize,
    /// The thread.
    thread: Option<thread::JoinHandle<()>>,
}

impl UiThread {
    /// Starts the UI thread, timing host input from `base`.
    ///
    /// Fails when a hook or the overlay window cannot be created.
    pub fn start(base: Instant) -> Result<UiThread, String> {
        let signals = Arc::new(Signals::new(base));
        let ghosts = Arc::new(Mutex::new(Vec::new()));
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread = {
            let signals = Arc::clone(&signals);
            let ghosts = Arc::clone(&ghosts);
            thread::Builder::new()
                .name("surf-rac-input-ui".into())
                .spawn(move || run(signals, ghosts, ready_tx))
                .map_err(|e| e.to_string())?
        };
        match ready_rx.recv() {
            Ok(Ok(hwnd)) => Ok(UiThread {
                signals,
                ghosts,
                hwnd,
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => Err("input UI thread ended during start".into()),
        }
    }

    /// Returns what the hooks observe.
    pub fn signals(&self) -> Arc<Signals> {
        Arc::clone(&self.signals)
    }

    /// Replaces the ghosts the overlay draws: color slot and desktop position each.
    pub fn set_ghosts(&self, ghosts: Vec<(u8, i32, i32)>) {
        *self.ghosts.lock().unwrap_or_else(|e| e.into_inner()) = ghosts;
        // SAFETY: posting to a window owned by the UI thread; a destroyed window only fails the post.
        unsafe {
            let _ = PostMessageW(Some(self.window()), WM_GHOSTS, WPARAM(0), LPARAM(0));
        }
    }

    /// Returns whether the overlay window is shown.
    pub fn overlay_visible(&self) -> bool {
        // SAFETY: querying a window handle; an invalid handle returns false.
        unsafe { IsWindowVisible(self.window()).as_bool() }
    }

    /// Returns the overlay window.
    fn window(&self) -> HWND {
        HWND(self.hwnd as *mut _)
    }
}

impl Drop for UiThread {
    /// Destroys the overlay, removes the hooks and waits for the thread to end.
    fn drop(&mut self) {
        // SAFETY: posting to a window owned by the UI thread.
        unsafe {
            let _ = PostMessageW(Some(self.window()), WM_STOP, WPARAM(0), LPARAM(0));
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Body of the UI thread: installs the hooks, creates the overlay, reports
/// the window through `ready` and pumps messages until stopped.
fn run(signals: Arc<Signals>, ghosts: SharedGhosts, ready: mpsc::Sender<Result<isize, String>>) {
    if !ensure_dpi_awareness() {
        tracing::warn!("input UI thread is not per-monitor DPI aware; positions may be scaled");
    }
    SIGNALS.with(|s| *s.borrow_mut() = Some(Arc::clone(&signals)));
    GHOSTS.with(|g| *g.borrow_mut() = Some(ghosts));
    // SAFETY: hook procedures are 'static functions; handles are released below on this thread.
    let hooks = unsafe {
        let mouse = SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_hook), None, 0);
        let keyboard = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook), None, 0);
        (mouse, keyboard)
    };
    let (mouse, keyboard) = match hooks {
        (Ok(m), Ok(k)) => (m, k),
        (m, k) => {
            unhook(m.ok(), k.ok());
            let _ = ready.send(Err("installing the low-level input hooks failed".into()));
            return;
        }
    };
    // SAFETY: the WinEvent procedure is a 'static function.
    let foreground = unsafe {
        SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND,
            EVENT_SYSTEM_FOREGROUND,
            None,
            Some(foreground_event),
            0,
            0,
            WINEVENT_OUTOFCONTEXT,
        )
    };
    let hwnd = match create_overlay() {
        Ok(hwnd) => hwnd,
        Err(e) => {
            unhook(Some(mouse), Some(keyboard));
            let _ = ready.send(Err(format!("creating the ghost overlay failed: {e}")));
            return;
        }
    };
    signals.alive.store(true, Ordering::Release);
    let _ = ready.send(Ok(hwnd.0 as isize));
    let mut msg = MSG::default();
    // SAFETY: standard message loop on the thread that owns the window and hooks.
    unsafe {
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            DispatchMessageW(&msg);
        }
    }
    signals.alive.store(false, Ordering::Release);
    unhook(Some(mouse), Some(keyboard));
    if !foreground.is_invalid() {
        // SAFETY: the handle came from SetWinEventHook on this thread.
        unsafe {
            let _ = UnhookWinEvent(foreground);
        }
    }
}

/// Removes the given low-level hooks.
fn unhook(mouse: Option<HHOOK>, keyboard: Option<HHOOK>) {
    for hook in [mouse, keyboard].into_iter().flatten() {
        // SAFETY: the handle came from SetWindowsHookExW on this thread.
        unsafe {
            let _ = UnhookWindowsHookEx(hook);
        }
    }
}

/// Records physical host mouse input; injected events are ignored.
unsafe extern "system" fn mouse_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 {
        // SAFETY: for WH_MOUSE_LL with code >= 0, lparam points to an MSLLHOOKSTRUCT.
        let info = unsafe { &*(lparam.0 as *const MSLLHOOKSTRUCT) };
        if info.flags & LLMHF_INJECTED == 0 {
            with_signals(|s| {
                s.host_input();
                s.mouse_at.store(pack(info.pt.x, info.pt.y), Ordering::Release);
                s.mouse_seq.fetch_add(1, Ordering::AcqRel);
            });
        }
    }
    // SAFETY: passing the event on unchanged.
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

/// Records physical host keyboard input and the last injected key.
unsafe extern "system" fn keyboard_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 {
        // SAFETY: for WH_KEYBOARD_LL with code >= 0, lparam points to a KBDLLHOOKSTRUCT.
        let info = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
        with_signals(|s| {
            if info.flags.0 & LLKHF_INJECTED.0 != 0 {
                let extended = if info.flags.0 & LLKHF_EXTENDED.0 != 0 { 0x100 } else { 0 };
                let key = (info.scanCode & 0xFF) | extended;
                s.injected_key.store(key + 1, Ordering::Release);
            } else {
                s.host_input();
            }
        });
    }
    // SAFETY: passing the event on unchanged.
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

/// Records the centre of the monitor holding a new foreground window.
unsafe extern "system" fn foreground_event(
    _hook: HWINEVENTHOOK,
    _event: u32,
    hwnd: HWND,
    _object: i32,
    _child: i32,
    _thread: u32,
    _time: u32,
) {
    let mut info = MONITORINFO {
        cbSize: size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` is a valid MONITORINFO with its size set.
    let ok = unsafe { GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mut info).as_bool() };
    if ok {
        let r = info.rcMonitor;
        with_signals(|s| {
            s.foreground_at.store(pack((r.left + r.right) / 2, (r.top + r.bottom) / 2), Ordering::Release);
            s.foreground_seq.fetch_add(1, Ordering::AcqRel);
        });
    }
}

/// Returns the virtual screen as `(left, top, width, height)`.
fn virtual_screen() -> (i32, i32, i32, i32) {
    // SAFETY: plain Win32 calls without pointers.
    unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    }
}

/// Creates the hidden, click-through overlay window covering the virtual screen.
fn create_overlay() -> windows::core::Result<HWND> {
    // SAFETY: registers a class with a 'static window procedure and creates a
    // window owned by this thread.
    unsafe {
        let instance = GetModuleHandleW(None)?;
        let class = WNDCLASSW {
            lpfnWndProc: Some(overlay_proc),
            hInstance: instance.into(),
            lpszClassName: w!("SurfRacGhostOverlay"),
            ..Default::default()
        };
        RegisterClassW(&class);
        let (x, y, cx, cy) = virtual_screen();
        let hwnd = CreateWindowExW(
            WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TOPMOST,
            w!("SurfRacGhostOverlay"),
            w!(""),
            WS_POPUP,
            x,
            y,
            cx,
            cy,
            None,
            None,
            Some(instance.into()),
            None,
        )?;
        SetLayeredWindowAttributes(hwnd, KEY_COLOR, 0, LWA_COLORKEY)?;
        Ok(hwnd)
    }
}

/// Returns a copy of the ghosts this thread's overlay draws.
fn current_ghosts() -> Vec<(u8, i32, i32)> {
    GHOSTS.with(|g| {
        g.borrow()
            .as_ref()
            .map(|g| g.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .unwrap_or_default()
    })
}

/// Window procedure of the ghost overlay.
unsafe extern "system" fn overlay_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // SAFETY: every call below operates on `hwnd`, which this thread owns.
    unsafe {
        match msg {
            WM_GHOSTS => {
                if current_ghosts().is_empty() {
                    let _ = ShowWindow(hwnd, SW_HIDE);
                } else {
                    let (x, y, cx, cy) = virtual_screen();
                    let _ = SetWindowPos(hwnd, Some(HWND_TOPMOST), x, y, cx, cy, SWP_NOACTIVATE | SWP_SHOWWINDOW);
                    let _ = InvalidateRect(Some(hwnd), None, false);
                }
                LRESULT(0)
            }
            WM_DISPLAYCHANGE => {
                let (x, y, cx, cy) = virtual_screen();
                let _ = SetWindowPos(hwnd, Some(HWND_TOPMOST), x, y, cx, cy, SWP_NOACTIVATE);
                let _ = InvalidateRect(Some(hwnd), None, false);
                LRESULT(0)
            }
            WM_ERASEBKGND => LRESULT(1),
            WM_PAINT => {
                paint(hwnd);
                LRESULT(0)
            }
            WM_STOP => {
                let _ = DestroyWindow(hwnd);
                LRESULT(0)
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

/// Paints the transparent background and one ring per ghost.
///
/// # Safety
/// Must be called on the thread that owns `hwnd`, in response to WM_PAINT.
unsafe fn paint(hwnd: HWND) {
    let (vx, vy, cx, cy) = virtual_screen();
    let mut ps = PAINTSTRUCT::default();
    // SAFETY: the caller handles WM_PAINT for `hwnd` on its own thread; every
    // GDI object created here is deleted before returning.
    unsafe {
        let hdc = BeginPaint(hwnd, &mut ps);
        let background = CreateSolidBrush(KEY_COLOR);
        FillRect(hdc, &RECT { left: 0, top: 0, right: cx, bottom: cy }, background);
        let _ = DeleteObject(background.into());
        let old_brush = SelectObject(hdc, GetStockObject(NULL_BRUSH));
        let r = RING_DIAMETER / 2;
        for (slot, x, y) in current_ghosts() {
            let (red, green, blue) = PALETTE[usize::from(slot) % PALETTE.len()];
            let color = COLORREF(u32::from(red) | (u32::from(green) << 8) | (u32::from(blue) << 16));
            let pen = CreatePen(PS_SOLID, RING_WIDTH, color);
            let old_pen = SelectObject(hdc, pen.into());
            let (x, y) = (x - vx, y - vy);
            let _ = Ellipse(hdc, x - r, y - r, x + r, y + r);
            SelectObject(hdc, old_pen);
            let _ = DeleteObject(pen.into());
        }
        SelectObject(hdc, old_brush);
        let _ = EndPaint(hwnd, &ps);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_round_trips_negative_positions() {
        for (x, y) in [(0, 0), (-1920, -100), (5119, 1439), (i32::MIN, i32::MAX)] {
            assert_eq!(unpack(pack(x, y)), (x, y));
        }
    }

    #[test]
    fn signals_report_nothing_until_observed() {
        let s = Signals::new(Instant::now());
        assert_eq!(s.last_host_input(), None);
        assert_eq!(s.host_mouse(), None);
        assert_eq!(s.foreground(), None);
        assert_eq!(s.last_injected_key(), None);
        assert!(!s.alive());
        s.host_input();
        assert!(s.last_host_input().is_some());
    }
}
