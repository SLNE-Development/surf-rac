//! The host's input UI thread: low-level hooks that detect physical host
//! input, foreground tracking for follow mode, and the ghost pointer overlay.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, SIZE, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CLIP_DEFAULT_PRECIS, CreateFontW, CreatePen, CreateSolidBrush, DEFAULT_CHARSET,
    DeleteObject, Ellipse, EndPaint, FF_SWISS, FW_SEMIBOLD, FillRect, GetMonitorInfoW,
    GetStockObject, GetTextExtentPoint32W, HDC, InvalidateRect, MONITOR_DEFAULTTONEAREST,
    MONITORINFO, MonitorFromPoint, MonitorFromWindow, NONANTIALIASED_QUALITY, NULL_BRUSH,
    OUT_DEFAULT_PRECIS, PAINTSTRUCT, PS_SOLID, Polygon, Rectangle, SelectObject, SetBkMode, SetTextColor,
    TRANSPARENT, TextOutW, VARIABLE_PITCH,
};
use windows::Win32::UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Accessibility::{HWINEVENTHOOK, SetWinEventHook, UnhookWinEvent};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    EVENT_SYSTEM_FOREGROUND, GetMessageW, GetSystemMetrics, HHOOK, HWND_TOPMOST,
    IsWindowVisible, KBDLLHOOKSTRUCT, KillTimer, LLKHF_EXTENDED, LLKHF_INJECTED, LLMHF_INJECTED,
    LWA_COLORKEY, MSG, MSLLHOOKSTRUCT, PostMessageW, PostQuitMessage, RegisterClassW,
    SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    SW_HIDE, SWP_NOACTIVATE, SWP_SHOWWINDOW, SetLayeredWindowAttributes, SetTimer, SetWindowPos,
    SetWindowsHookExW, ShowWindow, UnhookWindowsHookEx, WH_KEYBOARD_LL, WH_MOUSE_LL,
    WINEVENT_OUTOFCONTEXT, WM_APP, WM_DESTROY, WM_DISPLAYCHANGE, WM_ERASEBKGND, WM_PAINT,
    WM_TIMER, WNDCLASSW, WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST,
    WS_EX_TRANSPARENT, WS_POPUP,
};
use windows::core::w;

use crate::host::Ghost;
use crate::inject::ensure_dpi_awareness;

/// Fill color of each ghost slot's pointer and label, as RGB; slots beyond
/// the palette reuse it.
pub const PALETTE: [(u8, u8, u8); 5] = [
    (0, 170, 255),
    (255, 140, 0),
    (40, 200, 80),
    (230, 60, 160),
    (250, 220, 0),
];

/// Overlay background that is drawn fully transparent.
const KEY_COLOR: COLORREF = COLORREF(0x00FF_00FF);

/// Outline of the ghost pointer arrow at 100% scale, tip first, in pixels
/// relative to the tip.
const ARROW: [(i32, i32); 7] = [(0, 0), (0, 17), (4, 13), (7, 19), (10, 18), (7, 12), (12, 12)];

/// Color of the arrow outline and of dark label text, as RGB.
const INK: (u8, u8, u8) = (20, 20, 20);

/// Color of light label text, as RGB.
const PAPER: (u8, u8, u8) = (255, 255, 255);

/// Offset of the label's top-left corner from the pointer's tip at 100% scale, in pixels.
const LABEL_OFFSET: (i32, i32) = (9, 20);

/// Space between the label text and the label's edge at 100% scale, in pixels.
const LABEL_PADDING: (i32, i32) = (4, 1);

/// Height of the label font at 100% scale, in pixels.
const LABEL_FONT_HEIGHT: i32 = 13;

/// How long the pulse around the tip shows after a click.
const PULSE: Duration = Duration::from_millis(300);

/// Outer diameter of the click pulse at 100% scale, in pixels.
const PULSE_DIAMETER: i32 = 26;

/// Line width of the click pulse at 100% scale, in pixels.
const PULSE_WIDTH: i32 = 3;

/// Identifier of the timer that ends click pulses.
const PULSE_TIMER: usize = 1;

/// Message that tells the overlay to redraw the current ghosts.
const WM_GHOSTS: u32 = WM_APP + 1;

/// Message that ends the UI thread.
const WM_STOP: u32 = WM_APP + 2;

/// Ghosts to draw, shared with the UI thread.
#[derive(Debug, Default)]
struct Ghosts {
    /// Each ghost to draw.
    list: Mutex<Vec<Ghost>>,
    /// When each color slot last clicked.
    pulses: Mutex<BTreeMap<u8, Instant>>,
    /// Whether a redraw message is already queued for the overlay.
    redraw_pending: AtomicBool,
}

impl Ghosts {
    /// Returns the color slots whose click pulse still shows at `now`.
    fn pulsing(&self, now: Instant) -> Vec<u8> {
        let mut pulses = self.pulses.lock().unwrap_or_else(|e| e.into_inner());
        pulses.retain(|_, at| now.duration_since(*at) < PULSE);
        pulses.keys().copied().collect()
    }

    /// Returns how long until the oldest click pulse that still shows at `now` ends.
    fn next_pulse_end(&self, now: Instant) -> Option<Duration> {
        let pulses = self.pulses.lock().unwrap_or_else(|e| e.into_inner());
        pulses
            .values()
            .map(|at| (*at + PULSE).saturating_duration_since(now))
            .filter(|left| !left.is_zero())
            .min()
    }
}

/// Ghosts shared between the UI thread and its owner.
type SharedGhosts = Arc<Ghosts>;

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
        let ghosts = Arc::new(Ghosts::default());
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

    /// Replaces the ghosts the overlay draws; a ghost with `pulse` set starts
    /// a short pulse around its tip.
    ///
    /// At most one redraw is queued at a time, and nothing is posted once the
    /// UI thread has stopped.
    pub fn set_ghosts(&self, ghosts: Vec<Ghost>) {
        let now = Instant::now();
        {
            let mut pulses = self.ghosts.pulses.lock().unwrap_or_else(|e| e.into_inner());
            for ghost in ghosts.iter().filter(|g| g.pulse) {
                pulses.insert(ghost.slot, now);
            }
        }
        *self.ghosts.list.lock().unwrap_or_else(|e| e.into_inner()) = ghosts;
        if !self.signals.alive() || self.ghosts.redraw_pending.swap(true, Ordering::AcqRel) {
            return;
        }
        // SAFETY: posting to the window the running UI thread owns.
        let posted = unsafe { PostMessageW(Some(self.window()), WM_GHOSTS, WPARAM(0), LPARAM(0)) };
        if posted.is_err() {
            self.ghosts.redraw_pending.store(false, Ordering::Release);
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
    ///
    /// When the stop request cannot be posted to a running thread, the thread
    /// is left to end on its own instead of being waited for.
    fn drop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        if self.signals.alive() {
            // SAFETY: posting to the window the running UI thread owns.
            let posted = unsafe { PostMessageW(Some(self.window()), WM_STOP, WPARAM(0), LPARAM(0)) };
            if posted.is_err() && !thread.is_finished() {
                tracing::warn!("input UI thread did not take the stop request");
                return;
            }
        }
        let _ = thread.join();
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
    if foreground.is_invalid() {
        tracing::warn!("foreground tracking unavailable; follow mode reacts to the mouse only");
    }
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
        while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
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
fn current_ghosts() -> Vec<Ghost> {
    GHOSTS.with(|g| {
        g.borrow()
            .as_ref()
            .map(|g| g.list.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .unwrap_or_default()
    })
}

/// Returns the color slots of this thread's overlay whose click pulse still shows.
fn current_pulses() -> Vec<u8> {
    GHOSTS.with(|g| g.borrow().as_ref().map(|g| g.pulsing(Instant::now())).unwrap_or_default())
}

/// Arms the pulse timer of `hwnd` for the end of the oldest showing click
/// pulse, or stops it when none shows.
///
/// # Safety
/// Must be called on the thread that owns `hwnd`.
unsafe fn arm_pulse_timer(hwnd: HWND) {
    let next = GHOSTS.with(|g| g.borrow().as_ref().and_then(|g| g.next_pulse_end(Instant::now())));
    // SAFETY: the caller owns `hwnd`.
    unsafe {
        match next {
            Some(left) => {
                let ms = u32::try_from(left.as_millis()).unwrap_or(u32::MAX).max(1);
                SetTimer(Some(hwnd), PULSE_TIMER, ms, None);
            }
            None => {
                let _ = KillTimer(Some(hwnd), PULSE_TIMER);
            }
        }
    }
}

/// Window procedure of the ghost overlay.
unsafe extern "system" fn overlay_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // SAFETY: every call below operates on `hwnd`, which this thread owns.
    unsafe {
        match msg {
            WM_GHOSTS => {
                GHOSTS.with(|g| {
                    if let Some(g) = g.borrow().as_ref() {
                        g.redraw_pending.store(false, Ordering::Release);
                    }
                });
                if current_ghosts().is_empty() {
                    let _ = ShowWindow(hwnd, SW_HIDE);
                } else {
                    let (x, y, cx, cy) = virtual_screen();
                    let _ = SetWindowPos(hwnd, Some(HWND_TOPMOST), x, y, cx, cy, SWP_NOACTIVATE | SWP_SHOWWINDOW);
                    let _ = InvalidateRect(Some(hwnd), None, false);
                }
                arm_pulse_timer(hwnd);
                LRESULT(0)
            }
            WM_TIMER if wparam.0 == PULSE_TIMER => {
                let _ = InvalidateRect(Some(hwnd), None, false);
                arm_pulse_timer(hwnd);
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

/// Paints the transparent background and, per ghost, an arrow pointer in
/// its slot color with its label below and to the right of the tip, plus a
/// pulse around the tip while a click pulse shows.
///
/// # Safety
/// Must be called on the thread that owns `hwnd`, in response to WM_PAINT.
unsafe fn paint(hwnd: HWND) {
    let (vx, vy, cx, cy) = virtual_screen();
    let pulses = current_pulses();
    let mut ps = PAINTSTRUCT::default();
    // SAFETY: the caller handles WM_PAINT for `hwnd` on its own thread; every
    // GDI object created here is deleted before returning.
    unsafe {
        let hdc = BeginPaint(hwnd, &mut ps);
        let background = CreateSolidBrush(KEY_COLOR);
        FillRect(hdc, &RECT { left: 0, top: 0, right: cx, bottom: cy }, background);
        let _ = DeleteObject(background.into());
        for ghost in current_ghosts() {
            let scale = monitor_scale(ghost.x, ghost.y);
            let tip = (ghost.x - vx, ghost.y - vy);
            let color = PALETTE[usize::from(ghost.slot) % PALETTE.len()];
            if pulses.contains(&ghost.slot) {
                draw_pulse(hdc, tip, color, scale);
            }
            draw_arrow(hdc, tip, color, scale);
            draw_label(hdc, tip, color, scale, &ghost.label);
        }
        let _ = EndPaint(hwnd, &ps);
    }
}

/// Returns the scale factor of the monitor holding desktop pixel `(x, y)`:
/// 1.0 at 96 DPI, and 1.0 when the DPI cannot be read.
fn monitor_scale(x: i32, y: i32) -> f32 {
    let (mut dx, mut dy) = (0u32, 0u32);
    // SAFETY: plain Win32 calls with valid out pointers.
    let ok = unsafe {
        let monitor = MonitorFromPoint(POINT { x, y }, MONITOR_DEFAULTTONEAREST);
        GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut dx, &mut dy).is_ok()
    };
    if ok && dx > 0 { dx as f32 / 96.0 } else { 1.0 }
}

/// Scales a length in pixels at 100% by `scale`, rounding to whole pixels.
fn scaled(px: i32, scale: f32) -> i32 {
    (px as f32 * scale).round() as i32
}

/// Returns `(r, g, b)` as a GDI color.
fn colorref((r, g, b): (u8, u8, u8)) -> COLORREF {
    COLORREF(u32::from(r) | (u32::from(g) << 8) | (u32::from(b) << 16))
}

/// Returns the label text color that reads best on `background`: [`INK`] on
/// light colors, [`PAPER`] on dark ones.
fn label_text_color((r, g, b): (u8, u8, u8)) -> (u8, u8, u8) {
    let luma = 299 * u32::from(r) + 587 * u32::from(g) + 114 * u32::from(b);
    if luma >= 140_000 { INK } else { PAPER }
}

/// Returns the corners of the ghost arrow with its tip at `tip`, scaled by `scale`.
fn arrow_points(tip: (i32, i32), scale: f32) -> [POINT; ARROW.len()] {
    ARROW.map(|(x, y)| POINT {
        x: tip.0 + scaled(x, scale),
        y: tip.1 + scaled(y, scale),
    })
}

/// Draws the ghost arrow with its tip at `tip`, filled with `color` and
/// outlined in [`INK`].
///
/// # Safety
/// `hdc` must be a valid device context owned by this thread.
unsafe fn draw_arrow(hdc: HDC, tip: (i32, i32), color: (u8, u8, u8), scale: f32) {
    let points = arrow_points(tip, scale);
    // SAFETY: the caller's device context is valid; the pen and brush are
    // deselected and deleted before returning.
    unsafe {
        let pen = CreatePen(PS_SOLID, scaled(1, scale).max(1), colorref(INK));
        let brush = CreateSolidBrush(colorref(color));
        let old_pen = SelectObject(hdc, pen.into());
        let old_brush = SelectObject(hdc, brush.into());
        let _ = Polygon(hdc, &points);
        SelectObject(hdc, old_brush);
        SelectObject(hdc, old_pen);
        let _ = DeleteObject(brush.into());
        let _ = DeleteObject(pen.into());
    }
}

/// Draws a ring of `color` around `tip` that marks a click.
///
/// # Safety
/// `hdc` must be a valid device context owned by this thread.
unsafe fn draw_pulse(hdc: HDC, tip: (i32, i32), color: (u8, u8, u8), scale: f32) {
    let r = scaled(PULSE_DIAMETER / 2, scale);
    // SAFETY: the caller's device context is valid; the pen is deselected
    // and deleted before returning.
    unsafe {
        let pen = CreatePen(PS_SOLID, scaled(PULSE_WIDTH, scale).max(1), colorref(color));
        let old_pen = SelectObject(hdc, pen.into());
        let old_brush = SelectObject(hdc, GetStockObject(NULL_BRUSH));
        let _ = Ellipse(hdc, tip.0 - r, tip.1 - r, tip.0 + r, tip.1 + r);
        SelectObject(hdc, old_brush);
        SelectObject(hdc, old_pen);
        let _ = DeleteObject(pen.into());
    }
}

/// Draws `label` on a box of `color` below and to the right of `tip`, in a
/// font without antialiasing so no edge pixels blend with the key color.
///
/// # Safety
/// `hdc` must be a valid device context owned by this thread.
unsafe fn draw_label(hdc: HDC, tip: (i32, i32), color: (u8, u8, u8), scale: f32, label: &str) {
    if label.is_empty() {
        return;
    }
    let text: Vec<u16> = label.encode_utf16().collect();
    // SAFETY: the caller's device context is valid; the font, pen and brush
    // are deselected and deleted before returning.
    unsafe {
        let font = CreateFontW(
            -scaled(LABEL_FONT_HEIGHT, scale),
            0,
            0,
            0,
            FW_SEMIBOLD.0 as i32,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            NONANTIALIASED_QUALITY,
            (VARIABLE_PITCH.0 | FF_SWISS.0) as u32,
            w!("Segoe UI"),
        );
        let old_font = SelectObject(hdc, font.into());
        let mut size = SIZE::default();
        let _ = GetTextExtentPoint32W(hdc, &text, &mut size);
        let (px, py) = (scaled(LABEL_PADDING.0, scale), scaled(LABEL_PADDING.1, scale));
        let left = tip.0 + scaled(LABEL_OFFSET.0, scale);
        let top = tip.1 + scaled(LABEL_OFFSET.1, scale);
        let (right, bottom) = (left + size.cx + 2 * px, top + size.cy + 2 * py);
        let pen = CreatePen(PS_SOLID, 1, colorref(INK));
        let brush = CreateSolidBrush(colorref(color));
        let old_pen = SelectObject(hdc, pen.into());
        let old_brush = SelectObject(hdc, brush.into());
        let _ = Rectangle(hdc, left, top, right, bottom);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, colorref(label_text_color(color)));
        let _ = TextOutW(hdc, left + px, top + py, &text);
        SelectObject(hdc, old_brush);
        SelectObject(hdc, old_pen);
        SelectObject(hdc, old_font);
        let _ = DeleteObject(brush.into());
        let _ = DeleteObject(pen.into());
        let _ = DeleteObject(font.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that the arrow is about 12x19 pixels at 100%, starts at the
    /// tip and scales with the monitor.
    #[test]
    fn arrow_spans_twelve_by_nineteen_and_scales() {
        let points = arrow_points((100, 50), 1.0);
        assert_eq!((points[0].x, points[0].y), (100, 50));
        let width = points.iter().map(|p| p.x).max().unwrap() - 100;
        let height = points.iter().map(|p| p.y).max().unwrap() - 50;
        assert_eq!((width, height), (12, 19));
        let big = arrow_points((0, 0), 2.0);
        assert_eq!(big.iter().map(|p| p.y).max(), Some(38));
    }

    /// Checks that every palette color gets readable label text and that no
    /// drawing color equals the transparent key color.
    #[test]
    fn label_colors_contrast_and_avoid_the_key() {
        assert_eq!(label_text_color((250, 220, 0)), INK);
        assert_eq!(label_text_color((0, 0, 0)), PAPER);
        for color in PALETTE.into_iter().chain([INK, PAPER]) {
            assert_ne!(colorref(color), KEY_COLOR);
        }
    }

    /// Checks that a click pulse shows for [`PULSE`] and then ends.
    #[test]
    fn pulses_end_after_their_duration() {
        let ghosts = Ghosts::default();
        let t0 = Instant::now();
        ghosts.pulses.lock().unwrap().insert(2, t0);
        assert_eq!(ghosts.pulsing(t0 + PULSE / 2), [2]);
        assert_eq!(ghosts.next_pulse_end(t0 + PULSE / 2), Some(PULSE / 2));
        assert_eq!(ghosts.next_pulse_end(t0 + PULSE), None);
        assert!(ghosts.pulsing(t0 + PULSE).is_empty());
    }

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
