//! One running client per Windows user and state directory.
//!
//! The first process for a state directory takes a named mutex and publishes
//! its process id in a named file mapping. A later process for the same state
//! directory finds the first one's main window through that process id, brings
//! it to the front and reports that it should exit.

use std::path::Path;

use sha2::{Digest, Sha256};

/// Result of trying to become the running instance.
pub enum Acquired {
    /// This process is the running instance; the guard must live as long as the process.
    First(Guard),
    /// Another process already runs for this state directory and was asked to show its window.
    AlreadyRunning,
}

/// Keeps the single-instance mutex and the published process id alive.
///
/// Dropping the guard releases the claim, so the caller holds it for the
/// whole process lifetime.
pub struct Guard {
    /// Operating-system handles that stay open until the guard is dropped.
    #[cfg(windows)]
    handles: Vec<windows::Win32::Foundation::HANDLE>,
}

#[cfg(windows)]
impl Drop for Guard {
    /// Closes the mutex and file-mapping handles.
    fn drop(&mut self) {
        for h in self.handles.drain(..) {
            // SAFETY: each handle was returned by the OS and is closed exactly once.
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(h);
            }
        }
    }
}

/// Normalises a state directory path so equivalent spellings compare equal:
/// the extended-length prefix is removed, `/` becomes `\`, trailing
/// separators are dropped and the text is lower-cased.
pub fn normalize_path(path: &str) -> String {
    let p = path.strip_prefix(r"\\?\").unwrap_or(path);
    let p = p.replace('/', "\\").to_lowercase();
    let trimmed = p.trim_end_matches('\\');
    if trimmed.is_empty() {
        p
    } else {
        trimmed.to_string()
    }
}

/// Derives the object-name suffix for a state directory: the first 16 hex
/// characters of the SHA-256 of its normalised path.
pub fn name_suffix(path: &str) -> String {
    let digest = Sha256::digest(normalize_path(path).as_bytes());
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Returns the mutex name for a state directory path.
pub fn mutex_name(path: &str) -> String {
    format!("Local\\surf-rac-{}", name_suffix(path))
}

/// Returns the name of the file mapping that carries the first instance's process id.
pub fn pid_mapping_name(path: &str) -> String {
    format!("Local\\surf-rac-{}-pid", name_suffix(path))
}

/// Resolves a state directory to an absolute path, canonical when it exists.
#[cfg(windows)]
fn resolve_dir(dir: &Path) -> String {
    let resolved = std::fs::canonicalize(dir)
        .or_else(|_| std::path::absolute(dir))
        .unwrap_or_else(|_| dir.to_path_buf());
    resolved.to_string_lossy().into_owned()
}

/// Claims the single-instance slot for `state_dir`.
///
/// When another process already holds it, that process's main window is
/// restored and focused and [`Acquired::AlreadyRunning`] is returned. If the
/// operating system refuses to create the mutex, the process proceeds as the
/// first instance without a claim.
#[cfg(windows)]
pub fn acquire(state_dir: &Path) -> Acquired {
    use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
    use windows::Win32::System::Threading::{CreateMutexW, GetCurrentProcessId};
    use windows::core::HSTRING;

    let path = resolve_dir(state_dir);
    let name = HSTRING::from(mutex_name(&path));
    // SAFETY: the name is a valid NUL-terminated wide string for the call.
    let mutex = match unsafe { CreateMutexW(None, false, &name) } {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "single-instance mutex unavailable");
            return Acquired::First(Guard {
                handles: Vec::new(),
            });
        }
    };
    // SAFETY: reads the thread's last error right after CreateMutexW.
    let exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    if exists {
        // SAFETY: handle returned above, closed once.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(mutex);
        }
        if let Some(pid) = read_pid(&path) {
            focus_process_window(pid);
        }
        return Acquired::AlreadyRunning;
    }
    let mut handles = vec![mutex];
    // SAFETY: plain query of the current process id.
    let pid = unsafe { GetCurrentProcessId() };
    if let Some(h) = publish_pid(&path, pid) {
        handles.push(h);
    }
    Acquired::First(Guard { handles })
}

/// Off Windows there is no guard; the process always proceeds.
#[cfg(not(windows))]
pub fn acquire(_state_dir: &Path) -> Acquired {
    Acquired::First(Guard {})
}

/// Stores `pid` in a named file mapping and returns the mapping handle, which
/// must stay open so the mapping survives.
#[cfg(windows)]
fn publish_pid(path: &str, pid: u32) -> Option<windows::Win32::Foundation::HANDLE> {
    use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows::Win32::System::Memory::{
        CreateFileMappingW, FILE_MAP_WRITE, MapViewOfFile, PAGE_READWRITE, UnmapViewOfFile,
    };
    use windows::core::HSTRING;

    let name = HSTRING::from(pid_mapping_name(path));
    // SAFETY: anonymous 4-byte mapping with a valid wide-string name.
    let handle =
        unsafe { CreateFileMappingW(INVALID_HANDLE_VALUE, None, PAGE_READWRITE, 0, 4, &name) }
            .ok()?;
    // SAFETY: the mapping is at least 4 bytes and the view is unmapped right after the write.
    unsafe {
        let view = MapViewOfFile(handle, FILE_MAP_WRITE, 0, 0, 4);
        if view.Value.is_null() {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            return None;
        }
        std::ptr::write_volatile(view.Value as *mut u32, pid);
        let _ = UnmapViewOfFile(view);
    }
    Some(handle)
}

/// Reads the process id published by the running instance, retrying briefly
/// because the first instance publishes it right after taking the mutex.
#[cfg(windows)]
fn read_pid(path: &str) -> Option<u32> {
    use windows::Win32::System::Memory::{
        FILE_MAP_READ, MapViewOfFile, OpenFileMappingW, UnmapViewOfFile,
    };
    use windows::core::HSTRING;

    let name = HSTRING::from(pid_mapping_name(path));
    for _ in 0..20 {
        // SAFETY: valid wide-string name; the handle is closed below.
        if let Ok(handle) = unsafe { OpenFileMappingW(FILE_MAP_READ.0, false, &name) } {
            // SAFETY: the mapping is 4 bytes; the view is unmapped before return.
            let pid = unsafe {
                let view = MapViewOfFile(handle, FILE_MAP_READ, 0, 0, 4);
                let pid = if view.Value.is_null() {
                    None
                } else {
                    let v = std::ptr::read_volatile(view.Value as *const u32);
                    let _ = UnmapViewOfFile(view);
                    Some(v)
                };
                let _ = windows::Win32::Foundation::CloseHandle(handle);
                pid
            };
            if pid.is_some_and(|p| p != 0) {
                return pid;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    None
}

/// Candidate state while searching a process's top-level windows.
#[cfg(windows)]
struct Search {
    /// Process whose window is wanted.
    pid: u32,
    /// Best window found so far.
    best: Option<windows::Win32::Foundation::HWND>,
    /// Whether `best` carries the application title.
    titled: bool,
}

/// Window-enumeration callback: records the best candidate window of the
/// searched process, preferring one titled `surf-rac`.
#[cfg(windows)]
unsafe extern "system" fn visit(
    hwnd: windows::Win32::Foundation::HWND,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::core::BOOL {
    use windows::Win32::UI::WindowsAndMessaging::{
        GW_OWNER, GetWindow, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    };
    // SAFETY: lparam points at the `Search` owned by the caller of EnumWindows.
    let s = unsafe { &mut *(lparam.0 as *mut Search) };
    let mut owner = 0u32;
    // SAFETY: `hwnd` is a valid window handle supplied by the enumeration.
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut owner));
        if owner != s.pid
            || !IsWindowVisible(hwnd).as_bool()
            || GetWindow(hwnd, GW_OWNER).is_ok_and(|w| !w.is_invalid())
        {
            return true.into();
        }
        let mut buf = [0u16; 64];
        let n = GetWindowTextW(hwnd, &mut buf).max(0) as usize;
        let titled = String::from_utf16_lossy(&buf[..n]) == "surf-rac";
        if s.best.is_none() || (titled && !s.titled) {
            s.best = Some(hwnd);
            s.titled = titled;
        }
    }
    true.into()
}

/// Restores (if minimised) and focuses the main window of process `pid`.
///
/// The main window is the visible, unowned top-level window of the process;
/// when there are several, the one titled `surf-rac` wins.
#[cfg(windows)]
fn focus_process_window(pid: u32) {
    use windows::Win32::Foundation::LPARAM;
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, IsIconic, SW_RESTORE, SetForegroundWindow, ShowWindow,
    };

    let mut search = Search {
        pid,
        best: None,
        titled: false,
    };
    // SAFETY: the callback only runs during this call and `search` outlives it.
    unsafe {
        let _ = EnumWindows(Some(visit), LPARAM(&mut search as *mut Search as isize));
        if let Some(hwnd) = search.best {
            if IsIconic(hwnd).as_bool() {
                let _ = ShowWindow(hwnd, SW_RESTORE);
            }
            let _ = SetForegroundWindow(hwnd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The suffix is 16 lowercase hex characters.
    #[test]
    fn suffix_is_sixteen_hex_chars() {
        let s = name_suffix(r"C:\Users\a\AppData\Roaming\surf-rac");
        assert_eq!(s.len(), 16);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    /// The suffix is the leading half of the SHA-256 of the normalised path.
    #[test]
    fn suffix_matches_sha256_prefix() {
        let expected: String = Sha256::digest(b"c:\\x")
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(name_suffix(r"C:\X"), expected);
    }

    /// Case, separator style, extended prefix and trailing separators do not matter.
    #[test]
    fn equivalent_spellings_share_a_name() {
        let a = mutex_name(r"C:\Data\Surf");
        assert_eq!(a, mutex_name(r"c:/data/surf/"));
        assert_eq!(a, mutex_name(r"\\?\C:\Data\Surf"));
    }

    /// Different state directories get different names.
    #[test]
    fn different_dirs_get_different_names() {
        assert_ne!(mutex_name(r"C:\a"), mutex_name(r"C:\b"));
    }

    /// Names live in the per-session namespace and the pid mapping is distinct.
    #[test]
    fn names_use_local_namespace() {
        let m = mutex_name(r"C:\a");
        assert!(m.starts_with("Local\\surf-rac-"));
        assert_ne!(m, pid_mapping_name(r"C:\a"));
    }

    /// A second acquire for the same directory is refused while the first guard
    /// lives, and a different directory is independent.
    #[cfg(windows)]
    #[test]
    fn second_acquire_same_dir_is_refused() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("surf-rac-si-{nanos}"));
        let a = base.join("a");
        let b = base.join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let first = acquire(&a);
        assert!(matches!(first, Acquired::First(_)));
        assert!(matches!(acquire(&a), Acquired::AlreadyRunning));
        assert!(matches!(acquire(&b), Acquired::First(_)));
        drop(first);
        assert!(matches!(acquire(&a), Acquired::First(_)));
        let _ = std::fs::remove_dir_all(&base);
    }
}
