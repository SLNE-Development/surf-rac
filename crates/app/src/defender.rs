//! The Microsoft Defender exclusion for the client's executable, added
//! through an elevated PowerShell after a UAC prompt.

use std::path::Path;

/// Returns the PowerShell arguments that exclude the executable `exe` from
/// Defender scans, both as a file and as a process; its folder is not excluded.
///
/// The path is quoted for PowerShell's single-quoted strings.
pub fn exclusion_arguments(exe: &Path) -> String {
    let path = exe.display().to_string().replace('\'', "''");
    format!(
        "-NoProfile -NonInteractive -WindowStyle Hidden -Command \"Add-MpPreference -ExclusionPath '{path}' -ExclusionProcess '{path}'\""
    )
}

/// Asks Windows to run the exclusion command elevated for this executable.
///
/// Returns once the UAC prompt was shown; fails when the user cancels it or
/// the command cannot be started.
#[cfg(windows)]
pub fn add_exclusion() -> Result<(), String> {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    use windows::core::{HSTRING, PCWSTR, w};
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let args = HSTRING::from(exclusion_arguments(&exe));
    // SAFETY: all strings are valid, NUL-terminated wide strings for the call.
    let result = unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            w!("powershell.exe"),
            &args,
            PCWSTR::null(),
            SW_HIDE,
        )
    };
    if result.0 as isize > 32 {
        Ok(())
    } else {
        Err("The exclusion was not added (the prompt was cancelled or failed).".into())
    }
}

/// Fails: Defender exists only on Windows.
#[cfg(not(windows))]
pub fn add_exclusion() -> Result<(), String> {
    Err("Defender exclusions are only supported on Windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_is_single_quoted_and_escaped() {
        let args = exclusion_arguments(Path::new(r"C:\Users\O'Neil\Downloads\surf-rac.exe"));
        assert!(args.contains(r"-ExclusionPath 'C:\Users\O''Neil\Downloads\surf-rac.exe'"));
        assert!(args.contains(r"-ExclusionProcess 'C:\Users\O''Neil\Downloads\surf-rac.exe'"));
        assert!(args.starts_with("-NoProfile"));
    }
}
