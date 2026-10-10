//! Protection of secrets at rest with the Windows Data Protection API in user scope.

/// Extra entropy mixed into every protected blob of the client.
const ENTROPY: &[u8] = b"surf-rac-state-v1";

/// Why data could not be protected or unprotected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DpapiError {
    /// The operating system refused the operation, for example for a blob of
    /// another user or machine, or one that was altered.
    #[error("data protection failed: {0}")]
    Failed(String),
    /// This platform has no data protection API.
    #[error("data protection is only supported on Windows")]
    Unsupported,
}

/// Encrypts `data` so only the current Windows user on this machine can decrypt it.
#[cfg(windows)]
pub fn protect(data: &[u8]) -> Result<Vec<u8>, DpapiError> {
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };
    let input = blob(data);
    let entropy = blob(ENTROPY);
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: the input blobs point at live slices for the duration of the
    // call, and the output blob is released by `take` below.
    unsafe {
        CryptProtectData(
            &input,
            windows::core::PCWSTR::null(),
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|e| DpapiError::Failed(e.message()))?;
        Ok(take(output))
    }
}

/// Decrypts a blob made by [`protect`] for the current user.
#[cfg(windows)]
pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, DpapiError> {
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };
    let input = blob(data);
    let entropy = blob(ENTROPY);
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as in `protect`.
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|e| DpapiError::Failed(e.message()))?;
        Ok(take(output))
    }
}

/// Wraps `data` in a blob descriptor that borrows it.
#[cfg(windows)]
fn blob(data: &[u8]) -> windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
    windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

/// Copies a blob the system allocated into a vector and frees the system copy.
///
/// # Safety
///
/// `blob` must come from a successful `CryptProtectData` or `CryptUnprotectData` call.
#[cfg(windows)]
unsafe fn take(blob: windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB) -> Vec<u8> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    if blob.pbData.is_null() {
        return Vec::new();
    }
    // SAFETY: the system returned `cbData` readable bytes at `pbData`, which
    // are freed exactly once with `LocalFree` after copying.
    unsafe {
        let out = std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(blob.pbData.cast())));
        out
    }
}

/// Returns `data` unchanged; stands in for the data protection API in tests off Windows.
#[cfg(all(not(windows), test))]
pub fn protect(data: &[u8]) -> Result<Vec<u8>, DpapiError> {
    Ok(data.to_vec())
}

/// Returns `data` unchanged; stands in for the data protection API in tests off Windows.
#[cfg(all(not(windows), test))]
pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, DpapiError> {
    Ok(data.to_vec())
}

/// Fails: there is no data protection API off Windows.
#[cfg(all(not(windows), not(test)))]
pub fn protect(_data: &[u8]) -> Result<Vec<u8>, DpapiError> {
    Err(DpapiError::Unsupported)
}

/// Fails: there is no data protection API off Windows.
#[cfg(all(not(windows), not(test)))]
pub fn unprotect(_data: &[u8]) -> Result<Vec<u8>, DpapiError> {
    Err(DpapiError::Unsupported)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// Checks that protected data differs from the input and unprotects back to it.
    #[test]
    fn round_trips() {
        let blob = protect(b"secret").unwrap();
        assert_ne!(blob, b"secret");
        assert_eq!(unprotect(&blob).unwrap(), b"secret");
    }

    /// Checks that an altered or arbitrary blob fails to unprotect.
    #[test]
    fn altered_blob_fails() {
        let mut blob = protect(b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(unprotect(&blob).is_err());
        assert!(unprotect(b"garbage").is_err());
    }
}
