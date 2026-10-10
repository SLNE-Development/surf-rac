//! The hardware fingerprint a device registers with: a hash of the Windows MachineGuid.

use sha2::{Digest, Sha256};

/// Prefix hashed in front of the MachineGuid; its version changes every fingerprint when bumped.
const PREFIX: &str = "surf-rac-fingerprint-v1:";

/// Why the fingerprint could not be computed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FingerprintError {
    /// The MachineGuid registry value could not be read.
    #[error("could not read the machine GUID: {0}")]
    Unreadable(String),
    /// This platform has no MachineGuid.
    #[error("device fingerprints are only supported on Windows")]
    Unsupported,
}

/// Returns the fingerprint hash of `machine_guid`: 64 lowercase hex characters.
///
/// The GUID is trimmed and lower-cased first, so its spelling does not matter.
pub fn hash_machine_guid(machine_guid: &str) -> String {
    let digest = Sha256::new()
        .chain_update(PREFIX.as_bytes())
        .chain_update(machine_guid.trim().to_lowercase().as_bytes())
        .finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Returns this machine's fingerprint hash.
pub fn fingerprint_hash() -> Result<String, FingerprintError> {
    machine_guid().map(|guid| hash_machine_guid(&guid))
}

/// Reads `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` from the 64-bit registry view.
#[cfg(windows)]
fn machine_guid() -> Result<String, FingerprintError> {
    use windows::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegGetValueW,
    };
    use windows::core::w;
    let mut buf = [0u16; 128];
    let mut size = std::mem::size_of_val(&buf) as u32;
    // SAFETY: `buf` is writable for `size` bytes and outlives the call.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!("SOFTWARE\\Microsoft\\Cryptography"),
            w!("MachineGuid"),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if status.is_err() {
        return Err(FingerprintError::Unreadable(format!("{status:?}")));
    }
    let chars = (size as usize / 2).min(buf.len());
    let guid = String::from_utf16_lossy(&buf[..chars]);
    let guid = guid.trim_end_matches('\0').trim().to_string();
    if guid.is_empty() {
        return Err(FingerprintError::Unreadable("empty value".into()));
    }
    Ok(guid)
}

/// Fails: there is no MachineGuid off Windows.
#[cfg(not(windows))]
fn machine_guid() -> Result<String, FingerprintError> {
    Err(FingerprintError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that the machine GUID hash is the SHA-256 of the prefixed GUID as 64
    /// lowercase hex digits.
    #[test]
    fn hash_is_prefixed_sha256_in_lowercase_hex() {
        let guid = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";
        let expected: String = Sha256::digest(format!("{PREFIX}{guid}").as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let hash = hash_machine_guid(guid);
        assert_eq!(hash, expected);
        assert_eq!(hash.len(), 64);
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    /// Checks that case and surrounding whitespace in the machine GUID do not change
    /// the hash.
    #[test]
    fn spelling_of_guid_does_not_matter() {
        assert_eq!(
            hash_machine_guid(" 1B4E28BA-2FA1-11D2-883F-0016D3CCA427\n"),
            hash_machine_guid("1b4e28ba-2fa1-11d2-883f-0016d3cca427")
        );
    }

    /// Checks that this machine yields a stable 64-character fingerprint hash.
    #[cfg(windows)]
    #[test]
    fn this_machine_has_a_fingerprint() {
        let hash = fingerprint_hash().unwrap();
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, fingerprint_hash().unwrap());
    }
}
