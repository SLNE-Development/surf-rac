//! Signed update manifests that describe a release of the Windows client.
//!
//! A release publishes the client executable together with `update.json`, an
//! [`UpdateManifest`] naming the version, the executable's file name, its
//! SHA-256 and size, and an Ed25519 signature over those fields made with the
//! release key. Clients install an executable only after [`verify`] accepts
//! its manifest against the release public key they were built with.

use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Domain tag that starts every signed manifest message.
const DOMAIN: &str = "surf-rac-update-v1";

/// Name of the manifest asset in every release.
pub const MANIFEST_ASSET: &str = "update.json";

/// A client version: `MAJOR.MINOR.PATCH`, ordered numerically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
}

impl FromStr for Version {
    type Err = UpdateError;

    /// Parses exactly three dot-separated decimal numbers, such as `1.2.3`.
    ///
    /// Signs, spaces, empty parts, pre-release or build suffixes and numbers
    /// that do not fit a `u32` are rejected.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('.');
        let mut next = || -> Result<u32, UpdateError> {
            let part = parts.next().ok_or(UpdateError::Version)?;
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(UpdateError::Version);
            }
            part.parse().map_err(|_| UpdateError::Version)
        };
        let version = Version {
            major: next()?,
            minor: next()?,
            patch: next()?,
        };
        if parts.next().is_some() {
            return Err(UpdateError::Version);
        }
        Ok(version)
    }
}

impl fmt::Display for Version {
    /// Formats the version as `MAJOR.MINOR.PATCH`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The signed description of one release's executable (`update.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateManifest {
    /// The release's client version.
    pub version: String,
    /// File name of the executable asset in the same release.
    pub asset: String,
    /// SHA-256 of the executable, 64 lowercase hex characters.
    pub sha256: String,
    /// Size of the executable in bytes.
    pub size: u64,
    /// Base64 Ed25519 signature over [`signing_message`] of the other fields.
    pub signature: String,
}

/// Why a manifest was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpdateError {
    /// The version is not `MAJOR.MINOR.PATCH`.
    #[error("invalid version")]
    Version,
    /// The asset name is not a plain `.exe` file name.
    #[error("invalid asset name")]
    Asset,
    /// The SHA-256 is not 64 lowercase hex characters.
    #[error("invalid sha256")]
    Sha256,
    /// The signature is malformed or does not verify.
    #[error("update signature invalid")]
    Signature,
    /// The public key is not a valid Ed25519 key.
    #[error("invalid release key")]
    Key,
}

/// Returns the bytes the release key signs for a manifest with these fields:
/// the domain tag, version, asset, sha256 and size, each on its own line.
pub fn signing_message(version: &str, asset: &str, sha256: &str, size: u64) -> Vec<u8> {
    format!("{DOMAIN}\n{version}\n{asset}\n{sha256}\n{size}").into_bytes()
}

/// Checks that `asset` is a plain executable file name: only ASCII letters,
/// digits, `.`, `_` and `-`, not starting with `.`, and ending in `.exe`.
fn valid_asset(asset: &str) -> bool {
    !asset.starts_with('.')
        && asset.len() > ".exe".len()
        && asset.ends_with(".exe")
        && asset
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Checks that `sha256` is exactly 64 lowercase hex characters.
fn valid_sha256(sha256: &str) -> bool {
    sha256.len() == 64
        && sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Checks the manifest's fields and its signature against `public_key`.
///
/// # Errors
///
/// Returns the first problem found: a malformed version, asset name or
/// SHA-256, an invalid public key, or a signature that is malformed or does
/// not verify strictly.
///
/// # Returns
///
/// The manifest's parsed version.
pub fn verify(manifest: &UpdateManifest, public_key: &[u8; 32]) -> Result<Version, UpdateError> {
    let version: Version = manifest.version.parse()?;
    if !valid_asset(&manifest.asset) {
        return Err(UpdateError::Asset);
    }
    if !valid_sha256(&manifest.sha256) {
        return Err(UpdateError::Sha256);
    }
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| UpdateError::Key)?;
    let raw = STANDARD
        .decode(&manifest.signature)
        .map_err(|_| UpdateError::Signature)?;
    let signature = Signature::from_slice(&raw).map_err(|_| UpdateError::Signature)?;
    let message = signing_message(
        &manifest.version,
        &manifest.asset,
        &manifest.sha256,
        manifest.size,
    );
    key.verify_strict(&message, &signature)
        .map_err(|_| UpdateError::Signature)?;
    Ok(version)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    /// Returns a signing key derived from a fixed seed byte.
    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Builds a manifest for version 1.2.3 signed by `signer`.
    fn manifest(signer: &SigningKey) -> UpdateManifest {
        let (version, asset, sha256, size) = (
            "1.2.3",
            "surf-rac-1.2.3-windows-x86_64.exe",
            "ab".repeat(32),
            42,
        );
        let sig = signer.sign(&signing_message(version, asset, &sha256, size));
        UpdateManifest {
            version: version.into(),
            asset: asset.into(),
            sha256,
            size,
            signature: STANDARD.encode(sig.to_bytes()),
        }
    }

    /// Valid versions parse into their three numbers and print back unchanged.
    #[test]
    fn versions_parse_and_print() {
        let v: Version = "10.0.7".parse().unwrap();
        assert_eq!((v.major, v.minor, v.patch), (10, 0, 7));
        assert_eq!(v.to_string(), "10.0.7");
    }

    /// Anything other than three plain decimal numbers is refused.
    #[test]
    fn malformed_versions_are_refused() {
        for s in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "1..3",
            "+1.2.3",
            "1.2.-3",
            " 1.2.3",
            "1.2.3-rc1",
            "1.2.99999999999",
        ] {
            assert_eq!(s.parse::<Version>(), Err(UpdateError::Version), "{s:?}");
        }
    }

    /// Versions order numerically, not as text.
    #[test]
    fn versions_order_numerically() {
        let v = |s: &str| s.parse::<Version>().unwrap();
        assert!(v("0.10.0") > v("0.9.9"));
        assert!(v("1.0.0") > v("0.99.99"));
        assert!(v("0.1.2") > v("0.1.1"));
        assert_eq!(v("0.1.0"), v("0.1.0"));
    }

    /// A correctly signed manifest verifies and yields its version.
    #[test]
    fn signed_manifest_verifies() {
        let k = key(1);
        let m = manifest(&k);
        assert_eq!(
            verify(&m, k.verifying_key().as_bytes()),
            Ok("1.2.3".parse().unwrap())
        );
    }

    /// A manifest signed by another key is refused.
    #[test]
    fn wrong_key_is_refused() {
        let m = manifest(&key(1));
        assert_eq!(
            verify(&m, key(2).verifying_key().as_bytes()),
            Err(UpdateError::Signature)
        );
    }

    /// Changing any signed field after signing breaks the signature.
    #[test]
    fn tampered_fields_are_refused() {
        let k = key(1);
        let pk = *k.verifying_key().as_bytes();
        let tamper: [fn(&mut UpdateManifest); 4] = [
            |m| m.version = "9.9.9".into(),
            |m| m.asset = "other.exe".into(),
            |m| m.sha256 = "cd".repeat(32),
            |m| m.size += 1,
        ];
        for t in tamper {
            let mut m = manifest(&k);
            t(&mut m);
            assert_eq!(verify(&m, &pk), Err(UpdateError::Signature), "{m:?}");
        }
    }

    /// Malformed signatures are refused without panicking.
    #[test]
    fn malformed_signatures_are_refused() {
        let k = key(1);
        let pk = *k.verifying_key().as_bytes();
        for sig in ["", "not base64!", "AAAA"] {
            let mut m = manifest(&k);
            m.signature = sig.into();
            assert_eq!(verify(&m, &pk), Err(UpdateError::Signature), "{sig:?}");
        }
    }

    /// Asset names with paths, other extensions or odd characters are refused.
    #[test]
    fn unsafe_asset_names_are_refused() {
        let k = key(1);
        let pk = *k.verifying_key().as_bytes();
        for asset in [
            "../x.exe",
            r"a\b.exe",
            "x.msi",
            ".exe",
            ".hidden.exe",
            "a b.exe",
            "x.exe\n",
        ] {
            let mut m = manifest(&k);
            m.asset = asset.into();
            assert_eq!(verify(&m, &pk), Err(UpdateError::Asset), "{asset:?}");
        }
    }

    /// Hashes in upper case or of the wrong length are refused.
    #[test]
    fn malformed_hashes_are_refused() {
        let k = key(1);
        let pk = *k.verifying_key().as_bytes();
        for sha in ["AB".repeat(32), "ab".repeat(31), "zz".repeat(32)] {
            let mut m = manifest(&k);
            m.sha256 = sha;
            assert_eq!(verify(&m, &pk), Err(UpdateError::Sha256));
        }
    }

    /// The manifest reads from and writes to the documented JSON shape.
    #[test]
    fn manifest_json_shape() {
        let json =
            r#"{"version":"0.2.0","asset":"a.exe","sha256":"00","size":5,"signature":"c2ln"}"#;
        let m: UpdateManifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.size, 5);
        assert_eq!(serde_json::to_string(&m).unwrap(), json);
    }
}
