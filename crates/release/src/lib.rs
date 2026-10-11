//! Release-key handling for publishing surf-rac client releases: generating
//! the Ed25519 release key and writing signed `update.json` manifests.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use surf_rac_protocol::update::{UpdateManifest, Version, signing_message, verify};

/// Generates a release key pair.
///
/// # Returns
///
/// The base64 32-byte private seed and the base64 32-byte public key.
pub fn keygen() -> (String, String) {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    (
        STANDARD.encode(key.to_bytes()),
        STANDARD.encode(key.verifying_key().to_bytes()),
    )
}

/// Decodes a base64 32-byte private seed into a signing key.
///
/// # Errors
///
/// Fails when the text is not base64 or does not decode to exactly 32 bytes.
pub fn signing_key(seed_b64: &str) -> anyhow::Result<SigningKey> {
    let raw = STANDARD
        .decode(seed_b64.trim())
        .context("release key is not base64")?;
    let seed: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("release key must decode to 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Builds and signs a manifest for an executable with the given fields, then
/// verifies the result against the key's public half.
///
/// # Errors
///
/// Fails when the version, asset name or hash is malformed, which the
/// verification step reports.
pub fn sign_manifest(
    key: &SigningKey,
    version: &str,
    asset: &str,
    sha256: &str,
    size: u64,
) -> anyhow::Result<UpdateManifest> {
    version
        .parse::<Version>()
        .map_err(|e| anyhow::anyhow!("{version:?}: {e}"))?;
    let signature = key.sign(&signing_message(version, asset, sha256, size));
    let manifest = UpdateManifest {
        version: version.into(),
        asset: asset.into(),
        sha256: sha256.into(),
        size,
        signature: STANDARD.encode(signature.to_bytes()),
    };
    verify(&manifest, key.verifying_key().as_bytes())
        .map_err(|e| anyhow::anyhow!("manifest does not verify: {e}"))?;
    Ok(manifest)
}

/// Hashes the file at `path`.
///
/// # Returns
///
/// The lowercase hex SHA-256 and the size in bytes.
///
/// # Errors
///
/// Fails when the file cannot be read.
pub fn hash_file(path: &Path) -> anyhow::Result<(String, u64)> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), size))
}

/// Signs the executable at `file` as release `version` and returns the
/// manifest JSON, using the file's name as the asset name.
///
/// # Errors
///
/// Fails when the file cannot be read, has no UTF-8 file name, or the
/// manifest fields are malformed.
pub fn sign_file(key: &SigningKey, version: &str, file: &Path) -> anyhow::Result<String> {
    let Some(asset) = file.file_name().and_then(|n| n.to_str()) else {
        bail!("{} has no usable file name", file.display());
    };
    let (sha256, size) = hash_file(file)?;
    let manifest = sign_manifest(key, version, asset, &sha256, size)?;
    Ok(serde_json::to_string_pretty(&manifest)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A generated key signs a manifest that verifies with its public key and
    /// not with another key.
    #[test]
    fn signed_manifest_round_trips() {
        let (seed, public) = keygen();
        let key = signing_key(&seed).unwrap();
        assert_eq!(STANDARD.encode(key.verifying_key().to_bytes()), public);
        let m = sign_manifest(&key, "0.2.0", "surf-rac.exe", &"0f".repeat(32), 7).unwrap();
        assert!(verify(&m, key.verifying_key().as_bytes()).is_ok());
        let (other, _) = keygen();
        let other = signing_key(&other).unwrap();
        assert!(verify(&m, other.verifying_key().as_bytes()).is_err());
    }

    /// Malformed versions and keys are refused before anything is signed.
    #[test]
    fn bad_inputs_are_refused() {
        let (seed, _) = keygen();
        let key = signing_key(&seed).unwrap();
        assert!(sign_manifest(&key, "v0.2.0", "a.exe", &"0f".repeat(32), 1).is_err());
        assert!(sign_manifest(&key, "0.2.0", "a.zip", &"0f".repeat(32), 1).is_err());
        assert!(signing_key("AAAA").is_err());
        assert!(signing_key("not base64").is_err());
    }

    /// Signing a file records its name, size and SHA-256.
    #[test]
    fn sign_file_hashes_the_file() {
        let dir = std::env::temp_dir().join(format!("surf-rac-release-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("surf-rac-0.2.0-windows-x86_64.exe");
        std::fs::write(&file, b"abc").unwrap();
        let (seed, _) = keygen();
        let key = signing_key(&seed).unwrap();
        let json = sign_file(&key, "0.2.0", &file).unwrap();
        let m: UpdateManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m.asset, "surf-rac-0.2.0-windows-x86_64.exe");
        assert_eq!(m.size, 3);
        assert_eq!(
            m.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
