//! Self-update of the client from the project's GitHub releases.
//!
//! The latest release carries the executable and a signed `update.json`. A
//! newer, correctly signed release is downloaded next to the running
//! executable as `<exe>.new` and verified there. Installing it renames the
//! running executable to `<exe>.old`, moves the new file into its place and
//! starts it; the new process removes the leftovers on start.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use surf_rac_protocol::update::{MANIFEST_ASSET, UpdateError, UpdateManifest, Version, verify};

/// Base64 Ed25519 public key that every release manifest must be signed with.
const RELEASE_PUBLIC_KEY: &str = "SKClCiAbz44si3MUhmg4biYKqN3g4b30n+gzRNC3efU=";

/// GitHub API address of the latest published release.
pub const FEED_URL: &str = "https://api.github.com/repos/SLNE-Development/surf-rac/releases/latest";

/// How long after start the first check runs.
pub const CHECK_DELAY: Duration = Duration::from_secs(30);

/// Time between periodic checks.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// How long one feed request may take.
const FEED_TIMEOUT: Duration = Duration::from_secs(15);

/// How long connecting for the download, and each read during it, may take.
const DOWNLOAD_STALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Command-line flag that tells a freshly installed process which process it replaces.
pub const AFTER_UPDATE_FLAG: &str = "--after-update";

/// Returns the version of this build.
pub fn current_version() -> Version {
    env!("CARGO_PKG_VERSION")
        .parse()
        .expect("the crate version is MAJOR.MINOR.PATCH")
}

/// Returns the compiled-in release public key.
fn release_key() -> [u8; 32] {
    STANDARD
        .decode(RELEASE_PUBLIC_KEY)
        .ok()
        .and_then(|raw| raw.try_into().ok())
        .expect("the release public key is 32 bytes of base64")
}

/// Returns the download URL of the asset called `name` in a GitHub release object.
pub fn asset_url(release: &serde_json::Value, name: &str) -> Option<String> {
    release["assets"]
        .as_array()?
        .iter()
        .find(|a| a["name"].as_str() == Some(name))?["browser_download_url"]
        .as_str()
        .map(str::to_owned)
}

/// Returns the URL of the release's `update.json`, if it has one.
pub fn manifest_url(release: &serde_json::Value) -> Option<String> {
    asset_url(release, MANIFEST_ASSET)
}

/// Decides whether `manifest` is an update for a build at `current`.
///
/// # Errors
///
/// Returns the verification error when the manifest is malformed or not
/// signed by `key`.
///
/// # Returns
///
/// The manifest's version when it is strictly newer than `current`, or
/// `None` when it is the same or older.
pub fn decide(
    manifest: &UpdateManifest,
    current: Version,
    key: &[u8; 32],
) -> Result<Option<Version>, UpdateError> {
    let version = verify(manifest, key)?;
    Ok((version > current).then_some(version))
}

/// Returns `<exe>.new`, where a downloaded update waits to be installed.
pub fn staged_path(exe: &Path) -> PathBuf {
    with_suffix(exe, ".new")
}

/// Returns `<exe>.old`, where the replaced executable stays until the next start.
pub fn old_path(exe: &Path) -> PathBuf {
    with_suffix(exe, ".old")
}

/// Appends `suffix` to the full file name of `path`.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Replaces `exe` with the staged `<exe>.new`, keeping the old file as `<exe>.old`.
///
/// A running executable may be renamed on Windows, so this works while the
/// client runs. When moving the staged file into place fails, the original
/// is renamed back.
///
/// # Errors
///
/// Returns the I/O error of the failed rename; `exe` is then unchanged.
pub fn swap(exe: &Path) -> std::io::Result<()> {
    let staged = staged_path(exe);
    let old = old_path(exe);
    if !staged.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no downloaded update",
        ));
    }
    match std::fs::remove_file(&old) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::rename(exe, &old)?;
    if let Err(e) = std::fs::rename(&staged, exe) {
        if let Err(back) = std::fs::rename(&old, exe) {
            tracing::error!(error = %back, "restoring the executable after a failed update failed");
        }
        return Err(e);
    }
    Ok(())
}

/// Removes `<exe>.old` and `<exe>.new` left by an earlier update, ignoring
/// files that do not exist and logging other failures.
pub fn cleanup_leftovers(exe: &Path) {
    for path in [old_path(exe), staged_path(exe)] {
        match std::fs::remove_file(&path) {
            Ok(()) => tracing::info!(path = %path.display(), "removed update leftover"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "update leftover not removed")
            }
        }
    }
}

/// Returns the process id given with `--after-update <pid>`, if present and valid.
pub fn parse_after_update(args: impl IntoIterator<Item = String>) -> Option<u32> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == AFTER_UPDATE_FLAG {
            return args.next()?.parse().ok().filter(|&pid| pid != 0);
        }
    }
    None
}

/// Waits up to `timeout` for process `pid` to exit; returns at once when it
/// is already gone or cannot be opened.
#[cfg(windows)]
pub fn wait_for_exit(pid: u32, timeout: Duration) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };
    // SAFETY: opens a handle with only the right to wait on the process.
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }) else {
        return;
    };
    let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: `handle` is a valid process handle, closed once right after the wait.
    unsafe {
        let _ = WaitForSingleObject(handle, ms);
        let _ = CloseHandle(handle);
    }
}

/// Does nothing off Windows.
#[cfg(not(windows))]
pub fn wait_for_exit(_pid: u32, _timeout: Duration) {}

/// Builds the HTTP client for feed requests.
pub fn feed_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(FEED_TIMEOUT)
        .user_agent(concat!("surf-rac/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("HTTP client with default TLS settings")
}

/// Builds the HTTP client for downloading executables, which limits stalls
/// rather than the total time.
pub fn download_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(DOWNLOAD_STALL_TIMEOUT)
        .read_timeout(DOWNLOAD_STALL_TIMEOUT)
        .user_agent(concat!("surf-rac/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("HTTP client with default TLS settings")
}

/// Turns a non-success feed status into a user-facing message.
fn feed_status_error(status: reqwest::StatusCode) -> String {
    match status.as_u16() {
        404 => "no published release found".into(),
        403 | 429 => "GitHub refused the request; trying again later".into(),
        code => format!("GitHub answered {code}"),
    }
}

/// Fetches the latest release and its manifest and decides whether it is an
/// update for this build.
///
/// # Errors
///
/// Returns a user-facing message when the feed cannot be read or the
/// manifest is malformed or wrongly signed.
///
/// # Returns
///
/// The verified manifest, its version and the executable's download URL when
/// the release is newer; `None` when it is not or has no manifest.
pub async fn fetch_update(
    client: &reqwest::Client,
) -> Result<Option<(UpdateManifest, Version, String)>, String> {
    let release: serde_json::Value = get_json(client, FEED_URL).await?;
    let Some(url) = manifest_url(&release) else {
        return Ok(None);
    };
    let manifest: UpdateManifest = get_json(client, &url).await?;
    let Some(version) =
        decide(&manifest, current_version(), &release_key()).map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let exe_url = asset_url(&release, &manifest.asset)
        .ok_or_else(|| format!("release {version} lacks {}", manifest.asset))?;
    Ok(Some((manifest, version, exe_url)))
}

/// Requests `url` with the GitHub JSON media type and decodes the JSON body.
async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, String> {
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("update server unreachable: {e}"))?;
    if !response.status().is_success() {
        return Err(feed_status_error(response.status()));
    }
    response
        .json()
        .await
        .map_err(|e| format!("unreadable update information: {e}"))
}

/// Accumulates the bytes of a download and checks them against the manifest.
struct Receiver {
    /// Expected size in bytes.
    size: u64,
    /// Bytes received so far.
    received: u64,
    /// Running hash of the received bytes.
    hasher: Sha256,
}

impl Receiver {
    /// Starts receiving a file of `size` bytes.
    fn new(size: u64) -> Self {
        Receiver {
            size,
            received: 0,
            hasher: Sha256::new(),
        }
    }

    /// Adds a chunk.
    ///
    /// # Errors
    ///
    /// Fails once more bytes than expected have arrived.
    fn push(&mut self, chunk: &[u8]) -> Result<(), String> {
        self.received += chunk.len() as u64;
        if self.received > self.size {
            return Err("download is larger than announced".into());
        }
        self.hasher.update(chunk);
        Ok(())
    }

    /// Checks the total size and hash against `sha256`.
    ///
    /// # Errors
    ///
    /// Fails when the size or hash does not match.
    fn finish(self, sha256: &str) -> Result<(), String> {
        if self.received != self.size {
            return Err("download is incomplete".into());
        }
        if hex::encode(self.hasher.finalize()) != sha256 {
            return Err("download does not match the signed hash".into());
        }
        Ok(())
    }
}

/// Downloads `url` into `dest` and checks it against the manifest's size and hash.
///
/// # Errors
///
/// Returns a user-facing message on any network, file or verification
/// failure; `dest` is removed in that case.
pub async fn download(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    manifest: &UpdateManifest,
) -> Result<(), String> {
    let result = download_inner(client, url, dest, manifest).await;
    if result.is_err() {
        let _ = std::fs::remove_file(dest);
    }
    result
}

/// Does the work of [`download`] without removing `dest` on failure.
async fn download_inner(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    manifest: &UpdateManifest,
) -> Result<(), String> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("download failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "download failed: HTTP {}",
            response.status().as_u16()
        ));
    }
    let mut file =
        std::fs::File::create(dest).map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
    let mut receiver = Receiver::new(manifest.size);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("download failed: {e}"))?
    {
        receiver.push(&chunk)?;
        file.write_all(&chunk)
            .map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
    }
    file.sync_all()
        .map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
    receiver.finish(&manifest.sha256)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use surf_rac_protocol::update::signing_message;

    use super::*;

    /// Builds a manifest for `version` signed by a key derived from `seed`,
    /// returning it with the public key.
    fn signed(version: &str, seed: u8) -> (UpdateManifest, [u8; 32]) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let (asset, sha256, size) = ("surf-rac.exe", "ab".repeat(32), 9);
        let sig = key.sign(&signing_message(version, asset, &sha256, size));
        let m = UpdateManifest {
            version: version.into(),
            asset: asset.into(),
            sha256,
            size,
            signature: STANDARD.encode(sig.to_bytes()),
        };
        (m, key.verifying_key().to_bytes())
    }

    /// Returns a fresh, empty temporary directory for one test.
    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("surf-rac-update-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The compiled-in release key and crate version are well formed.
    #[test]
    fn built_in_key_and_version_parse() {
        assert_eq!(release_key().len(), 32);
        let _ = current_version();
    }

    /// Only a strictly newer, correctly signed release is an update.
    #[test]
    fn only_newer_signed_releases_are_updates() {
        let current: Version = "0.2.0".parse().unwrap();
        let (newer, key) = signed("0.3.0", 1);
        assert_eq!(
            decide(&newer, current, &key),
            Ok(Some("0.3.0".parse().unwrap()))
        );
        let (same, key) = signed("0.2.0", 1);
        assert_eq!(decide(&same, current, &key), Ok(None));
        let (older, key) = signed("0.1.9", 1);
        assert_eq!(decide(&older, current, &key), Ok(None));
        let (_, other) = signed("0.3.0", 2);
        assert_eq!(decide(&newer, current, &other), Err(UpdateError::Signature));
    }

    /// Assets are found by exact name in a GitHub release object.
    #[test]
    fn assets_are_selected_by_name() {
        let release = serde_json::json!({
            "tag_name": "v0.3.0",
            "assets": [
                {"name": "surf-rac-0.3.0-windows-x86_64.exe", "browser_download_url": "https://x/exe"},
                {"name": "update.json", "browser_download_url": "https://x/manifest"}
            ]
        });
        assert_eq!(
            manifest_url(&release).as_deref(),
            Some("https://x/manifest")
        );
        assert_eq!(
            asset_url(&release, "surf-rac-0.3.0-windows-x86_64.exe").as_deref(),
            Some("https://x/exe")
        );
        assert_eq!(asset_url(&release, "update"), None);
        assert_eq!(
            manifest_url(&serde_json::json!({"message": "Not Found"})),
            None
        );
    }

    /// The staged and old paths append to the full file name.
    #[test]
    fn leftover_paths_append_suffixes() {
        let exe = Path::new(r"C:\Tools\surf-rac.exe");
        assert_eq!(staged_path(exe), Path::new(r"C:\Tools\surf-rac.exe.new"));
        assert_eq!(old_path(exe), Path::new(r"C:\Tools\surf-rac.exe.old"));
    }

    /// A swap moves the staged file into place and keeps the old one.
    #[test]
    fn swap_installs_the_staged_file() {
        let dir = temp_dir("swap");
        let exe = dir.join("surf-rac.exe");
        std::fs::write(&exe, b"old").unwrap();
        std::fs::write(staged_path(&exe), b"new").unwrap();
        std::fs::write(old_path(&exe), b"older").unwrap();
        swap(&exe).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
        assert_eq!(std::fs::read(old_path(&exe)).unwrap(), b"old");
        assert!(!staged_path(&exe).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without a staged file nothing changes.
    #[test]
    fn swap_without_staged_file_changes_nothing() {
        let dir = temp_dir("nostage");
        let exe = dir.join("surf-rac.exe");
        std::fs::write(&exe, b"old").unwrap();
        assert!(swap(&exe).is_err());
        assert_eq!(std::fs::read(&exe).unwrap(), b"old");
        assert!(!old_path(&exe).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// When the staged file cannot be moved into place, the original returns.
    #[cfg(windows)]
    #[test]
    fn failed_swap_restores_the_original() {
        use std::os::windows::fs::OpenOptionsExt;
        /// Share mode that allows others to read only, so renaming the file fails.
        const FILE_SHARE_READ: u32 = 1;
        let dir = temp_dir("rollback");
        let exe = dir.join("surf-rac.exe");
        std::fs::write(&exe, b"old").unwrap();
        std::fs::write(staged_path(&exe), b"new").unwrap();
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(staged_path(&exe))
            .unwrap();
        assert!(swap(&exe).is_err());
        assert_eq!(std::fs::read(&exe).unwrap(), b"old");
        assert!(!old_path(&exe).exists());
        drop(lock);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cleanup removes both leftovers and tolerates their absence.
    #[test]
    fn cleanup_removes_leftovers() {
        let dir = temp_dir("cleanup");
        let exe = dir.join("surf-rac.exe");
        std::fs::write(old_path(&exe), b"x").unwrap();
        std::fs::write(staged_path(&exe), b"y").unwrap();
        cleanup_leftovers(&exe);
        assert!(!old_path(&exe).exists());
        assert!(!staged_path(&exe).exists());
        cleanup_leftovers(&exe);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The previous process id is read only from a well-formed flag.
    #[test]
    fn after_update_flag_is_parsed() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            parse_after_update(args(&["surf-rac.exe", "--after-update", "4242"])),
            Some(4242)
        );
        assert_eq!(parse_after_update(args(&["surf-rac.exe"])), None);
        assert_eq!(
            parse_after_update(args(&["surf-rac.exe", "--after-update"])),
            None
        );
        assert_eq!(
            parse_after_update(args(&["surf-rac.exe", "--after-update", "x"])),
            None
        );
        assert_eq!(
            parse_after_update(args(&["surf-rac.exe", "--after-update", "0"])),
            None
        );
    }

    /// A download is accepted only with the announced size and hash.
    #[test]
    fn received_bytes_are_checked() {
        let sha = hex::encode(Sha256::digest(b"abc"));
        let mut ok = Receiver::new(3);
        ok.push(b"ab").unwrap();
        ok.push(b"c").unwrap();
        assert!(ok.finish(&sha).is_ok());

        let mut short = Receiver::new(4);
        short.push(b"abc").unwrap();
        assert!(short.finish(&sha).is_err());

        let mut long = Receiver::new(2);
        assert!(long.push(b"abc").is_err());

        let mut wrong = Receiver::new(3);
        wrong.push(b"abd").unwrap();
        assert!(wrong.finish(&sha).is_err());
    }
}
