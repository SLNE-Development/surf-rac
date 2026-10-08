//! The client's persistent state: one JSON file per Windows user whose secret
//! fields are protected with the data protection API.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use surf_rac_protocol::DeviceId;

use crate::dpapi;

/// Version of the state file format this build writes.
pub const STATE_VERSION: u32 = 1;

/// Name of the state file inside the state directory.
const FILE_NAME: &str = "state.json";

/// Environment variable that overrides the state directory.
pub const STATE_DIR_ENV: &str = "SURF_RAC_STATE_DIR";

/// A secret held in memory in plain text and written to disk only protected.
///
/// It serialises as standard base64 of a data protection blob; its `Debug`
/// output never shows the value.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wraps a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the plain-text value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    /// Writes a placeholder instead of the value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl Serialize for Secret {
    /// Protects the value and writes the blob as base64.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let blob = dpapi::protect(self.0.as_bytes()).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&STANDARD.encode(blob))
    }
}

impl<'de> Deserialize<'de> for Secret {
    /// Reads a base64 blob and unprotects it; fails for blobs this user cannot decrypt.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        reveal(&text).ok_or_else(|| serde::de::Error::custom("secret cannot be decrypted"))
    }
}

/// Decodes and unprotects a stored secret; `None` when any step fails.
fn reveal(text: &str) -> Option<Secret> {
    let blob = STANDARD.decode(text).ok()?;
    let plain = dpapi::unprotect(&blob).ok()?;
    String::from_utf8(plain).ok().map(Secret)
}

/// Reads an optional secret, treating one that cannot be decrypted as absent.
fn lenient_secret<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Secret>, D::Error> {
    let text = Option::<String>::deserialize(deserializer)?;
    Ok(text.and_then(|t| {
        let secret = reveal(&t);
        if secret.is_none() {
            tracing::warn!("a stored secret could not be decrypted and is ignored");
        }
        secret
    }))
}

/// Reads a map of secrets, dropping entries that cannot be decrypted.
fn lenient_secrets<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<DeviceId, Secret>, D::Error> {
    let raw = BTreeMap::<DeviceId, String>::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .filter_map(|(id, text)| reveal(&text).map(|s| (id, s)))
        .collect())
}

/// Host-side and default session settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Whether this device accepts session requests at all.
    pub allow_incoming: bool,
    /// Whether a correct unattended password admits a viewer without a prompt.
    pub unattended: bool,
    /// Argon2id hash of the unattended password, if one is set.
    #[serde(
        deserialize_with = "lenient_secret",
        skip_serializing_if = "Option::is_none"
    )]
    pub password_hash: Option<Secret>,
    /// Whether new sessions start with clipboard sync on.
    pub clipboard_default: bool,
}

impl Default for Settings {
    /// Accept requests, ask for every one, sync the clipboard.
    fn default() -> Self {
        Self {
            allow_incoming: true,
            unattended: false,
            password_hash: None,
            clipboard_default: true,
        }
    }
}

/// Everything the client remembers between runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Format version of the file.
    pub version: u32,
    /// Server base URL chosen in the settings, if any.
    pub server_url: Option<String>,
    /// Username of the logged-in account.
    pub account: Option<String>,
    /// Session token of the logged-in account.
    #[serde(
        deserialize_with = "lenient_secret",
        skip_serializing_if = "Option::is_none"
    )]
    pub session_token: Option<Secret>,
    /// This device's ID once registered.
    pub device_id: Option<DeviceId>,
    /// This device's secret once registered.
    #[serde(
        deserialize_with = "lenient_secret",
        skip_serializing_if = "Option::is_none"
    )]
    pub device_secret: Option<Secret>,
    /// This device's X25519 private key, standard base64 of 32 bytes.
    #[serde(
        deserialize_with = "lenient_secret",
        skip_serializing_if = "Option::is_none"
    )]
    pub device_key: Option<Secret>,
    /// Public keys pinned per peer device, standard base64.
    pub known_keys: BTreeMap<DeviceId, String>,
    /// Unattended passwords remembered per host device.
    #[serde(deserialize_with = "lenient_secrets")]
    pub saved_passwords: BTreeMap<DeviceId, Secret>,
    /// Session settings.
    pub settings: Settings,
}

impl Default for State {
    /// An empty state of the current format version.
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            server_url: None,
            account: None,
            session_token: None,
            device_id: None,
            device_secret: None,
            device_key: None,
            known_keys: BTreeMap::new(),
            saved_passwords: BTreeMap::new(),
            settings: Settings::default(),
        }
    }
}

/// The state file and its loaded contents.
#[derive(Debug)]
pub struct Store {
    /// Path of the state file.
    path: PathBuf,
    /// The current state.
    state: State,
}

impl Store {
    /// Loads the state from `dir`, starting empty when there is no file.
    ///
    /// A file that cannot be parsed is renamed to `state.json.bad` and an empty
    /// state is used instead.
    pub fn open(dir: PathBuf) -> Store {
        let path = dir.join(FILE_NAME);
        let state = match std::fs::read(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => State::default(),
            Err(e) => {
                tracing::warn!(error = %e, "state file unreadable, starting empty");
                State::default()
            }
            Ok(bytes) => match serde_json::from_slice::<State>(&bytes) {
                Ok(state) => state,
                Err(e) => {
                    tracing::warn!(error = %e, "state file corrupt, moved aside");
                    let _ = std::fs::rename(&path, path.with_extension("json.bad"));
                    State::default()
                }
            },
        };
        Store { path, state }
    }

    /// Returns the current state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Applies `change` to the state and writes the file atomically.
    ///
    /// The in-memory state changes only when the write succeeds.
    pub fn update(&mut self, change: impl FnOnce(&mut State)) -> io::Result<()> {
        let mut next = self.state.clone();
        change(&mut next);
        write_atomic(&self.path, &next)?;
        self.state = next;
        Ok(())
    }
}

/// Writes `state` to a temporary file next to `path` and renames it over `path`.
fn write_atomic(path: &Path, state: &State) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)
}

/// Returns the state directory: `SURF_RAC_STATE_DIR`, else `%APPDATA%\surf-rac`.
pub fn default_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os(STATE_DIR_ENV) {
        return PathBuf::from(dir);
    }
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("surf-rac")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a fresh, empty directory for one test.
    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("surf-rac-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn id(n: u32) -> DeviceId {
        DeviceId::new(n).unwrap()
    }

    #[test]
    fn missing_file_gives_default_state() {
        let store = Store::open(temp_dir("missing"));
        assert_eq!(store.state(), &State::default());
    }

    #[test]
    fn state_round_trips_and_secrets_are_not_stored_in_plain_text() {
        let dir = temp_dir("round");
        let mut store = Store::open(dir.clone());
        store
            .update(|s| {
                s.account = Some("alice".into());
                s.session_token = Some(Secret::new("token-123"));
                s.device_id = Some(id(123_456_789));
                s.device_secret = Some(Secret::new("device-secret"));
                s.known_keys.insert(id(223_456_789), "AAAA".into());
                s.saved_passwords
                    .insert(id(223_456_789), Secret::new("hunter22"));
                s.settings.unattended = true;
            })
            .unwrap();
        let raw = std::fs::read_to_string(dir.join(FILE_NAME)).unwrap();
        for secret in ["token-123", "device-secret", "hunter22"] {
            assert!(!raw.contains(secret), "{secret} stored in plain text");
        }
        let reloaded = Store::open(dir);
        assert_eq!(reloaded.state(), store.state());
    }

    #[test]
    fn corrupt_file_is_moved_aside() {
        let dir = temp_dir("corrupt");
        std::fs::write(dir.join(FILE_NAME), b"{not json").unwrap();
        let store = Store::open(dir.clone());
        assert_eq!(store.state(), &State::default());
        assert!(dir.join("state.json.bad").exists());
    }

    #[test]
    fn undecryptable_secrets_are_dropped() {
        let dir = temp_dir("foreign");
        let json = serde_json::json!({
            "version": 1,
            "account": "alice",
            "session_token": STANDARD.encode(b"not a protected blob"),
            "saved_passwords": { "223456789": "!!" },
        });
        std::fs::write(dir.join(FILE_NAME), json.to_string()).unwrap();
        let store = Store::open(dir);
        assert_eq!(store.state().account.as_deref(), Some("alice"));
        #[cfg(windows)]
        assert!(store.state().session_token.is_none());
        assert!(store.state().saved_passwords.is_empty());
    }

    #[test]
    fn secret_debug_is_redacted() {
        assert_eq!(format!("{:?}", Secret::new("hunter22")), "Secret(..)");
        let state = State {
            session_token: Some(Secret::new("token-123")),
            ..State::default()
        };
        assert!(!format!("{state:?}").contains("token-123"));
    }
}
