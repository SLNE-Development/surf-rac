//! The client's persistent state: one JSON file per Windows user whose secret
//! fields are protected with the data protection API in user scope.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use surf_rac_protocol::DeviceId;

use crate::dpapi;

/// Version of the state file format this build writes.
///
/// Of a file of any other version only the server URL and settings are kept.
pub const STATE_VERSION: u32 = 2;

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

/// An installation as stored: its secret field still protected.
#[derive(Deserialize)]
struct RawInstallation {
    /// The device ID.
    device_id: DeviceId,
    /// The protected identity key.
    identity_key: String,
    /// The registered device name.
    name: String,
}

/// Reads an optional installation, treating one whose key cannot be decrypted as absent.
fn lenient_installation<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<InstallationState>, D::Error> {
    let raw = Option::<RawInstallation>::deserialize(deserializer)?;
    Ok(raw.and_then(|raw| match reveal(&raw.identity_key) {
        Some(identity_key) => Some(InstallationState {
            device_id: raw.device_id,
            identity_key,
            name: raw.name,
        }),
        None => {
            tracing::warn!("the stored identity key could not be decrypted and is ignored");
            None
        }
    }))
}

/// An account session as stored: its token still protected.
#[derive(Deserialize)]
struct RawAccount {
    /// The account username.
    username: String,
    /// The protected session token.
    session_token: String,
}

/// Reads an optional account session, treating one whose token cannot be decrypted as absent.
fn lenient_account<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<AccountState>, D::Error> {
    let raw = Option::<RawAccount>::deserialize(deserializer)?;
    Ok(raw.and_then(|raw| match reveal(&raw.session_token) {
        Some(session_token) => Some(AccountState {
            username: raw.username,
            session_token,
        }),
        None => {
            tracing::warn!("the stored session token could not be decrypted and is ignored");
            None
        }
    }))
}

/// This installation's registration with the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallationState {
    /// The device ID the server assigned.
    pub device_id: DeviceId,
    /// The Ed25519 identity key, standard base64 of its 32 secret bytes.
    pub identity_key: Secret,
    /// The device name the installation registered with.
    pub name: String,
}

/// The account a user signed in to on this installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountState {
    /// The account username.
    pub username: String,
    /// The account session token.
    pub session_token: Secret,
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
    /// This installation's registration, once registered.
    #[serde(
        deserialize_with = "lenient_installation",
        skip_serializing_if = "Option::is_none"
    )]
    pub installation: Option<InstallationState>,
    /// Identity keys pinned per peer device, standard base64.
    pub known_keys: BTreeMap<DeviceId, String>,
    /// The signed-in account, if any.
    #[serde(
        deserialize_with = "lenient_account",
        skip_serializing_if = "Option::is_none"
    )]
    pub account: Option<AccountState>,
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
            installation: None,
            known_keys: BTreeMap::new(),
            account: None,
            saved_passwords: BTreeMap::new(),
            settings: Settings::default(),
        }
    }
}

impl State {
    /// Forgets everything that belongs to the current server: the
    /// installation's registration and identity key, the account, pinned keys
    /// and saved host passwords. The settings are kept.
    pub fn forget_server(&mut self) {
        self.installation = None;
        self.account = None;
        self.known_keys.clear();
        self.saved_passwords.clear();
    }
}

/// The loaded state and the file it belongs to.
#[derive(Debug)]
struct Inner {
    /// Path of the state file.
    path: PathBuf,
    /// The current state.
    state: State,
}

/// The state file and its loaded contents; clones share one state.
#[derive(Debug, Clone)]
pub struct Store {
    /// The shared file path and state.
    inner: Arc<Mutex<Inner>>,
}

impl Store {
    /// Loads the state from `dir`, starting empty when there is no file.
    ///
    /// A file that cannot be parsed is renamed to `state.json.bad` and an
    /// empty state is used instead. Of a file of another format version only
    /// the server URL and the settings are kept; it is overwritten on the
    /// next save.
    pub fn open(dir: PathBuf) -> Store {
        let path = dir.join(FILE_NAME);
        let state = match std::fs::read(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => State::default(),
            Err(e) => {
                tracing::warn!(error = %e, "state file unreadable, starting empty");
                State::default()
            }
            Ok(bytes) => parse(&path, &bytes),
        };
        Store {
            inner: Arc::new(Mutex::new(Inner { path, state })),
        }
    }

    /// Returns a copy of the current state.
    pub fn state(&self) -> State {
        self.lock().state.clone()
    }

    /// Applies `change` to the state and writes the file atomically.
    ///
    /// The in-memory state changes only when the write succeeds.
    pub fn update(&self, change: impl FnOnce(&mut State)) -> io::Result<()> {
        let mut inner = self.lock();
        let mut next = inner.state.clone();
        change(&mut next);
        write_atomic(&inner.path, &next)?;
        inner.state = next;
        Ok(())
    }

    /// Locks the shared state, recovering from a poisoned lock.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Parses the contents of the state file at `path`.
///
/// Keeps only the server URL and settings of a file of another format
/// version, and moves a file that is not a valid state aside to
/// `state.json.bad`.
fn parse(path: &Path, bytes: &[u8]) -> State {
    let version = serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .map(|v| v.get("version").and_then(serde_json::Value::as_u64));
    if let Some(version) = version
        && version != Some(u64::from(STATE_VERSION))
    {
        tracing::warn!(
            ?version,
            "state file has another format version, keeping only the server and settings"
        );
        return carry_over(bytes);
    }
    match serde_json::from_slice::<State>(bytes) {
        Ok(state) => state,
        Err(e) => {
            tracing::warn!(error = %e, "state file corrupt, moved aside");
            let _ = std::fs::rename(path, path.with_extension("json.bad"));
            State::default()
        }
    }
}

/// Returns an empty state that keeps the server URL and the settings of a
/// state file of another format version, as far as they still parse.
///
/// The installation, account, pinned keys and saved passwords are dropped.
fn carry_over(bytes: &[u8]) -> State {
    let Ok(old) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return State::default();
    };
    let server_url = old
        .get("server_url")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let settings = old
        .get("settings")
        .and_then(|s| serde_json::from_value::<Settings>(s.clone()).ok())
        .unwrap_or_default();
    State {
        server_url,
        settings,
        ..State::default()
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

    /// Returns the device id for the given number, panicking if it is out of range.
    fn id(n: u32) -> DeviceId {
        DeviceId::new(n).unwrap()
    }

    /// Returns an installation with fixed test values.
    fn installation() -> InstallationState {
        InstallationState {
            device_id: id(123_456_789),
            identity_key: Secret::new("identity-key-bytes"),
            name: "laptop".into(),
        }
    }

    /// Checks that opening a directory without a state file gives the default state.
    #[test]
    fn missing_file_gives_default_state() {
        let store = Store::open(temp_dir("missing"));
        assert_eq!(store.state(), State::default());
        assert!(store.state().installation.is_none());
        assert!(store.state().account.is_none());
    }

    /// Checks that the state survives a save and reload and that tokens, identity keys
    /// and saved passwords never appear in the file in plain text.
    #[test]
    fn state_round_trips_and_secrets_are_not_stored_in_plain_text() {
        let dir = temp_dir("round");
        let store = Store::open(dir.clone());
        store
            .update(|s| {
                s.installation = Some(installation());
                s.account = Some(AccountState {
                    username: "alice".into(),
                    session_token: Secret::new("token-123"),
                });
                s.known_keys.insert(id(223_456_789), "AAAA".into());
                s.saved_passwords
                    .insert(id(223_456_789), Secret::new("hunter22"));
                s.settings.unattended = true;
            })
            .unwrap();
        let raw = std::fs::read_to_string(dir.join(FILE_NAME)).unwrap();
        for secret in ["token-123", "identity-key-bytes", "hunter22"] {
            assert!(!raw.contains(secret), "{secret} stored in plain text");
        }
        assert!(raw.contains("\"version\": 2"));
        let reloaded = Store::open(dir);
        assert_eq!(reloaded.state(), store.state());
        assert_eq!(reloaded.state().installation, Some(installation()));
        assert_eq!(
            reloaded.state().account.map(|a| a.username).as_deref(),
            Some("alice")
        );
    }

    /// Checks that an update through one store clone is visible through the other.
    #[test]
    fn clones_share_one_state() {
        let dir = temp_dir("shared");
        let store = Store::open(dir);
        let other = store.clone();
        other
            .update(|s| s.installation = Some(installation()))
            .unwrap();
        assert_eq!(store.state().installation, Some(installation()));
    }

    /// Checks that a version 1 state file keeps only its server URL and settings and
    /// drops the account, device and key data.
    #[test]
    fn old_version_file_keeps_server_and_settings_only() {
        let dir = temp_dir("old");
        let hash = Secret::new("$argon2id$v=19$hash");
        let json = serde_json::json!({
            "version": 1,
            "server_url": "https://custom.example",
            "account": "alice",
            "session_token": STANDARD.encode(b"blob"),
            "device_id": "123456789",
            "device_secret": STANDARD.encode(b"blob"),
            "device_key": STANDARD.encode(b"blob"),
            "known_keys": { "223456789": "AAAA" },
            "saved_passwords": { "223456789": serde_json::to_value(&hash).unwrap() },
            "settings": {
                "allow_incoming": false,
                "unattended": true,
                "password_hash": serde_json::to_value(&hash).unwrap(),
                "clipboard_default": false,
            },
        });
        std::fs::write(dir.join(FILE_NAME), json.to_string()).unwrap();
        let store = Store::open(dir.clone());
        let state = store.state();
        assert_eq!(state.version, STATE_VERSION);
        assert_eq!(state.server_url.as_deref(), Some("https://custom.example"));
        assert!(state.installation.is_none());
        assert!(state.account.is_none());
        assert!(state.known_keys.is_empty());
        assert!(state.saved_passwords.is_empty());
        assert!(!state.settings.allow_incoming);
        assert!(state.settings.unattended);
        assert!(!state.settings.clipboard_default);
        #[cfg(windows)]
        assert_eq!(state.settings.password_hash, Some(hash));
        store.update(|s| s.settings.unattended = false).unwrap();
        let reloaded = Store::open(dir);
        assert_eq!(
            reloaded.state().server_url.as_deref(),
            Some("https://custom.example")
        );
        assert!(reloaded.state().installation.is_none());
    }

    /// Checks that a version 1 file with unreadable settings keeps the server URL and
    /// falls back to default settings.
    #[test]
    fn old_version_file_with_unreadable_settings_keeps_the_server() {
        let dir = temp_dir("oldbad");
        let json = serde_json::json!({
            "version": 1,
            "server_url": "https://custom.example",
            "settings": "not settings",
        });
        std::fs::write(dir.join(FILE_NAME), json.to_string()).unwrap();
        let state = Store::open(dir).state();
        assert_eq!(state.server_url.as_deref(), Some("https://custom.example"));
        assert_eq!(state.settings, Settings::default());
    }

    /// Checks that a state file without a version starts from the default state.
    #[test]
    fn file_without_version_starts_fresh() {
        let dir = temp_dir("noversion");
        std::fs::write(
            dir.join(FILE_NAME),
            br#"{"known_keys":{"223456789":"AAAA"}}"#,
        )
        .unwrap();
        assert_eq!(Store::open(dir).state(), State::default());
    }

    /// Checks that an unparseable state file is renamed aside and the default state is
    /// used.
    #[test]
    fn corrupt_file_is_moved_aside() {
        let dir = temp_dir("corrupt");
        std::fs::write(dir.join(FILE_NAME), b"{not json").unwrap();
        let store = Store::open(dir.clone());
        assert_eq!(store.state(), State::default());
        assert!(dir.join("state.json.bad").exists());
    }

    /// Checks that secrets which cannot be decrypted are dropped while the rest of the
    /// state is kept.
    #[test]
    fn undecryptable_secrets_are_dropped() {
        let dir = temp_dir("foreign");
        let json = serde_json::json!({
            "version": STATE_VERSION,
            "installation": {
                "device_id": "123456789",
                "identity_key": STANDARD.encode(b"not a protected blob"),
                "name": "laptop",
            },
            "account": {
                "username": "alice",
                "session_token": STANDARD.encode(b"not a protected blob"),
            },
            "saved_passwords": { "223456789": "!!" },
            "settings": { "unattended": true },
        });
        std::fs::write(dir.join(FILE_NAME), json.to_string()).unwrap();
        let store = Store::open(dir);
        #[cfg(windows)]
        {
            assert!(store.state().installation.is_none());
            assert!(store.state().account.is_none());
        }
        assert!(store.state().saved_passwords.is_empty());
        assert!(store.state().settings.unattended);
    }

    /// Checks that forgetting the server drops the installation, account, known keys
    /// and saved passwords but keeps the settings.
    #[test]
    fn forgetting_the_server_drops_everything_bound_to_it() {
        let mut state = State {
            server_url: Some("https://old.example".into()),
            installation: Some(installation()),
            account: Some(AccountState {
                username: "alice".into(),
                session_token: Secret::new("token"),
            }),
            ..State::default()
        };
        state.known_keys.insert(id(223_456_789), "AAAA".into());
        state
            .saved_passwords
            .insert(id(223_456_789), Secret::new("pw"));
        state.settings.unattended = true;
        state.forget_server();
        assert!(state.installation.is_none());
        assert!(state.account.is_none());
        assert!(state.known_keys.is_empty());
        assert!(state.saved_passwords.is_empty());
        assert!(state.settings.unattended);
    }

    /// Checks that the debug output of secrets and of the whole state is redacted.
    #[test]
    fn secret_debug_is_redacted() {
        assert_eq!(format!("{:?}", Secret::new("hunter22")), "Secret(..)");
        let state = State {
            account: Some(AccountState {
                username: "alice".into(),
                session_token: Secret::new("token-123"),
            }),
            installation: Some(installation()),
            ..State::default()
        };
        let debug = format!("{state:?}");
        assert!(!debug.contains("token-123"));
        assert!(!debug.contains("identity-key-bytes"));
    }
}
