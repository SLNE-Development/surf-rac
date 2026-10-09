//! The client's background runtime: one actor task owns the signaling
//! connection, hosting and viewing sessions and the state file, takes
//! [`Command`]s from the UI and publishes a [`Snapshot`] for it to draw.

mod actor;
mod hosting;
pub mod identity;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use surf_rac_input::Grants;
use surf_rac_protocol::data::{DataMessage, InputState, ScreenState};
use surf_rac_protocol::{DeviceId, DeviceInfo};
use surf_rac_session::EndReason;
use surf_rac_session::viewer::RequestError;
use tokio::sync::{mpsc, oneshot};

use crate::access::PromptNote;
use crate::store::{Settings, Store};

/// Server used when neither the settings nor the environment name one.
pub const DEFAULT_SERVER: &str = "https://rac.slne.dev";

/// Environment variable that overrides the server URL.
pub const SERVER_ENV: &str = "SURF_RAC_SERVER";

/// Longest wait between reconnect attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Something the UI asks the runtime to do.
#[derive(Debug)]
pub enum Command {
    /// Log in to an existing account.
    Login {
        /// Account username.
        username: String,
        /// Account password.
        password: String,
    },
    /// Create an account with an invite code and log in.
    Register {
        /// Invite code from an admin.
        invite: String,
        /// Desired username.
        username: String,
        /// Desired password.
        password: String,
    },
    /// Log out and stop all sessions.
    Logout,
    /// Switch to another server; logs out.
    SetServer(String),
    /// Reload devices and contacts.
    RefreshLists,
    /// Add a contact or rename it.
    PutContact {
        /// The contact's device.
        id: DeviceId,
        /// Its alias.
        alias: String,
    },
    /// Remove a contact.
    DeleteContact(DeviceId),
    /// Remove one of the account's other devices.
    DeleteDevice(DeviceId),
    /// Connect to a host.
    Connect {
        /// The host device.
        host: DeviceId,
        /// A typed unattended password; a saved one is used when absent.
        password: Option<String>,
        /// Save the typed password for this host once the session starts.
        remember: bool,
    },
    /// Send a data message in a viewer session.
    ViewerSend {
        /// The viewer session.
        session: u64,
        /// The message.
        message: DataMessage,
    },
    /// End a viewer session and close its window.
    ViewerHangup(u64),
    /// Turn clipboard sync of a viewer session on or off.
    ViewerClipboard {
        /// The viewer session.
        session: u64,
        /// Whether to sync.
        on: bool,
    },
    /// Accept a pending request.
    Accept(String),
    /// Deny a pending request.
    Deny(String),
    /// Change what a connected viewer may do.
    SetGrants {
        /// The viewer device.
        viewer: DeviceId,
        /// Its new grants.
        grants: Grants,
    },
    /// Turn follow mode on or off.
    SetFollow(bool),
    /// Turn clipboard sync with a connected viewer on or off.
    HostClipboard {
        /// The viewer device.
        viewer: DeviceId,
        /// Whether to sync.
        on: bool,
    },
    /// Disconnect one viewer.
    Disconnect(DeviceId),
    /// Disconnect every viewer.
    DisconnectAll,
    /// Save the settings; the unattended password hash is kept.
    SaveSettings(Settings),
    /// Set or clear the unattended password.
    SetUnattendedPassword(Option<String>),
    /// Forget the saved password of a host.
    ForgetPassword(DeviceId),
    /// Reconnect after another connection replaced this device.
    Reconnect,
    /// Hide the banner message.
    ClearBanner,
    /// Stop everything; the sender is told when done.
    Shutdown(oneshot::Sender<()>),
}

/// Whether and how the client is signed in and connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    /// No account is logged in; the message says why, if there is a reason to tell.
    LoggedOut {
        /// Why the user was logged out or what failed.
        message: Option<String>,
    },
    /// Logging in, registering or registering the device.
    Working(String),
    /// Connecting to the signaling server.
    Connecting,
    /// Connected; requests can arrive and sessions can start.
    Online,
    /// The connection dropped; reconnecting with backoff.
    Offline,
    /// Another connection signed in as this device.
    Replaced,
}

/// A contact with its presence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactView {
    /// The contact's device.
    pub id: DeviceId,
    /// Its alias.
    pub alias: String,
    /// Whether it is online.
    pub online: bool,
}

/// A session request waiting for the host's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptView {
    /// The request's session ID.
    pub session_id: String,
    /// The requesting device.
    pub viewer: DeviceId,
    /// Its alias or ID.
    pub name: String,
    /// Fingerprint of its key.
    pub fingerprint: String,
    /// What the password check found.
    pub note: PromptNote,
}

/// A viewer connected to this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostViewerView {
    /// The viewer device.
    pub id: DeviceId,
    /// Its alias or ID.
    pub name: String,
    /// What it may do.
    pub grants: Grants,
    /// Whether the clipboard syncs with it.
    pub clipboard: bool,
}

/// The newest decoded frame of a viewer session.
#[derive(Clone)]
pub struct FrameImage {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// RGBA pixels.
    pub rgba: Arc<Vec<u8>>,
    /// Increases with every frame.
    pub seq: u64,
}

/// Where a viewer session stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewerStatus {
    /// Waiting for the host to answer.
    Requesting,
    /// Media is flowing.
    Connected,
    /// The media connection is recovering.
    Reconnecting,
    /// The session is over; the text says why.
    Ended(String),
}

/// One viewer session as the UI shows it.
#[derive(Clone)]
pub struct ViewerView {
    /// The runtime's session number.
    pub session: u64,
    /// The host device.
    pub host: DeviceId,
    /// The host's alias or ID.
    pub name: String,
    /// Where the session stands.
    pub status: ViewerStatus,
    /// The newest frame, written by the frame task.
    pub frame: Arc<Mutex<Option<FrameImage>>>,
    /// The host's screen state, once received.
    pub screen: Option<ScreenState>,
    /// What this viewer may do on the host.
    pub input: InputState,
    /// Whether the clipboard syncs in this session.
    pub clipboard: bool,
    /// Whether a saved password was refused, so the UI offers to forget it.
    pub offer_forget: bool,
}

/// Everything the UI draws, as of the runtime's last change.
#[derive(Clone)]
pub struct Snapshot {
    /// Sign-in and connection state.
    pub auth: Auth,
    /// The logged-in username.
    pub account: Option<String>,
    /// The server in use.
    pub server_url: String,
    /// This device's ID once registered.
    pub device_id: Option<DeviceId>,
    /// The account's devices.
    pub devices: Vec<DeviceInfo>,
    /// The account's contacts.
    pub contacts: Vec<ContactView>,
    /// Requests waiting for an answer.
    pub prompts: Vec<PromptView>,
    /// Viewers connected to this host.
    pub host_viewers: Vec<HostViewerView>,
    /// Whether this device is reachable for requests.
    pub hosting: bool,
    /// Whether follow mode is on.
    pub follow: bool,
    /// Whether host input currently locks out remote input.
    pub input_locked: bool,
    /// A message for the user, such as an error.
    pub banner: Option<String>,
    /// Viewer sessions.
    pub viewers: Vec<ViewerView>,
    /// Current settings, without the password hash.
    pub settings: Settings,
    /// Hosts with a saved password.
    pub saved_passwords: Vec<DeviceId>,
    /// Whether an unattended password is set.
    pub unattended_password_set: bool,
}

impl Default for Snapshot {
    /// A logged-out client with nothing loaded.
    fn default() -> Self {
        Snapshot {
            auth: Auth::LoggedOut { message: None },
            account: None,
            server_url: DEFAULT_SERVER.into(),
            device_id: None,
            devices: Vec::new(),
            contacts: Vec::new(),
            prompts: Vec::new(),
            host_viewers: Vec::new(),
            hosting: false,
            follow: false,
            input_locked: false,
            banner: None,
            viewers: Vec::new(),
            settings: Settings::default(),
            saved_passwords: Vec::new(),
            unattended_password_set: false,
        }
    }
}

/// A cloneable sender of commands to the runtime.
#[derive(Clone)]
pub struct Commands(mpsc::UnboundedSender<Command>);

impl Commands {
    /// Sends a command; ignored once the runtime has stopped.
    pub fn send(&self, command: Command) {
        let _ = self.0.send(command);
    }
}

/// A callback that asks the UI to redraw.
pub type Repaint = Arc<dyn Fn() + Send + Sync>;

/// Handle to the running runtime.
pub struct Runtime {
    /// The tokio runtime the actor runs on.
    rt: tokio::runtime::Runtime,
    /// Commands to the actor.
    commands: mpsc::UnboundedSender<Command>,
    /// The latest snapshot.
    snapshot: Arc<Mutex<Snapshot>>,
}

impl Runtime {
    /// Starts the runtime with the loaded state; `repaint` is called after every change.
    pub fn start(store: Store, repaint: Repaint) -> std::io::Result<Runtime> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("surf-rac-runtime")
            .build()?;
        let (commands, commands_rx) = mpsc::unbounded_channel();
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let shared = Arc::clone(&snapshot);
        rt.spawn(async move {
            actor::Actor::new(store, shared, repaint)
                .run(commands_rx)
                .await;
        });
        Ok(Runtime {
            rt,
            commands,
            snapshot,
        })
    }

    /// Sends a command to the actor.
    pub fn command(&self, command: Command) {
        let _ = self.commands.send(command);
    }

    /// Returns a sender of commands that can be used from any thread.
    pub fn commands(&self) -> Commands {
        Commands(self.commands.clone())
    }

    /// Returns the latest snapshot.
    pub fn snapshot(&self) -> Snapshot {
        lock(&self.snapshot).clone()
    }

    /// Hangs up every session, waits up to five seconds for that, and stops the runtime.
    pub fn shutdown(self) {
        let (done, done_rx) = oneshot::channel();
        self.command(Command::Shutdown(done));
        let _ = self
            .rt
            .block_on(async { tokio::time::timeout(Duration::from_secs(5), done_rx).await });
        self.rt.shutdown_timeout(Duration::from_secs(1));
    }
}

/// Locks a mutex, recovering from a poisoned lock.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Returns the wait before reconnect attempt `attempt` (0-based): 0 s first,
/// then 1, 2, 4 ... seconds, at most [`MAX_BACKOFF`].
pub fn backoff(attempt: u32) -> Duration {
    if attempt == 0 {
        return Duration::ZERO;
    }
    let secs = 1u64.checked_shl(attempt - 1).unwrap_or(u64::MAX);
    Duration::from_secs(secs).min(MAX_BACKOFF)
}

/// Chooses the password to offer a host: the typed one, else the saved one.
///
/// Returns the password and whether it is the saved one.
pub fn password_offer(saved: Option<&str>, typed: Option<&str>) -> Option<(String, bool)> {
    match (typed.filter(|t| !t.is_empty()), saved) {
        (Some(typed), _) => Some((typed.to_string(), false)),
        (None, Some(saved)) => Some((saved.to_string(), true)),
        (None, None) => None,
    }
}

/// Returns whether the viewer may take the host's key from the server to seal
/// a password: only for a typed password when no key is pinned yet.
///
/// A saved password is only ever sealed for a pinned key, so the server
/// cannot obtain it by presenting a key of its own.
pub fn may_fetch_host_key(saved_password: bool, pinned: bool) -> bool {
    !saved_password && !pinned
}

/// Returns whether a failed request should offer to forget the saved
/// password: only when the saved password was actually sent and the host
/// refused or never answered, as a host with a changed password does.
pub fn offer_forget(sent_saved: bool, error: &RequestError) -> bool {
    sent_saved && matches!(error, RequestError::Denied | RequestError::Timeout)
}

/// Returns the text a viewer window shows when a request fails.
pub fn request_error_text(error: &RequestError) -> String {
    match error {
        RequestError::Offline => "The host is offline.".into(),
        RequestError::Denied => "The host denied the connection.".into(),
        RequestError::RoomFull => "The host already has the maximum number of viewers.".into(),
        RequestError::Timeout => "The host did not answer in time.".into(),
        RequestError::TokenRejected => "The media server rejected the session.".into(),
        RequestError::MediaUnavailable(_) => "The media server cannot be reached.".into(),
        RequestError::KeyChanged(_) => {
            "The host's security key changed. The connection was refused for safety.".into()
        }
        RequestError::Signaling(_) => "The connection to the server was lost.".into(),
    }
}

/// Returns the text a viewer window shows when a session ends.
pub fn end_text(reason: EndReason) -> String {
    match reason {
        EndReason::Hangup => "The session was ended.".into(),
        EndReason::Timeout => "The connection was lost and did not recover.".into(),
        EndReason::CryptoError => "The session was ended because data failed to decrypt.".into(),
        EndReason::Closed => "The host closed the session.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_thirty_seconds() {
        let secs: Vec<u64> = (0..8).map(|n| backoff(n).as_secs()).collect();
        assert_eq!(secs, vec![0, 1, 2, 4, 8, 16, 30, 30]);
        assert_eq!(backoff(200), MAX_BACKOFF);
    }

    #[test]
    fn host_key_is_fetched_only_for_a_typed_password_without_pin() {
        assert!(may_fetch_host_key(false, false));
        assert!(!may_fetch_host_key(true, false));
        assert!(!may_fetch_host_key(false, true));
        assert!(!may_fetch_host_key(true, true));
    }

    #[test]
    fn forget_is_offered_only_when_the_saved_password_was_sent() {
        assert!(offer_forget(true, &RequestError::Denied));
        assert!(offer_forget(true, &RequestError::Timeout));
        assert!(!offer_forget(false, &RequestError::Denied));
        assert!(!offer_forget(true, &RequestError::Offline));
    }

    #[test]
    fn typed_password_wins_over_saved() {
        assert_eq!(
            password_offer(Some("saved"), Some("typed")),
            Some(("typed".into(), false))
        );
        assert_eq!(
            password_offer(Some("saved"), None),
            Some(("saved".into(), true))
        );
        assert_eq!(
            password_offer(Some("saved"), Some("")),
            Some(("saved".into(), true))
        );
        assert_eq!(password_offer(None, None), None);
    }

    #[test]
    fn every_request_error_has_text() {
        for error in [
            RequestError::Offline,
            RequestError::Denied,
            RequestError::RoomFull,
            RequestError::Timeout,
            RequestError::TokenRejected,
            RequestError::MediaUnavailable("x".into()),
        ] {
            assert!(request_error_text(&error).ends_with('.'));
        }
        assert!(end_text(EndReason::Timeout).contains("lost"));
    }
}
