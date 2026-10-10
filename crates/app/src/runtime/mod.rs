//! The client's background runtime: one actor task owns the installation's
//! identity, the signaling connection, the optional account, hosting and
//! viewing sessions and the state file, takes [`Command`]s from the UI and
//! publishes a [`Snapshot`] for it to draw.

pub mod account;
mod actor;
mod hosting;
pub mod identity;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use surf_rac_input::Grants;
use surf_rac_protocol::data::{DataMessage, InputState, ScreenState};
use surf_rac_protocol::{DeviceId, MyDeviceInfo};
use surf_rac_session::EndReason;
use surf_rac_session::signaling::SignalingError;
use surf_rac_session::viewer::RequestError;
use tokio::sync::{mpsc, oneshot};

use crate::access::PromptNote;
use crate::api::ApiError;
use crate::installation::InstallationStore;
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
    /// Sign in to an existing account and link this installation to it.
    SignIn {
        /// Account username.
        username: String,
        /// Account password.
        password: String,
    },
    /// Create an account, sign in to it and link this installation to it.
    CreateAccount {
        /// Desired username.
        username: String,
        /// Desired password.
        password: String,
    },
    /// Unlink this installation from the account and sign out of it; sessions keep running.
    SignOut,
    /// Delete the signed-in account after checking its password.
    DeleteAccount {
        /// The account password.
        password: String,
    },
    /// Switch to another server; signs out and registers a new installation there.
    SetServer(String),
    /// Reload My devices and contacts while signed in.
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
    /// Unlink another installation from the signed-in account.
    UnlinkDevice(DeviceId),
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
    /// Pause or resume the view of one connected viewer.
    PauseView {
        /// The viewer device.
        viewer: DeviceId,
        /// True to pause, false to resume.
        paused: bool,
    },
    /// Pause or resume the view of every viewer, including viewers that join while paused.
    PauseAll(bool),
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

/// The state of this installation's connection to the signaling server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Connection {
    /// Registering the installation or connecting to the server.
    Connecting,
    /// Connected; requests can arrive and sessions can start.
    Online,
    /// Not connected; retrying with backoff.
    Offline,
    /// The server does not support this client's version; no retries until restart.
    UpdateRequired,
    /// An administrator disabled this device; no retries until restart.
    Disabled,
    /// Another connection signed in as this device; reconnects only when asked.
    Replaced,
}

/// What the runtime is doing with the account, or why it failed last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountTask {
    /// Nothing is running and nothing failed.
    Idle,
    /// Signing in, creating or deleting the account; the text says which.
    Working(String),
    /// The last account action failed; the text says why.
    Failed(String),
}

/// How the runtime reacts to a failed connection attempt or registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectAction {
    /// Discard the installation, register a new one and connect again.
    Renew,
    /// Try again after the backoff.
    Retry,
    /// Stop connecting and show this state.
    Stop(Connection),
}

/// Returns how to react to a failed connection attempt.
///
/// A clone or an unknown ID renews the installation, unless the installation
/// was already renewed since the last successful connection; then the client
/// only retries with backoff. An outdated client and a disabled device stop.
pub fn connect_action(error: &SignalingError, renewed: bool) -> ConnectAction {
    match error {
        SignalingError::UpdateRequired => ConnectAction::Stop(Connection::UpdateRequired),
        SignalingError::DeviceDisabled => ConnectAction::Stop(Connection::Disabled),
        SignalingError::CloneDetected | SignalingError::UnknownDevice if !renewed => {
            ConnectAction::Renew
        }
        _ => ConnectAction::Retry,
    }
}

/// Returns how to react when no identity could be set up: a refused
/// registration as [`registration_action`] says, and an installation that
/// could not be stored by retrying with backoff.
pub fn identity_action(error: &identity::IdentityError) -> ConnectAction {
    match error {
        identity::IdentityError::Api(e) => registration_action(e),
        identity::IdentityError::Store(_) => ConnectAction::Retry,
    }
}

/// Returns how to react to a failed installation registration.
pub fn registration_action(error: &ApiError) -> ConnectAction {
    match error {
        ApiError::UpdateRequired => ConnectAction::Stop(Connection::UpdateRequired),
        ApiError::DeviceDisabled => ConnectAction::Stop(Connection::Disabled),
        _ => ConnectAction::Retry,
    }
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
    /// The alias of the viewer in the contact list, if it is a contact.
    pub alias: Option<String>,
    /// The device name the viewer chose for itself, cleaned for display; the
    /// viewer's ID when it gave none.
    pub device_name: String,
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
    /// Whether its view is paused.
    pub paused: bool,
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
    /// Whether the host paused the view; no picture is kept while it is.
    pub paused: bool,
}

/// Everything the UI draws, as of the runtime's last change.
#[derive(Clone)]
pub struct Snapshot {
    /// The connection to the signaling server.
    pub connection: Connection,
    /// The signed-in account's username, if any.
    pub account: Option<String>,
    /// The running or last failed account action.
    pub account_task: AccountTask,
    /// The server in use.
    pub server_url: String,
    /// This installation's ID once registered.
    pub device_id: Option<DeviceId>,
    /// The installations linked to the signed-in account.
    pub my_devices: Vec<MyDeviceInfo>,
    /// The signed-in account's contacts.
    pub contacts: Vec<ContactView>,
    /// Requests waiting for an answer.
    pub prompts: Vec<PromptView>,
    /// Viewers connected to this host.
    pub host_viewers: Vec<HostViewerView>,
    /// Whether this device is reachable for requests.
    pub hosting: bool,
    /// Whether follow mode is on.
    pub follow: bool,
    /// Whether the view is paused for every viewer, including viewers that join later.
    pub all_paused: bool,
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
    /// A connecting client without an account and with nothing loaded.
    fn default() -> Self {
        Snapshot {
            connection: Connection::Connecting,
            account: None,
            account_task: AccountTask::Idle,
            server_url: DEFAULT_SERVER.into(),
            device_id: None,
            my_devices: Vec::new(),
            contacts: Vec::new(),
            prompts: Vec::new(),
            host_viewers: Vec::new(),
            hosting: false,
            follow: false,
            all_paused: false,
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
    /// Starts the runtime with the loaded state and the store of this
    /// installation's identity; `repaint` is called after every change.
    pub fn start(
        store: Store,
        installation: Arc<dyn InstallationStore>,
        repaint: Repaint,
    ) -> std::io::Result<Runtime> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("surf-rac-runtime")
            .build()?;
        let (commands, commands_rx) = mpsc::unbounded_channel();
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let shared = Arc::clone(&snapshot);
        rt.spawn(async move {
            actor::Actor::new(store, installation, shared, repaint)
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

/// Returns the password a viewer sends to a host, given the offer from
/// [`password_offer`] and whether the host's identity key is pinned.
///
/// A saved password is only sent to a host whose key is pinned, so a server
/// that presents a key of its own for the host never receives it.
pub fn password_to_send(offer: Option<(String, bool)>, pinned: bool) -> Option<String> {
    match offer {
        Some((password, saved)) if !saved || pinned => Some(password),
        _ => None,
    }
}

/// Returns whether a failed request should offer to forget the saved
/// password: only when the saved password was actually sent and the host
/// refused or never answered, as a host with a changed password does. A
/// request the server refused as rate limited never offers it.
pub fn offer_forget(sent_saved: bool, error: &RequestError) -> bool {
    sent_saved && matches!(error, RequestError::Denied | RequestError::Timeout)
}

/// Returns the text a viewer window shows when a request fails.
pub fn request_error_text(error: &RequestError) -> String {
    match error {
        RequestError::Offline => "The host is offline.".into(),
        RequestError::Denied => "The host denied the connection.".into(),
        RequestError::KeyNotRecognised => "The host does not recognise this device's key.".into(),
        RequestError::RoomFull => "The host already has the maximum number of viewers.".into(),
        RequestError::Timeout => "The host did not answer in time.".into(),
        RequestError::TokenRejected => "The media server rejected the session.".into(),
        RequestError::MediaUnavailable(_) => "The media server cannot be reached.".into(),
        RequestError::KeyChanged(_) => {
            "The host's security key changed. The connection was refused for safety.".into()
        }
        RequestError::ChallengeMismatch => {
            "The host's answer did not match its security check. The connection was refused for safety.".into()
        }
        RequestError::Signaling(_) => "The connection to the server was lost.".into(),
        RequestError::RateLimited => {
            "The host is receiving too many requests. Try again in a minute.".into()
        }
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
    use super::identity::IdentityError;
    use super::*;

    #[test]
    fn backoff_doubles_up_to_thirty_seconds() {
        let secs: Vec<u64> = (0..8).map(|n| backoff(n).as_secs()).collect();
        assert_eq!(secs, vec![0, 1, 2, 4, 8, 16, 30, 30]);
        assert_eq!(backoff(200), MAX_BACKOFF);
    }

    #[test]
    fn update_required_and_disabled_stop_reconnecting() {
        assert_eq!(
            connect_action(&SignalingError::UpdateRequired, false),
            ConnectAction::Stop(Connection::UpdateRequired)
        );
        assert_eq!(
            connect_action(&SignalingError::DeviceDisabled, false),
            ConnectAction::Stop(Connection::Disabled)
        );
    }

    #[test]
    fn clone_and_unknown_device_renew_once_then_back_off() {
        for error in [SignalingError::CloneDetected, SignalingError::UnknownDevice] {
            assert_eq!(connect_action(&error, false), ConnectAction::Renew);
            assert_eq!(connect_action(&error, true), ConnectAction::Retry);
        }
    }

    #[test]
    fn other_connect_errors_retry() {
        for error in [
            SignalingError::Connect("refused".into()),
            SignalingError::Closed,
            SignalingError::RateLimited,
            SignalingError::BadSignature,
            SignalingError::Rejected(401),
        ] {
            assert_eq!(connect_action(&error, false), ConnectAction::Retry);
        }
    }

    #[test]
    fn identity_store_failures_retry() {
        assert_eq!(
            identity_action(&IdentityError::Store("disk full".into())),
            ConnectAction::Retry
        );
        assert_eq!(
            identity_action(&IdentityError::Api(ApiError::UpdateRequired)),
            ConnectAction::Stop(Connection::UpdateRequired)
        );
        assert_eq!(
            identity_action(&IdentityError::Api(ApiError::RateLimited)),
            ConnectAction::Retry
        );
    }

    #[test]
    fn registration_errors_map_to_connection_states() {
        assert_eq!(
            registration_action(&ApiError::UpdateRequired),
            ConnectAction::Stop(Connection::UpdateRequired)
        );
        assert_eq!(
            registration_action(&ApiError::Network("down".into())),
            ConnectAction::Retry
        );
        assert_eq!(
            registration_action(&ApiError::RateLimited),
            ConnectAction::Retry
        );
    }

    #[test]
    fn saved_password_is_only_sent_to_a_pinned_host() {
        assert_eq!(
            password_to_send(Some(("typed".into(), false)), false),
            Some("typed".into())
        );
        assert_eq!(password_to_send(Some(("saved".into(), true)), false), None);
        assert_eq!(
            password_to_send(Some(("saved".into(), true)), true),
            Some("saved".into())
        );
        assert_eq!(password_to_send(None, true), None);
    }

    #[test]
    fn forget_is_offered_only_when_the_saved_password_was_sent() {
        assert!(offer_forget(true, &RequestError::Denied));
        assert!(offer_forget(true, &RequestError::Timeout));
        assert!(!offer_forget(false, &RequestError::Denied));
        assert!(!offer_forget(true, &RequestError::Offline));
        assert!(!offer_forget(true, &RequestError::RateLimited));
        assert!(!offer_forget(true, &RequestError::KeyNotRecognised));
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
            RequestError::ChallengeMismatch,
            RequestError::RateLimited,
            RequestError::KeyNotRecognised,
        ] {
            assert!(request_error_text(&error).ends_with('.'));
        }
        assert_eq!(
            request_error_text(&RequestError::KeyNotRecognised),
            "The host does not recognise this device's key."
        );
        assert!(end_text(EndReason::Timeout).contains("lost"));
    }
}
