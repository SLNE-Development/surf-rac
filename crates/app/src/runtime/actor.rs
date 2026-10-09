//! The runtime actor: owns all session state and handles commands and events
//! one at a time.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use surf_rac_protocol::data::{Control, DataMessage, InputState, ScreenState};
use surf_rac_protocol::{
    ClientMessage, ContactInfo, DenyReason, DeviceId, MyDeviceInfo, ServerMessage,
};
use surf_rac_session::host::{HostEvent, HostSession};
use surf_rac_session::signaling::{SignalingClient, SignalingError};
use surf_rac_session::viewer::{RequestError, RequestOptions, ViewerEvent, ViewerSession};
use surf_rac_session::{IdentityPublic, KnownKeys, SessionConfig};
use tokio::sync::mpsc;

use super::account::{self, LinkError};
use super::hosting::Hosting;
use super::identity::{self, Identity, IdentityError};
use super::{
    AccountTask, Command, ConnectAction, Connection, ContactView, DEFAULT_SERVER, FrameImage,
    Repaint, SERVER_ENV, Snapshot, ViewerStatus, ViewerView, backoff, connect_action, end_text,
    identity_action, lock, offer_forget, password_offer, password_to_send, request_error_text,
};
use crate::access;
use crate::api::{Api, ApiError};
use crate::clipboard::{self, ClipboardSync};
use crate::fingerprint;
use crate::installation::InstallationStore;
use crate::store::{AccountState, Secret, Settings, Store};
use crate::yuv;

/// How often the clipboard is checked while a session syncs it.
const CLIPBOARD_POLL: Duration = Duration::from_millis(500);

/// Banner shown when the server needs a newer client.
const UPDATE_REQUIRED_TEXT: &str =
    "This version of surf-rac is too old for the server. Please update to connect.";

/// Banner shown when an administrator disabled this device.
const DISABLED_TEXT: &str = "This device was disabled by the server's administrator.";

/// Banner shown when an account action needs a signed-in account.
const SIGN_IN_FIRST_TEXT: &str = "Sign in to an account to keep contacts and devices.";

/// Events from tasks the actor spawned.
pub(super) enum Internal {
    /// Setting up the installation's identity of generation `.0` finished.
    IdentityReady(u64, Result<Identity, IdentityError>),
    /// A signaling connection of generation `.0` opened.
    Connected(u64, SignalingClient),
    /// A connection attempt of generation `.0` failed.
    ConnectFailed(u64, SignalingError),
    /// A message arrived on the connection of generation `.0`.
    Signal(u64, ServerMessage),
    /// The connection of generation `.0` closed.
    SignalingClosed(u64),
    /// Signing in or creating an account finished: the username and session token.
    SignedIn(Result<(String, Secret), String>),
    /// Linking this installation over the connection of generation `.0` finished.
    Linked(u64, Result<String, LinkError>),
    /// Deleting the account finished.
    AccountDeleted(Result<(), ApiError>),
    /// My devices and contacts loaded.
    Lists(Result<(Vec<MyDeviceInfo>, Vec<ContactInfo>), ApiError>),
    /// An API call failed.
    ApiFailed(ApiError),
    /// Hosting of generation `.0` started or failed.
    HostStarted(
        u64,
        Result<(HostSession, mpsc::Receiver<HostEvent>), String>,
    ),
    /// An event of the host session of generation `.0`.
    Host(u64, HostEvent),
    /// Try to start hosting again.
    RestartHosting,
    /// The host's input status changed.
    InputChanged,
    /// A viewer request finished.
    ViewerStarted {
        /// The session number.
        session: u64,
        /// The outcome.
        result: Result<(ViewerSession, mpsc::Receiver<ViewerEvent>), RequestError>,
        /// Whether the saved password was sent with the request.
        used_saved: bool,
        /// A typed password to save once the session started.
        remember: Option<String>,
    },
    /// An event of viewer session `.0`.
    Viewer(u64, ViewerEvent),
}

/// One viewer session.
struct Viewing {
    /// The host device.
    host: DeviceId,
    /// The session, once the request succeeded.
    session: Option<ViewerSession>,
    /// Where it stands.
    status: ViewerStatus,
    /// The newest frame.
    frame: Arc<Mutex<Option<FrameImage>>>,
    /// The host's screen state.
    screen: Option<ScreenState>,
    /// This viewer's input state on the host.
    input: InputState,
    /// Whether the clipboard syncs.
    clipboard: bool,
    /// Whether a saved password was refused.
    offer_forget: bool,
}

/// The clipboard of this machine, when it can be opened.
#[cfg(windows)]
type Clipboard = Option<ClipboardSync<clipboard::SystemBoard>>;

/// The clipboard of this machine; there is none off Windows.
#[cfg(not(windows))]
type Clipboard = Option<ClipboardSync<NoBoard>>;

/// A clipboard that never holds anything.
#[cfg(not(windows))]
pub(super) struct NoBoard;

#[cfg(not(windows))]
impl clipboard::Board for NoBoard {
    /// Always 0.
    fn sequence(&self) -> u32 {
        0
    }
    /// Always empty.
    fn read(&mut self) -> Option<clipboard::Item> {
        None
    }
    /// Always fails.
    fn write(&mut self, _item: &clipboard::Item) -> bool {
        false
    }
}

/// Opens this machine's clipboard for sync.
fn open_clipboard() -> Clipboard {
    #[cfg(windows)]
    {
        match clipboard::SystemBoard::open() {
            Ok(board) => Some(ClipboardSync::new(board)),
            Err(e) => {
                tracing::warn!(error = %e, "clipboard unavailable");
                None
            }
        }
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// The runtime actor.
pub(super) struct Actor {
    /// The state file.
    pub(super) store: Store,
    /// Where this installation's identity is kept.
    installation: Arc<dyn InstallationStore>,
    /// This machine's fingerprint hash, or why it could not be read.
    fingerprint: Result<String, String>,
    /// The published snapshot.
    shared: Arc<Mutex<Snapshot>>,
    /// Asks the UI to redraw.
    pub(super) repaint: Repaint,
    /// Sender for task events.
    pub(super) internal: mpsc::UnboundedSender<Internal>,
    /// The connection to the signaling server.
    pub(super) connection: Connection,
    /// The running or last failed account action.
    account_task: AccountTask,
    /// API client, with the account's session token while signed in.
    pub(super) api: Api,
    /// This installation, once registered.
    pub(super) identity: Option<Identity>,
    /// Pinned peer identity keys.
    pub(super) known: Arc<Mutex<KnownKeys>>,
    /// The open signaling connection.
    pub(super) signaling: Option<SignalingClient>,
    /// Generation of the current registration or connection; events of older ones are ignored.
    pub(super) generation: u64,
    /// Failed registration or connection attempts in a row.
    attempts: u32,
    /// Whether the installation was renewed since the last successful connection.
    renewed: bool,
    /// Hosting, when running.
    pub(super) host: Option<Hosting>,
    /// Whether hosting is being started.
    pub(super) host_starting: bool,
    /// Generation of hosting starts.
    pub(super) host_generation: u64,
    /// Viewer sessions by number.
    viewers: BTreeMap<u64, Viewing>,
    /// Next viewer session number.
    next_session: u64,
    /// The installations linked to the signed-in account.
    my_devices: Vec<MyDeviceInfo>,
    /// The signed-in account's contacts.
    pub(super) contacts: Vec<ContactView>,
    /// A message for the user.
    pub(super) banner: Option<String>,
    /// The clipboard.
    pub(super) clipboard: Clipboard,
    /// Password lockout bookkeeping.
    pub(super) lockout: access::HostLockout,
    /// Grants per viewer, remembered for the process lifetime.
    pub(super) grants: std::collections::HashMap<DeviceId, surf_rac_input::Grants>,
}

/// Returns the server URL: the environment override, the saved one, or the default.
fn server_url(store: &Store) -> String {
    std::env::var(SERVER_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| store.state().server_url)
        .unwrap_or_else(|| DEFAULT_SERVER.into())
}

/// Loads pinned identity keys from the state.
fn load_known(store: &Store) -> KnownKeys {
    let mut known = KnownKeys::default();
    for (id, key) in &store.state().known_keys {
        if let Ok(key) = IdentityPublic::from_base64(key) {
            known.trust_key(*id, key);
        }
    }
    known
}

/// Returns the API client for the server of `store`, with the account's token when signed in.
fn api_for(store: &Store) -> Api {
    Api::new(&server_url(store)).with_token(
        store
            .state()
            .account
            .map(|a| a.session_token.expose().to_string()),
    )
}

/// Returns the banner text for a connection state the client stopped in.
fn stop_text(connection: &Connection) -> Option<&'static str> {
    match connection {
        Connection::UpdateRequired => Some(UPDATE_REQUIRED_TEXT),
        Connection::Disabled => Some(DISABLED_TEXT),
        _ => None,
    }
}

impl Actor {
    /// Creates the actor from the loaded state and the installation store.
    pub(super) fn new(
        store: Store,
        installation: Arc<dyn InstallationStore>,
        shared: Arc<Mutex<Snapshot>>,
        repaint: Repaint,
    ) -> Actor {
        let (internal, _) = mpsc::unbounded_channel();
        let known = Arc::new(Mutex::new(load_known(&store)));
        Actor {
            api: api_for(&store),
            store,
            installation,
            fingerprint: fingerprint::fingerprint_hash().map_err(|e| e.to_string()),
            shared,
            repaint,
            internal,
            connection: Connection::Connecting,
            account_task: AccountTask::Idle,
            identity: None,
            known,
            signaling: None,
            generation: 0,
            attempts: 0,
            renewed: false,
            host: None,
            host_starting: false,
            host_generation: 0,
            viewers: BTreeMap::new(),
            next_session: 1,
            my_devices: Vec::new(),
            contacts: Vec::new(),
            banner: None,
            clipboard: open_clipboard(),
            lockout: access::HostLockout::default(),
            grants: Default::default(),
        }
    }

    /// Runs until the UI goes away or asks to shut down.
    pub(super) async fn run(mut self, mut commands: mpsc::UnboundedReceiver<Command>) {
        let (internal, mut internal_rx) = mpsc::unbounded_channel();
        self.internal = internal;
        self.start_identity(false);
        self.publish();
        let mut tick = tokio::time::interval(CLIPBOARD_POLL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(Command::Shutdown(done)) => {
                        self.stop_all().await;
                        let _ = done.send(());
                        return;
                    }
                    Some(command) => self.command(command).await,
                    None => {
                        self.stop_all().await;
                        return;
                    }
                },
                Some(event) = internal_rx.recv() => self.event(event).await,
                _ = tick.tick() => {
                    self.poll_clipboard().await;
                    self.prune_unjoined().await;
                    self.update_password_access();
                }
            }
            self.publish();
        }
    }

    /// Handles one command from the UI.
    async fn command(&mut self, command: Command) {
        match command {
            Command::SignIn { username, password } => self.sign_in(username, password, false),
            Command::CreateAccount { username, password } => self.sign_in(username, password, true),
            Command::SignOut => self.sign_out(),
            Command::DeleteAccount { password } => self.delete_account(password),
            Command::SetServer(url) => self.set_server(url).await,
            Command::RefreshLists => self.refresh_lists(),
            Command::PutContact { id, alias } => {
                let api = self.api.clone();
                self.spawn_account_api(async move { api.put_contact(id, &alias).await });
            }
            Command::DeleteContact(id) => {
                let api = self.api.clone();
                self.spawn_account_api(async move { api.delete_contact(id).await });
            }
            Command::UnlinkDevice(id) => {
                if Some(id) != self.identity.as_ref().map(|i| i.id) {
                    let api = self.api.clone();
                    self.spawn_account_api(async move { api.unlink_device(id).await });
                }
            }
            Command::Connect {
                host,
                password,
                remember,
            } => self.connect_to(host, password, remember),
            Command::ViewerSend { session, message } => {
                if let Some(s) = self.viewers.get(&session).and_then(|v| v.session.clone())
                    && let Err(e) = s.send(&message).await
                {
                    tracing::debug!(error = %e, "viewer message not sent");
                }
            }
            Command::ViewerHangup(session) => {
                if let Some(viewing) = self.viewers.remove(&session)
                    && let Some(s) = viewing.session
                {
                    s.hangup().await;
                }
            }
            Command::ViewerClipboard { session, on } => {
                if let Some(v) = self.viewers.get_mut(&session) {
                    v.clipboard = on;
                }
            }
            Command::Accept(session_id) => self.accept(&session_id).await,
            Command::Deny(session_id) => self.deny(&session_id).await,
            Command::SetGrants { viewer, grants } => self.set_grants(viewer, grants),
            Command::SetFollow(on) => self.set_follow(on),
            Command::HostClipboard { viewer, on } => self.set_host_clipboard(viewer, on),
            Command::Disconnect(viewer) => self.disconnect(viewer).await,
            Command::DisconnectAll => self.disconnect_all().await,
            Command::SaveSettings(settings) => self.save_settings(settings).await,
            Command::SetUnattendedPassword(password) => self.set_unattended_password(password),
            Command::ForgetPassword(id) => {
                self.save(|s| {
                    s.saved_passwords.remove(&id);
                });
                for v in self.viewers.values_mut().filter(|v| v.host == id) {
                    v.offer_forget = false;
                }
            }
            Command::Reconnect => {
                if self.connection == Connection::Replaced {
                    self.connection = Connection::Connecting;
                    self.connect_now();
                }
            }
            Command::ClearBanner => self.banner = None,
            Command::Shutdown(_) => {}
        }
    }

    /// Handles one event from a spawned task.
    async fn event(&mut self, event: Internal) {
        match event {
            Internal::IdentityReady(generation, result) if generation == self.generation => {
                self.on_identity(result)
            }
            Internal::Connected(generation, client) if generation == self.generation => {
                self.on_connected(generation, client)
            }
            Internal::ConnectFailed(generation, error) if generation == self.generation => {
                self.on_connect_failed(error)
            }
            Internal::Signal(generation, message) if generation == self.generation => {
                self.on_signal(message).await
            }
            Internal::SignalingClosed(generation) if generation == self.generation => {
                self.on_signaling_closed().await
            }
            Internal::Linked(generation, result) if generation == self.generation => {
                self.on_linked(result)
            }
            Internal::SignedIn(result) => self.on_signed_in(result),
            Internal::AccountDeleted(result) => self.on_account_deleted(result),
            Internal::Lists(Ok((devices, contacts))) => {
                if self.account().is_none() {
                    return;
                }
                self.my_devices = devices;
                self.contacts = contacts
                    .into_iter()
                    .map(|c| ContactView {
                        id: c.device_id,
                        alias: c.alias,
                        online: c.online,
                    })
                    .collect();
            }
            Internal::Lists(Err(e)) | Internal::ApiFailed(e) => {
                if e == ApiError::Unauthorized {
                    self.expire_account();
                } else {
                    self.banner = Some(e.user_message());
                }
            }
            Internal::HostStarted(generation, result) => {
                self.on_host_started(generation, result).await
            }
            Internal::Host(generation, event) => self.on_host_event(generation, event).await,
            Internal::RestartHosting => self.start_hosting(),
            Internal::InputChanged => {}
            Internal::ViewerStarted {
                session,
                result,
                used_saved,
                remember,
            } => self.on_viewer_started(session, result, used_saved, remember),
            Internal::Viewer(session, event) => self.on_viewer_event(session, event).await,
            Internal::IdentityReady(..)
            | Internal::Connected(..)
            | Internal::ConnectFailed(..)
            | Internal::Signal(..)
            | Internal::SignalingClosed(..)
            | Internal::Linked(..) => {}
        }
    }

    /// Writes a change to the state file, showing an error banner when that fails.
    pub(super) fn save(&mut self, change: impl FnOnce(&mut crate::store::State)) {
        if let Err(e) = self.store.update(change) {
            tracing::error!(error = %e, "state file not written");
            self.banner = Some("Settings could not be saved.".into());
        }
    }

    /// Writes the pinned keys to the state file.
    pub(super) fn persist_known(&mut self) {
        let keys: BTreeMap<DeviceId, String> = lock(&self.known)
            .entries()
            .map(|(id, key)| (id, key.to_base64()))
            .collect();
        if keys != self.store.state().known_keys {
            self.save(|s| s.known_keys = keys);
        }
    }

    /// Returns the signed-in account, if any.
    fn account(&self) -> Option<AccountState> {
        self.store.state().account
    }

    /// Loads or registers this installation's identity in the background,
    /// after the current backoff; with `renew` the stored one is discarded
    /// and a new one registered.
    fn start_identity(&mut self, renew: bool) {
        let fingerprint = match &self.fingerprint {
            Ok(fingerprint) => fingerprint.clone(),
            Err(e) => {
                tracing::error!(error = %e, "no device fingerprint, cannot register");
                self.connection = Connection::Offline;
                self.banner = Some(format!("This device cannot be registered: {e}"));
                return;
            }
        };
        self.generation += 1;
        let generation = self.generation;
        let delay = backoff(self.attempts);
        let store = Arc::clone(&self.installation);
        let api = self.api.with_token(None);
        let tx = self.internal.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let name = identity::device_name();
            let result = if renew {
                identity::renew(&*store, &api, &fingerprint, &name).await
            } else {
                identity::ensure(&*store, &api, &fingerprint, &name).await
            };
            let _ = tx.send(Internal::IdentityReady(generation, result));
        });
    }

    /// Takes a loaded or registered identity into use and connects, or
    /// handles why there is none.
    fn on_identity(&mut self, result: Result<Identity, IdentityError>) {
        match result {
            Ok(identity) => {
                tracing::info!(device_id = %identity.id, "installation identity ready");
                self.identity = Some(identity);
                self.connect_now();
            }
            Err(e) => {
                tracing::warn!(error = %e, "installation identity not set up");
                if let IdentityError::Store(_) = e {
                    self.banner = Some("This device's identity could not be saved.".into());
                }
                match identity_action(&e) {
                    ConnectAction::Stop(state) => self.stop_connecting(state),
                    ConnectAction::Retry | ConnectAction::Renew => {
                        self.connection = Connection::Offline;
                        self.attempts = self.attempts.saturating_add(1);
                        self.start_identity(false);
                    }
                }
            }
        }
    }

    /// Stops connecting in `state` and tells the user why.
    fn stop_connecting(&mut self, state: Connection) {
        tracing::warn!(?state, "no further connection attempts");
        self.banner = stop_text(&state).map(str::to_string);
        self.connection = state;
    }

    /// Ends every session and the signaling connection.
    async fn stop_all(&mut self) {
        self.generation += 1;
        self.attempts = 0;
        self.signaling = None;
        for (_, viewing) in std::mem::take(&mut self.viewers) {
            if let Some(s) = viewing.session {
                s.hangup().await;
            }
        }
        self.stop_hosting().await;
    }

    /// Switches to the server at `url`: signs out, forgets everything bound
    /// to the old server and registers this installation with the new one.
    async fn set_server(&mut self, url: String) {
        let url = url.trim().trim_end_matches('/').to_string();
        let saved = (!url.is_empty()).then_some(url);
        if saved == self.store.state().server_url {
            return;
        }
        self.sign_out();
        self.stop_all().await;
        self.identity = None;
        *lock(&self.known) = KnownKeys::default();
        if let Err(e) = self.installation.clear() {
            tracing::error!(error = %e, "installation not cleared");
        }
        self.save(|s| {
            s.forget_server();
            s.server_url = saved;
        });
        self.api = api_for(&self.store);
        self.renewed = false;
        self.banner = None;
        self.connection = Connection::Connecting;
        self.start_identity(false);
    }

    /// Starts a connection attempt after the current backoff.
    fn connect_now(&mut self) {
        let (Some(identity), Ok(fingerprint)) = (self.identity.clone(), self.fingerprint.clone())
        else {
            return;
        };
        self.generation += 1;
        let generation = self.generation;
        let delay = backoff(self.attempts);
        let url = self.api.ws_url();
        let tx = self.internal.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let event = match SignalingClient::connect(
                &url,
                identity.id,
                &identity.key,
                &fingerprint,
            )
            .await
            {
                Ok(client) => Internal::Connected(generation, client),
                Err(e) => Internal::ConnectFailed(generation, e),
            };
            let _ = tx.send(event);
        });
    }

    /// Takes a new connection into use, starts listening on it, links the
    /// signed-in account and starts hosting.
    fn on_connected(&mut self, generation: u64, client: SignalingClient) {
        self.attempts = 0;
        self.renewed = false;
        self.connection = Connection::Online;
        let mut events = client.subscribe();
        self.signaling = Some(client);
        let tx = self.internal.clone();
        tokio::spawn(async move {
            while let Some(message) = events.recv().await {
                if tx.send(Internal::Signal(generation, message)).is_err() {
                    return;
                }
            }
            let _ = tx.send(Internal::SignalingClosed(generation));
        });
        self.link_account();
        self.refresh_lists();
        if self.host.is_none() {
            self.start_hosting();
        }
    }

    /// Handles a failed connection attempt: renews a cloned or unknown
    /// installation once, stops for an outdated client or a disabled device,
    /// and otherwise retries with backoff.
    fn on_connect_failed(&mut self, error: SignalingError) {
        tracing::info!(error = %error, "signaling connection failed");
        match connect_action(&error, self.renewed) {
            ConnectAction::Stop(state) => self.stop_connecting(state),
            ConnectAction::Renew => {
                tracing::warn!(error = %error, "installation refused, registering a new one");
                self.identity = None;
                self.renewed = true;
                self.connection = Connection::Connecting;
                self.attempts = self.attempts.saturating_add(1);
                self.start_identity(true);
            }
            ConnectAction::Retry => {
                self.connection = Connection::Offline;
                self.attempts = self.attempts.saturating_add(1);
                self.connect_now();
            }
        }
    }

    /// Handles a message from the signaling server.
    async fn on_signal(&mut self, message: ServerMessage) {
        match message {
            ServerMessage::Presence { device_id, online } => {
                for c in self.contacts.iter_mut().filter(|c| c.id == device_id) {
                    c.online = online;
                }
                for d in self
                    .my_devices
                    .iter_mut()
                    .filter(|d| d.device_id == device_id)
                {
                    d.online = online;
                }
            }
            ServerMessage::Replaced => {
                tracing::warn!("another connection replaced this device");
                self.generation += 1;
                self.signaling = None;
                self.connection = Connection::Replaced;
                self.mark_hosting_stale().await;
            }
            ServerMessage::SessionRequest {
                from, session_id, ..
            } if !self.host_starting && self.host.as_ref().is_none_or(|h| h.is_stale()) => {
                if let Some(signaling) = &self.signaling {
                    let _ = signaling
                        .send(ClientMessage::SessionResponse {
                            to: from,
                            session_id,
                            accepted: false,
                            reason: Some(DenyReason::Denied),
                            session_key: None,
                            signature: None,
                            host_nonce: None,
                        })
                        .await;
                }
            }
            _ => {}
        }
    }

    /// Handles the end of the signaling connection: stops for a disabled
    /// device, otherwise reconnects; ends hosting once no viewer depends on it.
    async fn on_signaling_closed(&mut self) {
        let reason = self.signaling.take().and_then(|s| s.end_reason());
        tracing::info!(?reason, "signaling connection closed");
        self.mark_hosting_stale().await;
        if reason == Some(SignalingError::DeviceDisabled) {
            self.stop_connecting(Connection::Disabled);
            return;
        }
        self.connection = Connection::Offline;
        self.attempts = self.attempts.saturating_add(1);
        self.connect_now();
    }

    /// Signs in to an account, creating it first when `create` is set.
    fn sign_in(&mut self, username: String, password: String, create: bool) {
        if self.account().is_some() || matches!(self.account_task, AccountTask::Working(_)) {
            return;
        }
        self.account_task = AccountTask::Working(if create {
            "Creating account...".into()
        } else {
            "Signing in...".into()
        });
        let api = self.api.with_token(None);
        let tx = self.internal.clone();
        tokio::spawn(async move {
            let result = async {
                if create {
                    api.register(&username, &password).await?;
                }
                api.login(&username, &password).await
            }
            .await
            .map(|token| (username, Secret::new(token)))
            .map_err(|e| e.user_message());
            let _ = tx.send(Internal::SignedIn(result));
        });
    }

    /// Stores a new account session, links this installation and loads the lists.
    fn on_signed_in(&mut self, result: Result<(String, Secret), String>) {
        match result {
            Ok((username, session_token)) => {
                self.api = self
                    .api
                    .with_token(Some(session_token.expose().to_string()));
                self.save(|s| {
                    s.account = Some(AccountState {
                        username,
                        session_token,
                    })
                });
                self.account_task = AccountTask::Idle;
                self.link_account();
                self.refresh_lists();
            }
            Err(message) => self.account_task = AccountTask::Failed(message),
        }
    }

    /// Links this installation to the signed-in account over the open connection.
    fn link_account(&mut self) {
        let (Some(account), Some(signaling)) = (self.account(), self.signaling.clone()) else {
            return;
        };
        let generation = self.generation;
        let tx = self.internal.clone();
        tokio::spawn(async move {
            let result = account::link(&signaling, account.session_token.expose()).await;
            let _ = tx.send(Internal::Linked(generation, result));
        });
    }

    /// Handles the server's answer to linking this installation.
    fn on_linked(&mut self, result: Result<String, LinkError>) {
        match result {
            Ok(username) => {
                tracing::info!(%username, "installation linked to the account");
                self.refresh_lists();
            }
            Err(e) => tracing::warn!(error = %e, "installation not linked, retrying on reconnect"),
        }
    }

    /// Signs out of the account: forgets it here at once, then unlinks this
    /// installation over HTTP and ends the session on the server in the
    /// background, with or without a signaling connection.
    fn sign_out(&mut self) {
        if self.account().is_none() {
            return;
        }
        let api = self.api.clone();
        let device = self.identity.as_ref().map(|i| i.id);
        tokio::spawn(async move {
            account::sign_out(&api, device).await;
        });
        self.forget_account(AccountTask::Idle);
    }

    /// Deletes the signed-in account after the server checked `password`.
    fn delete_account(&mut self, password: String) {
        if self.account().is_none() || matches!(self.account_task, AccountTask::Working(_)) {
            return;
        }
        self.account_task = AccountTask::Working("Deleting account...".into());
        let api = self.api.clone();
        let tx = self.internal.clone();
        tokio::spawn(async move {
            let result = api.delete_account(&password).await;
            let _ = tx.send(Internal::AccountDeleted(result));
        });
    }

    /// Forgets a deleted account, or shows why it was not deleted.
    fn on_account_deleted(&mut self, result: Result<(), ApiError>) {
        match result {
            Ok(()) => self.forget_account(AccountTask::Idle),
            Err(e) => self.account_task = AccountTask::Failed(e.user_message()),
        }
    }

    /// Forgets the account because an account API call was refused with 401,
    /// and tells the user.
    fn expire_account(&mut self) {
        if self.account().is_none() {
            return;
        }
        tracing::warn!("the account session is no longer valid");
        let message = "Your account session expired. Please sign in again.";
        self.banner = Some(message.into());
        self.forget_account(AccountTask::Failed(message.into()));
    }

    /// Removes the account session, its lists and the token from the API
    /// client; the installation stays online.
    fn forget_account(&mut self, task: AccountTask) {
        self.save(|s| s.account = None);
        self.api = self.api.with_token(None);
        self.my_devices.clear();
        self.contacts.clear();
        self.account_task = task;
    }

    /// Loads My devices and contacts in the background while signed in.
    fn refresh_lists(&mut self) {
        if self.account().is_none() {
            return;
        }
        let api = self.api.clone();
        let tx = self.internal.clone();
        tokio::spawn(async move {
            let result = async { Ok((api.my_devices().await?, api.contacts().await?)) }.await;
            let _ = tx.send(Internal::Lists(result));
        });
    }

    /// Runs an account API call in the background and reloads the lists
    /// after it; without an account it only shows a hint.
    fn spawn_account_api<F>(&mut self, call: F)
    where
        F: std::future::Future<Output = Result<(), ApiError>> + Send + 'static,
    {
        if self.account().is_none() {
            self.banner = Some(SIGN_IN_FIRST_TEXT.into());
            return;
        }
        let api = self.api.clone();
        let tx = self.internal.clone();
        tokio::spawn(async move {
            if let Err(e) = call.await {
                let _ = tx.send(Internal::ApiFailed(e));
            }
            let result = async { Ok((api.my_devices().await?, api.contacts().await?)) }.await;
            let _ = tx.send(Internal::Lists(result));
        });
    }

    /// Returns the alias of `id`, or its ID when it is not a contact.
    pub(super) fn name_of(&self, id: DeviceId) -> String {
        self.contacts
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.alias.clone())
            .unwrap_or_else(|| id.to_string())
    }

    /// Starts a viewer session with `host`.
    fn connect_to(&mut self, host: DeviceId, password: Option<String>, remember: bool) {
        let Some(identity) = self.identity.clone() else {
            return;
        };
        let Some(signaling) = self.signaling.clone() else {
            self.banner = Some("Not connected to the server.".into());
            return;
        };
        let session = self.next_session;
        self.next_session += 1;
        let saved = self
            .store
            .state()
            .saved_passwords
            .get(&host)
            .map(|s| s.expose().to_string());
        let offer = password_offer(saved.as_deref(), password.as_deref());
        let remember = (remember && offer.as_ref().is_some_and(|(_, saved)| !saved))
            .then(|| password.clone())
            .flatten();
        self.viewers.insert(
            session,
            Viewing {
                host,
                session: None,
                status: ViewerStatus::Requesting,
                frame: Arc::new(Mutex::new(None)),
                screen: None,
                input: InputState::default(),
                clipboard: self.store.state().settings.clipboard_default,
                offer_forget: false,
            },
        );
        let known = Arc::clone(&self.known);
        let tx = self.internal.clone();
        tokio::spawn(async move {
            let offered_saved = offer.as_ref().is_some_and(|(_, saved)| *saved);
            let pinned = lock(&known).get(host).is_some();
            let used_saved = offered_saved && pinned;
            let options = RequestOptions {
                password: password_to_send(offer, pinned),
            };
            let result = ViewerSession::request_with(
                signaling,
                identity.key,
                known,
                host,
                options,
                SessionConfig::default(),
            )
            .await;
            let _ = tx.send(Internal::ViewerStarted {
                session,
                result,
                used_saved,
                remember,
            });
        });
    }

    /// Takes a finished viewer request into use or records why it failed.
    fn on_viewer_started(
        &mut self,
        session: u64,
        result: Result<(ViewerSession, mpsc::Receiver<ViewerEvent>), RequestError>,
        used_saved: bool,
        remember: Option<String>,
    ) {
        let Some(viewing) = self.viewers.get_mut(&session) else {
            if let Ok((s, _)) = result {
                tokio::spawn(s.hangup());
            }
            return;
        };
        match result {
            Ok((s, mut events)) => {
                viewing.session = Some(s);
                let host = viewing.host;
                let frame = Arc::clone(&viewing.frame);
                let tx = self.internal.clone();
                let repaint = Arc::clone(&self.repaint);
                tokio::spawn(async move {
                    let mut seq = 0;
                    while let Some(event) = events.recv().await {
                        if let ViewerEvent::VideoFrame(f) = event {
                            let rgba = yuv::to_rgba(&f);
                            if rgba.is_empty() {
                                continue;
                            }
                            seq += 1;
                            *lock(&frame) = Some(FrameImage {
                                width: f.width,
                                height: f.height,
                                rgba: Arc::new(rgba),
                                seq,
                            });
                            repaint();
                        } else if tx.send(Internal::Viewer(session, event)).is_err() {
                            return;
                        }
                    }
                });
                if let Some(password) = remember {
                    self.save(|s| {
                        s.saved_passwords.insert(host, Secret::new(password));
                    });
                }
                self.persist_known();
            }
            Err(e) => {
                viewing.offer_forget = offer_forget(used_saved, &e);
                viewing.status = ViewerStatus::Ended(request_error_text(&e));
            }
        }
    }

    /// Handles an event of viewer session `session`.
    async fn on_viewer_event(&mut self, session: u64, event: ViewerEvent) {
        let Some(viewing) = self.viewers.get_mut(&session) else {
            return;
        };
        match event {
            ViewerEvent::Connected => viewing.status = ViewerStatus::Connected,
            ViewerEvent::Reconnecting => viewing.status = ViewerStatus::Reconnecting,
            ViewerEvent::Ended { reason } => {
                viewing.status = ViewerStatus::Ended(end_text(reason));
                viewing.session = None;
                viewing.input = InputState::default();
            }
            ViewerEvent::DataReceived(DataMessage::Control(Control::ScreenState(state))) => {
                viewing.screen = Some(state)
            }
            ViewerEvent::DataReceived(DataMessage::Control(Control::InputState(state))) => {
                viewing.input = state
            }
            ViewerEvent::DataReceived(message @ DataMessage::Clipboard { .. }) => {
                if viewing.clipboard {
                    self.apply_clipboard(&message);
                }
            }
            ViewerEvent::DataReceived(_) | ViewerEvent::VideoFrame(_) => {}
        }
    }

    /// Writes a clipboard item received from a peer to this machine's clipboard.
    pub(super) fn apply_clipboard(&mut self, message: &DataMessage) {
        if let (Some(sync), Some(item)) = (self.clipboard.as_mut(), clipboard::decode(message)) {
            sync.apply(item);
        }
    }

    /// Sends a local clipboard change to every session that syncs the clipboard.
    async fn poll_clipboard(&mut self) {
        let viewer_targets: Vec<ViewerSession> = self
            .viewers
            .values()
            .filter(|v| v.clipboard && v.status == ViewerStatus::Connected)
            .filter_map(|v| v.session.clone())
            .collect();
        let host_targets = self.host_clipboard_targets();
        if viewer_targets.is_empty() && host_targets.is_empty() {
            return;
        }
        let Some(item) = self.clipboard.as_mut().and_then(|c| c.poll()) else {
            return;
        };
        let Some(message) = clipboard::encode(&item) else {
            return;
        };
        for session in viewer_targets {
            if let Err(e) = session.send(&message).await {
                tracing::debug!(error = %e, "clipboard not sent to host");
            }
        }
        if let Some(host) = &self.host {
            for viewer in host_targets {
                if let Err(e) = host.session.send(viewer, &message).await {
                    tracing::debug!(error = %e, "clipboard not sent to viewer");
                }
            }
        }
    }

    /// Saves new settings, keeping the password hash, and starts or stops hosting to match.
    async fn save_settings(&mut self, mut settings: Settings) {
        settings.password_hash = self.store.state().settings.password_hash.clone();
        let allow = settings.allow_incoming;
        self.save(|s| s.settings = settings);
        if !allow {
            self.stop_hosting().await;
        } else if self.host.is_none() {
            self.start_hosting();
        }
        self.update_password_access();
    }

    /// Sets or clears the unattended password.
    fn set_unattended_password(&mut self, password: Option<String>) {
        let hash = match password {
            None => None,
            Some(p) if p.chars().count() < access::MIN_PASSWORD_LEN => {
                self.banner = Some(format!(
                    "The password needs at least {} characters.",
                    access::MIN_PASSWORD_LEN
                ));
                return;
            }
            Some(p) => match access::hash_password(&p) {
                Ok(hash) => Some(Secret::new(hash)),
                Err(e) => {
                    tracing::error!(error = %e, "password not hashed");
                    self.banner = Some("The password could not be set.".into());
                    return;
                }
            },
        };
        self.save(|s| s.settings.password_hash = hash);
        self.update_password_access();
    }

    /// Publishes the current state for the UI and asks it to redraw.
    fn publish(&self) {
        let state = self.store.state();
        let mut settings = state.settings.clone();
        settings.password_hash = None;
        let snapshot = Snapshot {
            connection: self.connection.clone(),
            account: state.account.as_ref().map(|a| a.username.clone()),
            account_task: self.account_task.clone(),
            server_url: server_url(&self.store),
            device_id: self.identity.as_ref().map(|i| i.id),
            my_devices: self.my_devices.clone(),
            contacts: self.contacts.clone(),
            prompts: self
                .host
                .as_ref()
                .map(|h| h.prompts.clone())
                .unwrap_or_default(),
            host_viewers: self.host_viewer_views(),
            hosting: self.host.is_some(),
            follow: self.host.as_ref().is_some_and(|h| h.follow),
            input_locked: self.host.as_ref().is_some_and(|h| h.input_locked()),
            banner: self.banner.clone(),
            viewers: self
                .viewers
                .iter()
                .map(|(session, v)| ViewerView {
                    session: *session,
                    host: v.host,
                    name: self.name_of(v.host),
                    status: v.status.clone(),
                    frame: Arc::clone(&v.frame),
                    screen: v.screen.clone(),
                    input: v.input,
                    clipboard: v.clipboard,
                    offer_forget: v.offer_forget,
                })
                .collect(),
            settings,
            saved_passwords: state.saved_passwords.keys().copied().collect(),
            unattended_password_set: state.settings.password_hash.is_some(),
        };
        *lock(&self.shared) = snapshot;
        (self.repaint)();
    }
}
