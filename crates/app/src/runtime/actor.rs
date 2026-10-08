//! The runtime actor: owns all session state and handles commands and events
//! one at a time.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use surf_rac_protocol::data::{Control, DataMessage, InputState, ScreenState};
use surf_rac_protocol::{
    ClientMessage, ContactInfo, DenyReason, DeviceId, DeviceInfo, ServerMessage,
};
use surf_rac_session::host::{HostEvent, HostSession};
use surf_rac_session::signaling::{SignalingClient, SignalingError};
use surf_rac_session::viewer::{RequestError, RequestOptions, ViewerEvent, ViewerSession};
use surf_rac_session::{KnownKeys, PublicKey, SessionConfig};
use tokio::sync::mpsc;

use super::hosting::Hosting;
use super::identity::{self, Identity};
use super::{
    Auth, Command, ContactView, DEFAULT_SERVER, FrameImage, Repaint, SERVER_ENV, Snapshot,
    ViewerStatus, ViewerView, backoff, end_text, lock, password_offer, request_error_text,
};
use crate::access;
use crate::api::{Api, ApiError};
use crate::clipboard::{self, ClipboardSync};
use crate::store::{Secret, Settings, Store};
use crate::yuv;

/// How often the clipboard is checked while a session syncs it.
const CLIPBOARD_POLL: Duration = Duration::from_millis(500);

/// Events from tasks the actor spawned.
pub(super) enum Internal {
    /// Login or registration finished.
    LoggedIn(Result<(String, Secret), String>),
    /// Device registration finished.
    DeviceReady(Result<Identity, String>),
    /// A signaling connection of generation `.0` opened.
    Connected(u64, SignalingClient),
    /// A connection attempt of generation `.0` failed.
    ConnectFailed(u64, SignalingError),
    /// The server rejected the connection; `.1` tells whether the session token is still valid.
    Rejected(u64, bool),
    /// A message arrived on the connection of generation `.0`.
    Signal(u64, ServerMessage),
    /// The connection of generation `.0` closed.
    SignalingClosed(u64),
    /// Devices and contacts loaded.
    Lists(Result<(Vec<DeviceInfo>, Vec<ContactInfo>), ApiError>),
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
        /// Whether the saved password was offered.
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
    /// The published snapshot.
    shared: Arc<Mutex<Snapshot>>,
    /// Asks the UI to redraw.
    pub(super) repaint: Repaint,
    /// Sender for task events.
    pub(super) internal: mpsc::UnboundedSender<Internal>,
    /// Sign-in and connection state.
    pub(super) auth: Auth,
    /// API client with the current token.
    pub(super) api: Api,
    /// This device, once registered.
    pub(super) identity: Option<Identity>,
    /// Pinned peer keys.
    pub(super) known: Arc<Mutex<KnownKeys>>,
    /// The open signaling connection.
    pub(super) signaling: Option<SignalingClient>,
    /// Generation of the current connection; events of older ones are ignored.
    pub(super) generation: u64,
    /// Failed connection attempts in a row.
    attempts: u32,
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
    /// The account's devices.
    devices: Vec<DeviceInfo>,
    /// The account's contacts.
    pub(super) contacts: Vec<ContactView>,
    /// A message for the user.
    pub(super) banner: Option<String>,
    /// The clipboard.
    pub(super) clipboard: Clipboard,
    /// Password lockout bookkeeping.
    pub(super) lockout: access::Lockout,
    /// Grants per viewer, remembered for the process lifetime.
    pub(super) grants: std::collections::HashMap<DeviceId, surf_rac_input::Grants>,
}

/// Returns the server URL: the environment override, the saved one, or the default.
fn server_url(store: &Store) -> String {
    std::env::var(SERVER_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| store.state().server_url.clone())
        .unwrap_or_else(|| DEFAULT_SERVER.into())
}

/// Loads pinned keys from the state.
fn load_known(store: &Store) -> KnownKeys {
    let mut known = KnownKeys::default();
    for (id, key) in &store.state().known_keys {
        if let Ok(key) = PublicKey::from_base64(key) {
            known.trust_key(*id, key);
        }
    }
    known
}

impl Actor {
    /// Creates the actor from the loaded state.
    pub(super) fn new(store: Store, shared: Arc<Mutex<Snapshot>>, repaint: Repaint) -> Actor {
        let (internal, _) = mpsc::unbounded_channel();
        let api = Api::new(&server_url(&store)).with_token(
            store
                .state()
                .session_token
                .as_ref()
                .map(|t| t.expose().to_string()),
        );
        let known = Arc::new(Mutex::new(load_known(&store)));
        Actor {
            identity: Identity::from_state(store.state()),
            store,
            shared,
            repaint,
            internal,
            auth: Auth::LoggedOut { message: None },
            api,
            known,
            signaling: None,
            generation: 0,
            attempts: 0,
            host: None,
            host_starting: false,
            host_generation: 0,
            viewers: BTreeMap::new(),
            next_session: 1,
            devices: Vec::new(),
            contacts: Vec::new(),
            banner: None,
            clipboard: open_clipboard(),
            lockout: access::Lockout::default(),
            grants: Default::default(),
        }
    }

    /// Runs until the UI goes away or asks to shut down.
    pub(super) async fn run(mut self, mut commands: mpsc::UnboundedReceiver<Command>) {
        let (internal, mut internal_rx) = mpsc::unbounded_channel();
        self.internal = internal;
        self.resume();
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
                _ = tick.tick() => self.poll_clipboard().await,
            }
            self.publish();
        }
    }

    /// Picks up where the last run ended: connects when logged in.
    fn resume(&mut self) {
        if self.store.state().session_token.is_none() {
            return;
        }
        if self.identity.is_some() {
            self.auth = Auth::Connecting;
            self.connect_now();
        } else {
            self.register_device();
        }
    }

    /// Handles one command from the UI.
    async fn command(&mut self, command: Command) {
        match command {
            Command::Login { username, password } => self.login(None, username, password),
            Command::Register {
                invite,
                username,
                password,
            } => self.login(Some(invite), username, password),
            Command::Logout => self.logout(None).await,
            Command::SetServer(url) => {
                self.logout(None).await;
                let url = url.trim().trim_end_matches('/').to_string();
                let saved = (!url.is_empty()).then_some(url);
                self.save(|s| s.server_url = saved);
                self.api = Api::new(&server_url(&self.store));
            }
            Command::RefreshLists => self.refresh_lists(),
            Command::PutContact { id, alias } => {
                let api = self.api.clone();
                self.spawn_api(async move { api.put_contact(id, &alias).await });
            }
            Command::DeleteContact(id) => {
                let api = self.api.clone();
                self.spawn_api(async move { api.delete_contact(id).await });
            }
            Command::DeleteDevice(id) => {
                if Some(id) != self.identity.as_ref().map(|i| i.id) {
                    let api = self.api.clone();
                    self.spawn_api(async move { api.delete_device(id).await });
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
                if self.auth == Auth::Replaced {
                    self.auth = Auth::Connecting;
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
            Internal::LoggedIn(Ok((account, token))) => {
                self.save(|s| {
                    s.account = Some(account);
                    s.session_token = Some(token.clone());
                });
                self.api = self.api.with_token(Some(token.expose().to_string()));
                if self.identity.is_some() {
                    self.auth = Auth::Connecting;
                    self.connect_now();
                } else {
                    self.register_device();
                }
            }
            Internal::LoggedIn(Err(message)) => {
                self.auth = Auth::LoggedOut {
                    message: Some(message),
                }
            }
            Internal::DeviceReady(Ok(identity)) => {
                self.save(|s| identity.store(s));
                self.identity = Some(identity);
                self.auth = Auth::Connecting;
                self.connect_now();
            }
            Internal::DeviceReady(Err(message)) => {
                self.auth = Auth::LoggedOut {
                    message: Some(format!("This device could not be registered: {message}")),
                }
            }
            Internal::Connected(generation, client) if generation == self.generation => {
                self.on_connected(generation, client)
            }
            Internal::ConnectFailed(generation, error) if generation == self.generation => {
                self.on_connect_failed(generation, error)
            }
            Internal::Rejected(generation, token_valid) if generation == self.generation => {
                if token_valid {
                    tracing::warn!("device credentials rejected, registering again");
                    self.identity = None;
                    self.save(|s| {
                        s.device_secret = None;
                    });
                    self.register_device();
                } else {
                    self.expire_session().await;
                }
            }
            Internal::Signal(generation, message) if generation == self.generation => {
                self.on_signal(message).await
            }
            Internal::SignalingClosed(generation) if generation == self.generation => {
                self.on_signaling_closed().await
            }
            Internal::Lists(Ok((devices, contacts))) => {
                self.devices = devices;
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
                    self.expire_session().await;
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
            Internal::Connected(..)
            | Internal::ConnectFailed(..)
            | Internal::Rejected(..)
            | Internal::Signal(..)
            | Internal::SignalingClosed(..) => {}
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

    /// Logs in, or registers and then logs in when `invite` is set.
    fn login(&mut self, invite: Option<String>, username: String, password: String) {
        self.auth = Auth::Working(if invite.is_some() {
            "Creating account...".into()
        } else {
            "Logging in...".into()
        });
        let api = self.api.with_token(None);
        let tx = self.internal.clone();
        tokio::spawn(async move {
            let result = async {
                if let Some(invite) = invite {
                    api.register(&invite, &username, &password).await?;
                }
                api.login(&username, &password).await
            }
            .await
            .map(|token| (username, Secret::new(token)))
            .map_err(|e| e.user_message());
            let _ = tx.send(Internal::LoggedIn(result));
        });
    }

    /// Registers this device in the background.
    fn register_device(&mut self) {
        self.auth = Auth::Working("Registering this device...".into());
        let api = self.api.clone();
        let state = self.store.state().clone();
        let tx = self.internal.clone();
        tokio::spawn(async move {
            let _ = tx.send(Internal::DeviceReady(
                identity::register(&api, &state).await,
            ));
        });
    }

    /// Stops all sessions and forgets the session token.
    async fn logout(&mut self, message: Option<String>) {
        if self.store.state().session_token.is_some() {
            let api = self.api.clone();
            tokio::spawn(async move {
                let _ = api.logout().await;
            });
        }
        self.stop_all().await;
        self.save(|s| s.session_token = None);
        self.api = self.api.with_token(None);
        self.devices.clear();
        self.contacts.clear();
        self.auth = Auth::LoggedOut { message };
    }

    /// Logs out because the server no longer accepts the session token.
    async fn expire_session(&mut self) {
        self.logout(Some("Your session expired. Please log in again.".into()))
            .await;
    }

    /// Ends every session and the signaling connection.
    async fn stop_all(&mut self) {
        self.generation += 1;
        self.signaling = None;
        for (_, viewing) in std::mem::take(&mut self.viewers) {
            if let Some(s) = viewing.session {
                s.hangup().await;
            }
        }
        self.stop_hosting().await;
    }

    /// Starts a connection attempt after the current backoff.
    fn connect_now(&mut self) {
        let (Some(identity), Some(token)) = (
            self.identity.clone(),
            self.store.state().session_token.clone(),
        ) else {
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
                token.expose(),
                identity.id,
                identity.secret.expose(),
            )
            .await
            {
                Ok(client) => Internal::Connected(generation, client),
                Err(e) => Internal::ConnectFailed(generation, e),
            };
            let _ = tx.send(event);
        });
    }

    /// Takes a new connection into use and starts listening on it.
    fn on_connected(&mut self, generation: u64, client: SignalingClient) {
        self.attempts = 0;
        self.auth = Auth::Online;
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
        self.refresh_lists();
        if self.host.is_none() {
            self.start_hosting();
        }
    }

    /// Handles a failed connection attempt: checks credentials on rejection, else retries.
    fn on_connect_failed(&mut self, generation: u64, error: SignalingError) {
        if let SignalingError::Rejected(401 | 403) = error {
            let api = self.api.clone();
            let tx = self.internal.clone();
            tokio::spawn(async move {
                let token_valid = !matches!(api.devices().await, Err(ApiError::Unauthorized));
                let _ = tx.send(Internal::Rejected(generation, token_valid));
            });
            return;
        }
        tracing::info!(error = %error, "signaling connection failed");
        self.auth = Auth::Offline;
        self.attempts = self.attempts.saturating_add(1);
        self.connect_now();
    }

    /// Handles a message from the signaling server.
    async fn on_signal(&mut self, message: ServerMessage) {
        match message {
            ServerMessage::Presence { device_id, online } => {
                for c in self.contacts.iter_mut().filter(|c| c.id == device_id) {
                    c.online = online;
                }
                for d in self.devices.iter_mut().filter(|d| d.device_id == device_id) {
                    d.online = online;
                }
            }
            ServerMessage::Replaced => {
                tracing::warn!("another connection replaced this device");
                self.generation += 1;
                self.signaling = None;
                self.auth = Auth::Replaced;
            }
            ServerMessage::SessionRequest {
                from, session_id, ..
            } if self.host.is_none() && !self.host_starting => {
                if let Some(signaling) = &self.signaling {
                    let _ = signaling
                        .send(ClientMessage::SessionResponse {
                            to: from,
                            session_id,
                            accepted: false,
                            reason: Some(DenyReason::Denied),
                            host_public_key: None,
                            host_nonce: None,
                        })
                        .await;
                }
            }
            _ => {}
        }
    }

    /// Handles the end of the signaling connection: reconnects, and ends hosting
    /// once no viewer depends on it.
    async fn on_signaling_closed(&mut self) {
        tracing::info!("signaling connection closed");
        self.signaling = None;
        self.auth = Auth::Offline;
        self.attempts = self.attempts.saturating_add(1);
        self.mark_hosting_stale().await;
        self.connect_now();
    }

    /// Loads devices and contacts in the background.
    fn refresh_lists(&mut self) {
        if self.store.state().session_token.is_none() {
            return;
        }
        let api = self.api.clone();
        let tx = self.internal.clone();
        tokio::spawn(async move {
            let result = async { Ok((api.devices().await?, api.contacts().await?)) }.await;
            let _ = tx.send(Internal::Lists(result));
        });
    }

    /// Runs an API call in the background and reloads the lists after it.
    fn spawn_api<F>(&mut self, call: F)
    where
        F: std::future::Future<Output = Result<(), ApiError>> + Send + 'static,
    {
        let api = self.api.clone();
        let tx = self.internal.clone();
        tokio::spawn(async move {
            if let Err(e) = call.await {
                let _ = tx.send(Internal::ApiFailed(e));
            }
            let result = async { Ok((api.devices().await?, api.contacts().await?)) }.await;
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
        let api = self.api.clone();
        let known = Arc::clone(&self.known);
        let tx = self.internal.clone();
        tokio::spawn(async move {
            let used_saved = offer.as_ref().is_some_and(|(_, saved)| *saved);
            let pinned = lock(&known).get(host).copied();
            let host_key = match (&offer, pinned) {
                (Some(_), None) => api
                    .presence(host)
                    .await
                    .ok()
                    .and_then(|p| p.public_key)
                    .and_then(|k| PublicKey::from_base64(&k).ok()),
                _ => None,
            };
            let options = RequestOptions {
                password: offer.map(|(p, _)| p),
                host_key,
            };
            let result = ViewerSession::request_with(
                signaling,
                identity.keys,
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
                viewing.offer_forget = used_saved && e == RequestError::Denied;
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
    }

    /// Publishes the current state for the UI and asks it to redraw.
    fn publish(&self) {
        let state = self.store.state();
        let mut settings = state.settings.clone();
        settings.password_hash = None;
        let snapshot = Snapshot {
            auth: self.auth.clone(),
            account: state.account.clone(),
            server_url: server_url(&self.store),
            device_id: self.identity.as_ref().map(|i| i.id),
            devices: self.devices.clone(),
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
