//! The host side of the runtime: being reachable, deciding requests, and
//! running screen capture and input while viewers are connected.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use surf_rac_capture::{ScreenShare, ShareOptions};
use surf_rac_input::{Grants, InputHost, InputStatus};
use surf_rac_protocol::DeviceId;
use surf_rac_protocol::data::{Control, DataMessage};
use surf_rac_session::SessionConfig;
use surf_rac_session::host::{HostEvent, HostSession, Password};
use tokio::sync::{mpsc, watch};

use super::actor::{Actor, Internal};
use super::{Connection, HostViewerView, PromptView};
use crate::access::{self, Decision, PromptNote};

/// Placeholder size of the screen track until capture starts.
const INITIAL_TRACK: (u32, u32) = (1280, 720);

/// Wait before hosting is retried after it failed or ended.
const RESTART_DELAY: Duration = Duration::from_secs(10);

/// How long an accepted viewer has to join the room before it is given up.
const JOIN_WINDOW: Duration = Duration::from_secs(70);

/// A viewer accepted by this host.
struct HostViewer {
    /// What it may do.
    grants: Grants,
    /// Whether the clipboard syncs with it.
    clipboard: bool,
    /// Whether it joined the room.
    joined: bool,
    /// When it was accepted.
    accepted: Instant,
}

/// A running host session with its capture and input, while viewers are connected.
pub(super) struct Hosting {
    /// The host session.
    pub(super) session: HostSession,
    /// The start generation this session belongs to.
    generation: u64,
    /// Screen capture, while viewers are connected.
    share: Option<ScreenShare>,
    /// Input arbitration, while viewers are connected and input works here.
    input: Option<InputHost>,
    /// The input status, while input runs.
    status: Option<watch::Receiver<InputStatus>>,
    /// Accepted viewers.
    viewers: BTreeMap<DeviceId, HostViewer>,
    /// Requests waiting for an answer.
    pub(super) prompts: Vec<PromptView>,
    /// What the password check found for requests that fell back to a prompt.
    notes: BTreeMap<String, PromptNote>,
    /// Whether follow mode is on.
    pub(super) follow: bool,
    /// Whether the signaling connection this session used has closed.
    stale: bool,
}

impl Hosting {
    /// Returns whether the signaling connection this session used has closed.
    pub(super) fn is_stale(&self) -> bool {
        self.stale
    }

    /// Returns whether host input currently locks out remote input.
    pub(super) fn input_locked(&self) -> bool {
        self.status.as_ref().is_some_and(|s| s.borrow().locked)
    }

    /// Passes an event to the share and input, whichever are running.
    fn route(&self, event: &HostEvent) {
        match (&self.share, &self.input) {
            (Some(share), Some(input)) => surf_rac_input::route(event, share, input),
            (Some(share), None) => match event {
                HostEvent::ViewerJoined { viewer } => share.viewer_joined(*viewer),
                HostEvent::DataReceived {
                    viewer,
                    message:
                        DataMessage::Control(
                            control @ (Control::SelectMonitor { .. } | Control::SetQuality { .. }),
                        ),
                } => share.handle_control(*viewer, control),
                _ => {}
            },
            _ => {}
        }
    }

    /// Stops input and capture.
    async fn stop_capture(&mut self) {
        self.status = None;
        if let Some(input) = self.input.take() {
            input.stop().await;
        }
        if let Some(share) = self.share.take() {
            share.stop().await;
        }
    }
}

/// Returns whether a viewer accepted at `accepted` that has not joined by `now` is given up.
fn join_expired(accepted: Instant, joined: bool, now: Instant) -> bool {
    !joined && now.saturating_duration_since(accepted) >= JOIN_WINDOW
}

impl Actor {
    /// Starts hosting when allowed, connected and not already running.
    pub(super) fn start_hosting(&mut self) {
        if self.host.is_some() || self.host_starting || !self.store.state().settings.allow_incoming
        {
            return;
        }
        let (Some(signaling), Some(identity)) = (self.signaling.clone(), self.identity.clone())
        else {
            return;
        };
        self.host_starting = true;
        self.host_generation += 1;
        let generation = self.host_generation;
        let known = Arc::clone(&self.known);
        let tx = self.internal.clone();
        tokio::spawn(async move {
            let result = HostSession::start(
                signaling,
                identity.key,
                known,
                INITIAL_TRACK.0,
                INITIAL_TRACK.1,
                SessionConfig::default(),
            )
            .await
            .map_err(|e| e.to_string());
            let _ = tx.send(Internal::HostStarted(generation, result));
        });
    }

    /// Takes a started host session into use, or schedules a retry when it failed.
    pub(super) async fn on_host_started(
        &mut self,
        generation: u64,
        result: Result<(HostSession, mpsc::Receiver<HostEvent>), String>,
    ) {
        if generation != self.host_generation {
            if let Ok((session, _)) = result {
                session.close().await;
            }
            return;
        }
        self.host_starting = false;
        match result {
            Ok((session, mut events)) => {
                if !self.store.state().settings.allow_incoming || self.signaling.is_none() {
                    session.close().await;
                    return;
                }
                let tx = self.internal.clone();
                tokio::spawn(async move {
                    while let Some(event) = events.recv().await {
                        if tx.send(Internal::Host(generation, event)).is_err() {
                            return;
                        }
                    }
                });
                self.host = Some(Hosting {
                    session,
                    generation,
                    share: None,
                    input: None,
                    status: None,
                    viewers: BTreeMap::new(),
                    prompts: Vec::new(),
                    notes: BTreeMap::new(),
                    follow: false,
                    stale: false,
                });
                self.update_password_access();
            }
            Err(e) => {
                tracing::warn!(error = %e, "hosting could not start");
                self.banner = Some(format!("Incoming connections are unavailable: {e}"));
                self.schedule_restart();
            }
        }
    }

    /// Asks for another hosting start after [`RESTART_DELAY`].
    fn schedule_restart(&self) {
        let tx = self.internal.clone();
        tokio::spawn(async move {
            tokio::time::sleep(RESTART_DELAY).await;
            let _ = tx.send(Internal::RestartHosting);
        });
    }

    /// Handles an event of the host session of `generation`.
    pub(super) async fn on_host_event(&mut self, generation: u64, event: HostEvent) {
        if self
            .host
            .as_ref()
            .is_none_or(|h| h.generation != generation)
        {
            return;
        }
        match &event {
            HostEvent::ViewerRequested {
                session_id,
                viewer,
                name,
                fingerprint,
                ..
            } => {
                self.on_request(session_id, *viewer, name, fingerprint)
                    .await
            }
            HostEvent::PasswordReceived {
                session_id,
                viewer,
                password,
                ..
            } => {
                self.on_password(session_id, *viewer, password.as_ref())
                    .await
            }
            HostEvent::KeyChanged(changed) => {
                self.banner = Some(format!(
                    "Device {} presented a different security key; its request was refused.",
                    changed.device_id
                ));
            }
            HostEvent::RequestExpired { session_id, .. } => {
                if let Some(host) = self.host.as_mut() {
                    host.prompts.retain(|p| &p.session_id != session_id);
                    host.notes.remove(session_id);
                }
            }
            HostEvent::ViewerJoined { viewer } => {
                let remembered = self.grants.get(viewer).copied();
                let clipboard = self.store.state().settings.clipboard_default;
                let Some(host) = self.host.as_mut() else {
                    return;
                };
                host.route(&event);
                if let (Some(grants), Some(input)) = (remembered, &host.input) {
                    input.set_grants(*viewer, grants);
                }
                host.viewers
                    .entry(*viewer)
                    .or_insert(HostViewer {
                        grants: remembered.unwrap_or_default(),
                        clipboard,
                        joined: false,
                        accepted: Instant::now(),
                    })
                    .joined = true;
            }
            HostEvent::ViewerLeft { viewer } => {
                let Some(host) = self.host.as_mut() else {
                    return;
                };
                host.route(&event);
                host.viewers.remove(viewer);
                if host.viewers.is_empty() {
                    host.stop_capture().await;
                    if host.stale {
                        self.stop_hosting().await;
                        self.start_hosting();
                    }
                }
            }
            HostEvent::DataReceived {
                viewer,
                message: message @ DataMessage::Clipboard { .. },
            } => {
                let syncs = self
                    .host
                    .as_ref()
                    .and_then(|h| h.viewers.get(viewer))
                    .is_some_and(|v| v.joined && v.clipboard);
                if syncs {
                    self.apply_clipboard(message);
                }
            }
            HostEvent::DataReceived { .. } => {
                if let Some(host) = &self.host {
                    host.route(&event);
                }
            }
            HostEvent::Reconnecting | HostEvent::Reconnected => {}
            HostEvent::Ended { reason } => {
                tracing::warn!(?reason, "hosting ended");
                self.stop_hosting().await;
                if self.connection == Connection::Online {
                    self.schedule_restart();
                }
            }
        }
    }

    /// Tells the host session whether viewers may send the unattended
    /// password: unattended access is on, a password is set and password
    /// access is not locked out.
    pub(super) fn update_password_access(&self) {
        let settings = self.store.state().settings;
        let available = access::password_access_available(
            settings.unattended,
            settings.password_hash.is_some(),
            false,
            self.lockout.is_locked(Instant::now()),
        );
        if let Some(host) = &self.host {
            host.session.set_password_access(available);
        }
    }

    /// Shows a prompt for a session request, with what the password check
    /// found when the request fell back from a password. An open prompt of
    /// the same viewer is replaced and its request denied.
    async fn on_request(
        &mut self,
        session_id: &str,
        viewer: DeviceId,
        name: &str,
        fingerprint: &str,
    ) {
        self.persist_known();
        let alias = self
            .contacts
            .iter()
            .find(|c| c.id == viewer)
            .map(|c| c.alias.clone());
        let Some(host) = self.host.as_mut() else {
            return;
        };
        let note = host.notes.remove(session_id).unwrap_or(PromptNote::None);
        let replaced = access::open_prompt(
            &mut host.prompts,
            PromptView {
                session_id: session_id.to_string(),
                viewer,
                name: name.to_string(),
                alias,
                fingerprint: fingerprint.to_string(),
                note,
            },
        );
        for old in replaced {
            host.notes.remove(&old);
            if let Err(e) = host.session.deny(&old).await {
                tracing::debug!(error = %e, "replaced request not denied");
            }
        }
    }

    /// Decides a request whose viewer sent the unattended password: admits
    /// it on a correct password with unattended access on, otherwise falls
    /// back to a prompt.
    async fn on_password(
        &mut self,
        session_id: &str,
        viewer: DeviceId,
        password: Option<&Password>,
    ) {
        self.persist_known();
        let settings = self.store.state().settings;
        let hash = settings
            .password_hash
            .as_ref()
            .map(|h| h.expose().to_string());
        let unattended = settings.unattended && hash.is_some();
        let check = access::check_password(password.map(Password::as_str), hash.as_deref());
        let decision = access::decide(check, unattended, &mut self.lockout, Instant::now());
        self.update_password_access();
        tracing::info!(viewer = %viewer, ?check, ?decision, "unattended password received");
        match decision {
            Decision::Accept => self.accept_request(session_id, viewer).await,
            Decision::Prompt(note) => {
                let Some(host) = self.host.as_mut() else {
                    return;
                };
                host.notes.insert(session_id.to_string(), note);
                if let Err(e) = host.session.reject_password(session_id).await {
                    tracing::debug!(error = %e, "password not rejected");
                    host.notes.remove(session_id);
                }
            }
        }
    }

    /// Accepts the pending request `session_id` from the prompt.
    pub(super) async fn accept(&mut self, session_id: &str) {
        let Some(viewer) = self.take_prompt(session_id) else {
            return;
        };
        self.accept_request(session_id, viewer).await;
    }

    /// Denies the pending request `session_id` from the prompt.
    pub(super) async fn deny(&mut self, session_id: &str) {
        if self.take_prompt(session_id).is_none() {
            return;
        }
        if let Some(host) = &self.host
            && let Err(e) = host.session.deny(session_id).await
        {
            tracing::debug!(error = %e, "deny failed");
        }
    }

    /// Removes the prompt of `session_id` and returns its viewer.
    fn take_prompt(&mut self, session_id: &str) -> Option<DeviceId> {
        let host = self.host.as_mut()?;
        let index = host
            .prompts
            .iter()
            .position(|p| p.session_id == session_id)?;
        Some(host.prompts.remove(index).viewer)
    }

    /// Starts capture if needed and accepts `viewer`'s request.
    async fn accept_request(&mut self, session_id: &str, viewer: DeviceId) {
        if let Err(e) = self.ensure_capture().await {
            tracing::error!(error = %e, "screen capture could not start");
            self.banner = Some(format!("The screen cannot be shared: {e}"));
            if let Some(host) = &self.host {
                let _ = host.session.deny(session_id).await;
            }
            return;
        }
        let grants = self.grants.get(&viewer).copied().unwrap_or_default();
        let clipboard = self.store.state().settings.clipboard_default;
        let Some(host) = self.host.as_mut() else {
            return;
        };
        match host.session.accept(session_id).await {
            Ok(()) => {
                host.viewers.entry(viewer).or_insert(HostViewer {
                    grants,
                    clipboard,
                    joined: false,
                    accepted: Instant::now(),
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                if host.viewers.is_empty() {
                    host.stop_capture().await;
                }
            }
        }
    }

    /// Starts screen capture and input when they are not running.
    ///
    /// Capture failing is an error; input failing leaves viewers watch-only.
    async fn ensure_capture(&mut self) -> Result<(), String> {
        let tx = self.internal.clone();
        let host = self.host.as_mut().ok_or("not hosting")?;
        if host.share.is_some() {
            return Ok(());
        }
        let share = ScreenShare::start(host.session.clone(), ShareOptions::default())
            .await
            .map_err(|e| e.to_string())?;
        let input = InputHost::start(host.session.clone(), share.handle()).await;
        host.share = Some(share);
        match input {
            Ok(input) => {
                input.set_follow(host.follow);
                let mut status = input.subscribe();
                host.status = Some(status.clone());
                host.input = Some(input);
                tokio::spawn(async move {
                    while status.changed().await.is_ok() {
                        if tx.send(Internal::InputChanged).is_err() {
                            return;
                        }
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "remote input unavailable");
                self.banner =
                    Some("Remote control is unavailable here; viewers can only watch.".into());
            }
        }
        Ok(())
    }

    /// Changes what `viewer` may do and remembers it for later sessions.
    pub(super) fn set_grants(&mut self, viewer: DeviceId, grants: Grants) {
        self.grants.insert(viewer, grants);
        if let Some(host) = self.host.as_mut() {
            if let Some(v) = host.viewers.get_mut(&viewer) {
                v.grants = grants;
            }
            if let Some(input) = &host.input {
                input.set_grants(viewer, grants);
            }
        }
    }

    /// Turns follow mode on or off.
    pub(super) fn set_follow(&mut self, on: bool) {
        if let Some(host) = self.host.as_mut() {
            host.follow = on;
            if let Some(input) = &host.input {
                input.set_follow(on);
            }
        }
    }

    /// Turns clipboard sync with `viewer` on or off.
    pub(super) fn set_host_clipboard(&mut self, viewer: DeviceId, on: bool) {
        if let Some(v) = self.host.as_mut().and_then(|h| h.viewers.get_mut(&viewer)) {
            v.clipboard = on;
        }
    }

    /// Disconnects `viewer`.
    pub(super) async fn disconnect(&mut self, viewer: DeviceId) {
        if let Some(host) = &self.host
            && let Err(e) = host.session.hangup(viewer).await
        {
            tracing::debug!(error = %e, "hangup message not delivered");
        }
    }

    /// Disconnects every viewer.
    pub(super) async fn disconnect_all(&mut self) {
        let viewers: Vec<DeviceId> = self
            .host
            .as_ref()
            .map(|h| h.viewers.keys().copied().collect())
            .unwrap_or_default();
        for viewer in viewers {
            self.disconnect(viewer).await;
        }
    }

    /// Stops hosting: ends capture and input and leaves the room.
    pub(super) async fn stop_hosting(&mut self) {
        self.host_starting = false;
        self.host_generation += 1;
        if let Some(mut host) = self.host.take() {
            host.stop_capture().await;
            host.session.close().await;
        }
    }

    /// Handles a closed signaling connection: ends hosting now when no viewer
    /// is connected, otherwise once the last one leaves.
    pub(super) async fn mark_hosting_stale(&mut self) {
        self.host_starting = false;
        match self.host.as_mut() {
            Some(host) if !host.viewers.is_empty() => host.stale = true,
            Some(_) => self.stop_hosting().await,
            None => self.host_generation += 1,
        }
    }

    /// Gives up accepted viewers that did not join in time, stopping capture
    /// and restarting stale hosting when no viewer remains.
    pub(super) async fn prune_unjoined(&mut self) {
        let now = Instant::now();
        let Some(host) = self.host.as_mut() else {
            return;
        };
        let before = host.viewers.len();
        host.viewers
            .retain(|_, v| !join_expired(v.accepted, v.joined, now));
        if host.viewers.len() == before || !host.viewers.is_empty() {
            return;
        }
        tracing::info!("accepted viewers never joined, stopping capture");
        host.stop_capture().await;
        if host.stale {
            self.stop_hosting().await;
            self.start_hosting();
        }
    }

    /// Returns the viewers the local clipboard is sent to.
    pub(super) fn host_clipboard_targets(&self) -> Vec<DeviceId> {
        self.host
            .as_ref()
            .map(|h| {
                h.viewers
                    .iter()
                    .filter(|(_, v)| v.joined && v.clipboard)
                    .map(|(id, _)| *id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns the connected viewers as the UI shows them.
    pub(super) fn host_viewer_views(&self) -> Vec<HostViewerView> {
        self.host
            .as_ref()
            .map(|h| {
                h.viewers
                    .iter()
                    .filter(|(_, v)| v.joined)
                    .map(|(id, v)| HostViewerView {
                        id: *id,
                        name: self.name_of(*id),
                        grants: v.grants,
                        clipboard: v.clipboard,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unjoined_viewers_expire_after_the_join_window() {
        let accepted = Instant::now();
        assert!(!join_expired(accepted, false, accepted + JOIN_WINDOW / 2));
        assert!(join_expired(accepted, false, accepted + JOIN_WINDOW));
        assert!(!join_expired(accepted, true, accepted + JOIN_WINDOW * 10));
    }
}
