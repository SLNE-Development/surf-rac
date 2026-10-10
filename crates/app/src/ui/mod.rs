//! The egui user interface: the main window plus one native window per
//! prompt, the host's connections and each viewer session.

mod connect;
mod devices;
mod icons;
mod login;
mod main_window;
mod sessions;
mod settings;
mod theme;
mod widgets;

use std::collections::HashMap;

use eframe::egui;

use crate::runtime::{Command, Commands, Runtime, Snapshot};
use crate::store::Settings;
use crate::viewmap;

/// Which tab of the main window is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    /// Connect by ID and contacts.
    Connect,
    /// The signed-in account's devices.
    Devices,
    /// Settings.
    Settings,
}

/// Text fields and drafts of the main window.
#[derive(Default)]
struct Forms {
    /// Whether the sign-in dialog is open.
    sign_in: bool,
    /// Sign-in or registration username.
    username: String,
    /// Sign-in or registration password.
    password: String,
    /// Whether the sign-in dialog shows account creation.
    register: bool,
    /// Why the typed username or password was refused before sending, if it was.
    account_error: Option<&'static str>,
    /// Whether an account dialog sent its command, so the runtime's account
    /// progress and errors belong to it.
    account_sent: bool,
    /// The password typed to confirm account deletion; `Some` while the
    /// dialog is open.
    delete_account: Option<String>,
    /// Whether the sign-in password is shown in clear text.
    show_password: bool,
    /// Whether the server dialog is open.
    server_dialog: bool,
    /// Host ID to connect to.
    connect_id: String,
    /// Password typed for the connection.
    connect_password: String,
    /// Whether to save the typed password.
    connect_remember: bool,
    /// Text filtering the contact list.
    contact_search: String,
    /// The open add or rename contact dialog.
    contact_dialog: Option<ContactDialog>,
    /// Server URL being edited.
    server_url: Option<String>,
    /// Settings being edited.
    settings: Option<Settings>,
    /// New unattended password.
    new_password: String,
    /// New unattended password, repeated.
    new_password_again: String,
    /// A local message, such as a validation error.
    notice: Option<String>,
}

/// Fields of the add or rename contact dialog.
#[derive(Debug, Default)]
struct ContactDialog {
    /// Whether an existing contact is renamed; its ID is then fixed.
    rename: bool,
    /// The contact's device ID as typed.
    id: String,
    /// The contact's name as typed.
    alias: String,
    /// Why the last save was refused.
    error: Option<String>,
}

/// Drawing state of one viewer window.
#[derive(Default)]
struct ViewerUi {
    /// The frame texture.
    texture: Option<egui::TextureHandle>,
    /// Sequence number of the frame in the texture.
    seq: u64,
    /// Where the picture was drawn last, in window points.
    picture: Option<viewmap::Rect>,
    /// Whether the window has the keyboard focus.
    focused: bool,
}

/// The eframe application.
pub struct ClientApp {
    /// The runtime; taken on exit.
    runtime: Option<Runtime>,
    /// Command sender.
    commands: Commands,
    /// The snapshot drawn this frame.
    snap: Snapshot,
    /// Open tab.
    tab: Tab,
    /// Text fields.
    forms: Forms,
    /// Viewer windows by session.
    viewers: HashMap<u64, ViewerUi>,
    /// Whether closing the connections window waits for confirmation.
    confirm_disconnect_all: bool,
    /// When each pending request's prompt was first shown, by session ID.
    prompt_shown: HashMap<String, std::time::Instant>,
    /// The keyboard hook, when it could be installed.
    _hook: Option<crate::keyhook::KeyHook>,
}

impl ClientApp {
    /// Creates the app around a started runtime: installs the theme on `ctx`
    /// and the keyboard hook on this thread.
    pub fn new(ctx: &egui::Context, runtime: Runtime) -> ClientApp {
        theme::install(ctx);
        let hook = match crate::keyhook::KeyHook::install() {
            Ok(hook) => Some(hook),
            Err(e) => {
                tracing::warn!(error = %e, "keyboard capture unavailable");
                None
            }
        };
        ClientApp {
            commands: runtime.commands(),
            snap: runtime.snapshot(),
            runtime: Some(runtime),
            tab: Tab::Connect,
            forms: Forms::default(),
            viewers: HashMap::new(),
            confirm_disconnect_all: false,
            prompt_shown: HashMap::new(),
            _hook: hook,
        }
    }

    /// Sends a command to the runtime.
    fn send(&self, command: Command) {
        self.commands.send(command);
    }

    /// Opens the sign-in dialog with no message from an earlier attempt.
    fn open_sign_in(&mut self) {
        self.forms.sign_in = true;
        self.forms.account_error = None;
        self.forms.account_sent = false;
    }

    /// Opens the delete-account dialog with an empty password.
    fn open_delete_account(&mut self) {
        self.forms.delete_account = Some(String::new());
        self.forms.account_sent = false;
    }

    /// Routes captured keys to the focused viewer window whose host grants the keyboard.
    fn update_key_target(&self) {
        let target = key_target(&self.snap.viewers, |session| {
            self.viewers.get(&session).is_some_and(|ui| ui.focused)
        });
        crate::keyhook::set_target(target.map(|session| {
            let commands = self.commands.clone();
            let sink: crate::keyhook::Sink = std::sync::Arc::new(move |message| {
                commands.send(Command::ViewerSend { session, message });
            });
            (session, sink)
        }));
    }
}

/// Returns the session that receives captured keys: a connected session
/// whose window is focused and whose host grants the keyboard without a lock.
fn key_target(views: &[crate::runtime::ViewerView], focused: impl Fn(u64) -> bool) -> Option<u64> {
    views
        .iter()
        .find(|v| {
            v.status == crate::runtime::ViewerStatus::Connected
                && v.input.keyboard
                && !v.input.locked
                && focused(v.session)
        })
        .map(|v| v.session)
}

impl eframe::App for ClientApp {
    /// Draws every window from the latest snapshot.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if let Some(runtime) = &self.runtime {
            self.snap = runtime.snapshot();
        }
        let ctx = ui.ctx().clone();
        main_window::show(self, ui);
        self.show_prompts(&ctx);
        self.show_connections(&ctx);
        self.show_viewers(&ctx);
        self.update_key_target();
    }

    /// Hangs up every session and stops the runtime.
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        crate::keyhook::set_target(None);
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use surf_rac_protocol::DeviceId;
    use surf_rac_protocol::data::InputState;

    use super::*;
    use crate::runtime::{ViewerStatus, ViewerView};

    fn view(session: u64, status: ViewerStatus, keyboard: bool, locked: bool) -> ViewerView {
        ViewerView {
            session,
            host: DeviceId::new(123_456_789).unwrap(),
            name: "host".into(),
            status,
            frame: Arc::new(Mutex::new(None)),
            screen: None,
            input: InputState {
                pointer: true,
                keyboard,
                locked,
                follow: false,
                pointing: true,
            },
            clipboard: false,
            offer_forget: false,
            paused: false,
        }
    }

    #[test]
    fn keys_go_only_to_a_focused_connected_session_with_keyboard() {
        let focused = |s: u64| s != 9;
        let ended = ViewerStatus::Ended("over".into());
        assert_eq!(
            key_target(&[view(1, ViewerStatus::Connected, true, false)], focused),
            Some(1)
        );
        assert_eq!(key_target(&[view(1, ended, true, false)], focused), None);
        assert_eq!(
            key_target(&[view(1, ViewerStatus::Connected, false, false)], focused),
            None
        );
        assert_eq!(
            key_target(&[view(1, ViewerStatus::Connected, true, true)], focused),
            None
        );
        assert_eq!(
            key_target(&[view(9, ViewerStatus::Connected, true, false)], focused),
            None
        );
    }
}
