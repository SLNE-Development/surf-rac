//! The egui user interface: the main window plus one native window per
//! prompt, the host's connections and each viewer session.

mod main_window;
mod sessions;

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
    /// The account's devices.
    Devices,
    /// Settings.
    Settings,
}

/// Text fields and drafts of the main window.
#[derive(Default)]
struct Forms {
    /// Login or registration username.
    username: String,
    /// Login or registration password.
    password: String,
    /// Registration invite code.
    invite: String,
    /// Whether the login screen shows registration.
    register: bool,
    /// Host ID to connect to.
    connect_id: String,
    /// Password typed for the connection.
    connect_password: String,
    /// Whether to save the typed password.
    connect_remember: bool,
    /// ID of a contact to add or rename.
    contact_id: String,
    /// Alias of a contact to add or rename.
    contact_alias: String,
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
    /// The keyboard hook, when it could be installed.
    _hook: Option<crate::keyhook::KeyHook>,
}

impl ClientApp {
    /// Creates the app around a started runtime; installs the keyboard hook on this thread.
    pub fn new(runtime: Runtime) -> ClientApp {
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
            _hook: hook,
        }
    }

    /// Sends a command to the runtime.
    fn send(&self, command: Command) {
        self.commands.send(command);
    }

    /// Routes captured keys to the focused viewer window whose host grants the keyboard.
    fn update_key_target(&self) {
        let target = self.snap.viewers.iter().find(|v| {
            v.input.keyboard
                && !v.input.locked
                && self.viewers.get(&v.session).is_some_and(|ui| ui.focused)
        });
        crate::keyhook::set_target(target.map(|v| {
            let commands = self.commands.clone();
            let session = v.session;
            let sink: crate::keyhook::Sink = std::sync::Arc::new(move |message| {
                commands.send(Command::ViewerSend { session, message });
            });
            (session, sink)
        }));
    }
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
