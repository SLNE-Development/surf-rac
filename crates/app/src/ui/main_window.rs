//! The main window: login and registration, then connect, devices and settings.

use eframe::egui;
use surf_rac_protocol::DeviceId;

use super::{ClientApp, Tab};
use crate::access::MIN_PASSWORD_LEN;
use crate::runtime::{Auth, Command};

/// Draws the main window.
pub(super) fn show(app: &mut ClientApp, ui: &mut egui::Ui) {
    egui::Panel::top("header").show(ui, |ui| header(app, ui));
    egui::CentralPanel::default().show(ui, |ui| match app.snap.auth.clone() {
        Auth::LoggedOut { message } => login(app, ui, message.as_deref(), false),
        Auth::Working(text) => login(app, ui, Some(&text), true),
        _ => signed_in(app, ui),
    });
}

/// Draws the header: own ID, connection state, account, banner.
fn header(app: &mut ClientApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.heading("surf-rac");
        if let Some(id) = app.snap.device_id {
            ui.separator();
            ui.label("Your ID:");
            ui.monospace(format_id(id));
            if ui.small_button("Copy").clicked() {
                ui.ctx().copy_text(id.to_string());
            }
        }
        ui.separator();
        let (text, color) = match &app.snap.auth {
            Auth::Online => ("Online", egui::Color32::from_rgb(40, 160, 70)),
            Auth::Connecting => ("Connecting...", egui::Color32::GRAY),
            Auth::Offline => (
                "Offline - reconnecting",
                egui::Color32::from_rgb(200, 120, 0),
            ),
            Auth::Replaced => ("Signed in elsewhere", egui::Color32::from_rgb(200, 60, 60)),
            Auth::LoggedOut { .. } | Auth::Working(_) => ("Not signed in", egui::Color32::GRAY),
        };
        ui.colored_label(color, text);
        if app.snap.auth == Auth::Replaced && ui.button("Reconnect").clicked() {
            app.send(Command::Reconnect);
        }
        if let Some(account) = &app.snap.account
            && !matches!(app.snap.auth, Auth::LoggedOut { .. })
        {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Log out").clicked() {
                    app.send(Command::Logout);
                }
                ui.label(account);
            });
        }
    });
    if let Some(banner) = app.snap.banner.clone() {
        ui.horizontal(|ui| {
            ui.colored_label(egui::Color32::from_rgb(200, 120, 0), banner);
            if ui.small_button("x").clicked() {
                app.send(Command::ClearBanner);
            }
        });
    }
}

/// Formats a device ID in groups of three digits.
fn format_id(id: DeviceId) -> String {
    let s = id.to_string();
    format!("{} {} {}", &s[0..3], &s[3..6], &s[6..9])
}

/// Parses a device ID typed with or without spaces.
fn parse_id(text: &str) -> Option<DeviceId> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    digits.parse().ok()
}

/// Draws the login or registration form.
fn login(app: &mut ClientApp, ui: &mut egui::Ui, message: Option<&str>, busy: bool) {
    ui.add_space(24.0);
    ui.vertical_centered(|ui| {
        ui.set_max_width(320.0);
        ui.heading(if app.forms.register {
            "Create account"
        } else {
            "Log in"
        });
        ui.label(format!("Server: {}", app.snap.server_url));
        ui.add_space(8.0);
        let forms = &mut app.forms;
        if forms.register {
            ui.add(egui::TextEdit::singleline(&mut forms.invite).hint_text("Invite code"));
        }
        ui.add(egui::TextEdit::singleline(&mut forms.username).hint_text("Username"));
        let password = ui.add(
            egui::TextEdit::singleline(&mut forms.password)
                .password(true)
                .hint_text("Password"),
        );
        let submit = password.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if let Some(message) = message {
            ui.label(message);
        }
        ui.add_enabled_ui(!busy, |ui| {
            let label = if forms.register {
                "Create account"
            } else {
                "Log in"
            };
            if ui.button(label).clicked() || (submit && !busy) {
                let (username, password) =
                    (forms.username.trim().to_string(), forms.password.clone());
                forms.password.clear();
                let command = if forms.register {
                    Command::Register {
                        invite: forms.invite.trim().to_string(),
                        username,
                        password,
                    }
                } else {
                    Command::Login { username, password }
                };
                app.commands.send(command);
            }
        });
        let switch = if app.forms.register {
            "I already have an account"
        } else {
            "I have an invite code"
        };
        if ui.link(switch).clicked() {
            app.forms.register = !app.forms.register;
        }
        ui.add_space(16.0);
        ui.collapsing("Server", |ui| server_editor(app, ui));
    });
}

/// Draws the server URL editor.
fn server_editor(app: &mut ClientApp, ui: &mut egui::Ui) {
    let url = app
        .forms
        .server_url
        .get_or_insert_with(|| app.snap.server_url.clone());
    ui.text_edit_singleline(url);
    if ui.button("Use this server").clicked() {
        let url = url.clone();
        app.send(Command::SetServer(url));
        app.forms.server_url = None;
    }
    ui.small("Changing the server signs you out and forgets this device's registration and saved passwords.");
}

/// Draws the signed-in tabs.
fn signed_in(app: &mut ClientApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.selectable_value(&mut app.tab, Tab::Connect, "Connect");
        if ui
            .selectable_value(&mut app.tab, Tab::Devices, "My devices")
            .clicked()
        {
            app.send(Command::RefreshLists);
        }
        if ui
            .selectable_value(&mut app.tab, Tab::Settings, "Settings")
            .clicked()
        {
            app.forms.settings = None;
        }
    });
    ui.separator();
    egui::ScrollArea::vertical().show(ui, |ui| match app.tab {
        Tab::Connect => connect_tab(app, ui),
        Tab::Devices => devices_tab(app, ui),
        Tab::Settings => settings_tab(app, ui),
    });
}

/// Draws the connect form and the contact list.
fn connect_tab(app: &mut ClientApp, ui: &mut egui::Ui) {
    ui.heading("Connect to a device");
    let online = app.snap.auth == Auth::Online;
    egui::Grid::new("connect").num_columns(2).show(ui, |ui| {
        ui.label("Device ID");
        ui.text_edit_singleline(&mut app.forms.connect_id);
        ui.end_row();
        ui.label("Password");
        ui.add(
            egui::TextEdit::singleline(&mut app.forms.connect_password)
                .password(true)
                .hint_text("Only for unattended access"),
        );
        ui.end_row();
    });
    ui.checkbox(&mut app.forms.connect_remember, "Remember this password");
    ui.add_enabled_ui(online, |ui| {
        if ui.button("Connect").clicked() {
            match parse_id(&app.forms.connect_id) {
                Some(host) => {
                    let password = std::mem::take(&mut app.forms.connect_password);
                    app.send(Command::Connect {
                        host,
                        password: (!password.is_empty()).then_some(password),
                        remember: app.forms.connect_remember,
                    });
                    app.forms.notice = None;
                }
                None => app.forms.notice = Some("A device ID has 9 digits.".into()),
            }
        }
    });
    if let Some(notice) = &app.forms.notice {
        ui.label(notice);
    }

    ui.add_space(12.0);
    ui.heading("Contacts");
    let contacts = app.snap.contacts.clone();
    if contacts.is_empty() {
        ui.label("No contacts yet.");
    }
    egui::Grid::new("contacts")
        .num_columns(4)
        .striped(true)
        .show(ui, |ui| {
            for c in contacts {
                let dot = if c.online { "\u{25CF}" } else { "\u{25CB}" };
                let color = if c.online {
                    egui::Color32::from_rgb(40, 160, 70)
                } else {
                    egui::Color32::GRAY
                };
                ui.colored_label(color, dot);
                ui.label(&c.alias);
                ui.monospace(format_id(c.id));
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(online && c.online, egui::Button::new("Connect"))
                        .clicked()
                    {
                        app.send(Command::Connect {
                            host: c.id,
                            password: None,
                            remember: false,
                        });
                    }
                    if ui.small_button("Rename").clicked() {
                        app.forms.contact_id = c.id.to_string();
                        app.forms.contact_alias = c.alias.clone();
                    }
                    if ui.small_button("Remove").clicked() {
                        app.send(Command::DeleteContact(c.id));
                    }
                });
                ui.end_row();
            }
        });
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut app.forms.contact_id)
                .hint_text("Device ID")
                .desired_width(110.0),
        );
        ui.add(
            egui::TextEdit::singleline(&mut app.forms.contact_alias)
                .hint_text("Name")
                .desired_width(160.0),
        );
        if ui.button("Save contact").clicked() {
            let alias = app.forms.contact_alias.trim().to_string();
            match parse_id(&app.forms.contact_id) {
                Some(id) if !alias.is_empty() => {
                    app.send(Command::PutContact { id, alias });
                    app.forms.contact_id.clear();
                    app.forms.contact_alias.clear();
                }
                _ => app.forms.notice = Some("Enter a 9-digit ID and a name.".into()),
            }
        }
    });
}

/// Draws the account's devices.
fn devices_tab(app: &mut ClientApp, ui: &mut egui::Ui) {
    ui.heading("My devices");
    let devices = app.snap.devices.clone();
    egui::Grid::new("devices")
        .num_columns(4)
        .striped(true)
        .show(ui, |ui| {
            for d in devices {
                ui.label(&d.name);
                ui.monospace(format_id(d.device_id));
                ui.label(if d.online {
                    "online".to_string()
                } else {
                    d.last_seen_at
                        .map(|t| format!("last seen {}", t.format("%Y-%m-%d %H:%M")))
                        .unwrap_or_else(|| "offline".into())
                });
                if Some(d.device_id) == app.snap.device_id {
                    ui.label("this device");
                } else {
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                d.online && app.snap.auth == Auth::Online,
                                egui::Button::new("Connect"),
                            )
                            .clicked()
                        {
                            app.send(Command::Connect {
                                host: d.device_id,
                                password: None,
                                remember: false,
                            });
                        }
                        if ui.small_button("Remove").clicked() {
                            app.send(Command::DeleteDevice(d.device_id));
                        }
                    });
                }
                ui.end_row();
            }
        });
}

/// Draws the settings.
fn settings_tab(app: &mut ClientApp, ui: &mut egui::Ui) {
    let draft = app
        .forms
        .settings
        .get_or_insert_with(|| app.snap.settings.clone());
    ui.heading("Incoming connections");
    ui.checkbox(&mut draft.allow_incoming, "Allow incoming connections");
    ui.radio_value(
        &mut draft.unattended,
        false,
        "Always ask before someone connects",
    );
    ui.radio_value(
        &mut draft.unattended,
        true,
        "Let viewers with the unattended password connect without asking",
    );
    ui.checkbox(
        &mut draft.clipboard_default,
        "Sync the clipboard in new sessions",
    );
    if ui.button("Save settings").clicked() {
        let settings = draft.clone();
        app.send(Command::SaveSettings(settings));
        app.forms.settings = None;
    }

    ui.add_space(12.0);
    ui.heading("Unattended password");
    ui.label(if app.snap.unattended_password_set {
        "A password is set."
    } else {
        "No password is set."
    });
    ui.add(
        egui::TextEdit::singleline(&mut app.forms.new_password)
            .password(true)
            .hint_text("New password"),
    );
    ui.add(
        egui::TextEdit::singleline(&mut app.forms.new_password_again)
            .password(true)
            .hint_text("Repeat password"),
    );
    ui.horizontal(|ui| {
        if ui.button("Set password").clicked() {
            let (a, b) = (&app.forms.new_password, &app.forms.new_password_again);
            app.forms.notice = if a != b {
                Some("The passwords differ.".into())
            } else if a.chars().count() < MIN_PASSWORD_LEN {
                Some(format!("Use at least {MIN_PASSWORD_LEN} characters."))
            } else {
                app.commands
                    .send(Command::SetUnattendedPassword(Some(a.clone())));
                Some("Password set.".into())
            };
            app.forms.new_password.clear();
            app.forms.new_password_again.clear();
        }
        if app.snap.unattended_password_set && ui.button("Remove password").clicked() {
            app.send(Command::SetUnattendedPassword(None));
        }
    });
    if let Some(notice) = &app.forms.notice {
        ui.label(notice);
    }

    ui.add_space(12.0);
    ui.heading("Saved passwords");
    if app.snap.saved_passwords.is_empty() {
        ui.label("None.");
    }
    for id in app.snap.saved_passwords.clone() {
        ui.horizontal(|ui| {
            ui.monospace(format_id(id));
            if ui.small_button("Forget").clicked() {
                app.send(Command::ForgetPassword(id));
            }
        });
    }

    ui.add_space(12.0);
    ui.heading("Microsoft Defender");
    ui.label("surf-rac is not signed, so Defender may block or remove it. This adds an exclusion for its folder (asks for administrator rights).");
    if ui.button("Add Defender exclusion").clicked() {
        app.forms.notice = Some(match crate::defender::add_exclusion() {
            Ok(()) => "Exclusion requested.".into(),
            Err(e) => e,
        });
    }

    ui.add_space(12.0);
    ui.collapsing("Server", |ui| server_editor(app, ui));
    ui.small(format!("surf-rac {}", env!("CARGO_PKG_VERSION")));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_grouped_and_parsed_back() {
        let id = DeviceId::new(123_456_789).unwrap();
        assert_eq!(format_id(id), "123 456 789");
        assert_eq!(parse_id("123 456 789"), Some(id));
        assert_eq!(parse_id(" 123456789 "), Some(id));
        assert_eq!(parse_id("12345"), None);
        assert_eq!(parse_id("abc"), None);
    }
}
