//! The main window: the signed-out screen, or the app bar, banner and the
//! open tab when signed in.

use eframe::egui::{self, Align, Frame, Layout, Margin, RichText};
use surf_rac_protocol::DeviceId;

use super::widgets::{self, Kind, Tone};
use super::{ClientApp, Tab, connect, devices, icons, login, theme};
use crate::access::MIN_PASSWORD_LEN;
use crate::runtime::{Auth, Command};

/// Draws the main window.
pub(super) fn show(app: &mut ClientApp, ui: &mut egui::Ui) {
    let p = theme::palette(ui.ctx());
    match app.snap.auth.clone() {
        Auth::LoggedOut { message } => {
            egui::CentralPanel::no_frame()
                .frame(Frame::new().fill(p.bg))
                .show(ui, |ui| login::show(app, ui, message.as_deref(), false));
        }
        Auth::Working(text) => {
            egui::CentralPanel::no_frame()
                .frame(Frame::new().fill(p.bg))
                .show(ui, |ui| login::show(app, ui, Some(&text), true));
        }
        _ => signed_in(app, ui),
    }
    server_dialog(app, ui.ctx());
}

/// Returns the status chip text and tone for a sign-in state.
pub(super) fn status(auth: &Auth) -> (&'static str, Tone) {
    match auth {
        Auth::Online => ("Online", Tone::Ok),
        Auth::Connecting => ("Connecting...", Tone::Neutral),
        Auth::Offline => ("Offline - reconnecting", Tone::Warn),
        Auth::Replaced => ("Signed in elsewhere", Tone::Danger),
        Auth::LoggedOut { .. } | Auth::Working(_) => ("Not signed in", Tone::Neutral),
    }
}

/// Draws the app mark: the waves icon on an accent tile of `size` points.
pub(super) fn logo(ui: &mut egui::Ui, size: f32) {
    let p = theme::palette(ui.ctx());
    let (rect, _) = ui.allocate_exact_size(egui::Vec2::splat(size), egui::Sense::hover());
    ui.painter().rect_filled(rect, theme::RADIUS_CONTROL, p.accent);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        icons::WAVES,
        egui::FontId::new(size * 0.6, egui::FontFamily::Name(theme::LUCIDE.into())),
        egui::Color32::WHITE,
    );
}

/// Draws the signed-in layout: app bar, banners and the open tab.
fn signed_in(app: &mut ClientApp, ui: &mut egui::Ui) {
    let p = theme::palette(ui.ctx());
    egui::Panel::top("app_bar")
        .frame(
            Frame::new()
                .fill(p.surface)
                .inner_margin(Margin::symmetric(20, 10)),
        )
        .show(ui, |ui| app_bar(app, ui));
    if app.snap.auth == Auth::Replaced || app.snap.banner.is_some() {
        egui::Panel::top("banners")
            .frame(Frame::NONE)
            .show_separator_line(false)
            .show(ui, |ui| banners(app, ui));
    }
    egui::CentralPanel::no_frame()
        .frame(Frame::new().fill(p.bg))
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink(false)
                .show(ui, |ui| {
                    Frame::new()
                        .inner_margin(Margin::symmetric(24, 20))
                        .show(ui, |ui| match app.tab {
                            Tab::Connect => connect::show(app, ui),
                            Tab::Devices => devices::show(app, ui),
                            Tab::Settings => settings_tab(app, ui),
                        });
                });
        });
}

/// Draws the app bar: mark, section switcher, status chip and account menu.
fn app_bar(app: &mut ClientApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.set_min_height(36.0);
        logo(ui, 28.0);
        ui.label(RichText::new("surf-rac").font(theme::bold(15.0)));
        ui.add_space(16.0);
        let mut tab = app.tab;
        let items = [
            (Tab::Connect, "Connect"),
            (Tab::Devices, "My devices"),
            (Tab::Settings, "Settings"),
        ];
        if widgets::segmented(ui, &mut tab, &items) {
            app.tab = tab;
            match tab {
                Tab::Devices => app.send(Command::RefreshLists),
                Tab::Settings => app.forms.settings = None,
                Tab::Connect => {}
            }
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if let Some(account) = app.snap.account.clone() {
                account_menu(app, ui, &account);
            }
            let (text, tone) = status(&app.snap.auth);
            widgets::chip(ui, tone, true, text);
        });
    });
}

/// Draws the account button with its dropdown holding Log out.
fn account_menu(app: &mut ClientApp, ui: &mut egui::Ui, account: &str) {
    let p = theme::palette(ui.ctx());
    let button = egui::Button::new((
        RichText::new(account).font(theme::semibold(13.0)).color(p.text),
        icons::text(icons::CHEVRON_DOWN, 14.0).color(p.muted),
    ))
    .frame_when_inactive(false)
    .corner_radius(theme::RADIUS_CONTROL)
    .min_size(egui::vec2(0.0, 34.0));
    egui::containers::menu::MenuButton::from_button(button).ui(ui, |ui| {
        ui.set_min_width(180.0);
        ui.label(widgets::muted(ui, format!("Signed in as {account}")).size(12.0));
        ui.separator();
        if ui
            .add(widgets::btn(ui, Kind::Ghost, Some(icons::LOG_OUT), "Log out"))
            .clicked()
        {
            app.send(Command::Logout);
        }
    });
    widgets::avatar(ui, account, 28.0);
}

/// Draws the "signed in elsewhere" strip and the runtime's banner message.
fn banners(app: &mut ClientApp, ui: &mut egui::Ui) {
    if app.snap.auth == Auth::Replaced {
        widgets::banner(
            ui,
            Tone::Danger,
            icons::TRIANGLE_ALERT,
            "This device signed in from another window. This one is disconnected.",
            |ui| {
                if ui
                    .add(widgets::btn(ui, Kind::Secondary, None, "Reconnect"))
                    .clicked()
                {
                    app.send(Command::Reconnect);
                }
            },
        );
    }
    if let Some(banner) = app.snap.banner.clone() {
        widgets::banner(ui, Tone::Warn, icons::TRIANGLE_ALERT, &banner, |ui| {
            if widgets::icon_button(ui, icons::X, "Dismiss").clicked() {
                app.send(Command::ClearBanner);
            }
        });
    }
}

/// Formats a device ID in groups of three digits.
pub(super) fn format_id(id: DeviceId) -> String {
    let s = id.to_string();
    format!("{} {} {}", &s[0..3], &s[3..6], &s[6..9])
}

/// Parses a device ID typed with or without spaces.
pub(super) fn parse_id(text: &str) -> Option<DeviceId> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    digits.parse().ok()
}

/// Shows the server dialog while it is open: the URL field, a warning and
/// the buttons to apply or cancel.
fn server_dialog(app: &mut ClientApp, ctx: &egui::Context) {
    if !app.forms.server_dialog {
        return;
    }
    let mut close = false;
    let response = widgets::dialog(ctx, "server_dialog", "Change server", |ui| {
        let url = app
            .forms
            .server_url
            .get_or_insert_with(|| app.snap.server_url.clone());
        widgets::labeled(ui, "Server URL", |ui| {
            widgets::text_field(ui, url, "https://", false)
        });
        widgets::callout(
            ui,
            Tone::Warn,
            icons::TRIANGLE_ALERT,
            "Changing the server signs you out and forgets this device's registration and saved passwords.",
        );
        ui.add_space(4.0);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui
                .add(widgets::btn(ui, Kind::Primary, None, "Use this server"))
                .clicked()
            {
                let url = url.clone();
                app.commands.send(Command::SetServer(url));
                close = true;
            }
            if ui
                .add(widgets::btn(ui, Kind::Secondary, None, "Cancel"))
                .clicked()
            {
                close = true;
            }
        });
    });
    if close || response.should_close() {
        app.forms.server_dialog = false;
        app.forms.server_url = None;
    }
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
    if ui.button("Change server").clicked() {
        app.forms.server_dialog = true;
    }
    ui.small(format!("surf-rac {}", env!("CARGO_PKG_VERSION")));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_covers_every_auth() {
        assert_eq!(status(&Auth::Online), ("Online", Tone::Ok));
        assert_eq!(status(&Auth::Connecting), ("Connecting...", Tone::Neutral));
        assert_eq!(status(&Auth::Offline), ("Offline - reconnecting", Tone::Warn));
        assert_eq!(status(&Auth::Replaced), ("Signed in elsewhere", Tone::Danger));
        let out = Auth::LoggedOut { message: None };
        assert_eq!(status(&out), ("Not signed in", Tone::Neutral));
        assert_eq!(
            status(&Auth::Working("Signing in".into())),
            ("Not signed in", Tone::Neutral)
        );
    }

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
