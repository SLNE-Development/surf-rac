//! The main window: the app bar, banners and the open tab, plus the
//! sign-in, delete-account and server dialogs while they are open.

use eframe::egui::{self, Align, Frame, Layout, Margin, RichText};
use surf_rac_protocol::DeviceId;

use super::widgets::{self, Kind, Tone};
use super::{ClientApp, Tab, connect, devices, icons, login, settings, theme};
use crate::runtime::{Command, Connection};

/// Draws the main window and its open dialogs.
pub(super) fn show(app: &mut ClientApp, ui: &mut egui::Ui) {
    main_layout(app, ui);
    login::dialog(app, ui.ctx());
    delete_account_dialog(app, ui.ctx());
    server_dialog(app, ui.ctx());
}

/// Returns the status chip text and tone for a connection state.
pub(super) fn connection_status(connection: &Connection) -> (&'static str, Tone) {
    match connection {
        Connection::Online => ("Online", Tone::Ok),
        Connection::Connecting => ("Connecting...", Tone::Neutral),
        Connection::Offline => ("Offline - reconnecting", Tone::Warn),
        Connection::UpdateRequired => ("Update required", Tone::Danger),
        Connection::Disabled => ("Device disabled", Tone::Danger),
        Connection::Replaced => ("Signed in elsewhere", Tone::Danger),
    }
}

/// Returns the banner text and tone for a connection state the client
/// stopped in, or `None` while it is connected or still trying.
pub(super) fn connection_banner(connection: &Connection) -> Option<(&'static str, Tone)> {
    match connection {
        Connection::UpdateRequired => Some((
            "Update required: this version of surf-rac is too old for the server. \
             Install the latest version to connect.",
            Tone::Danger,
        )),
        Connection::Disabled => Some((
            "This device is disabled. The server's administrator turned it off; \
             it cannot connect or be reached.",
            Tone::Danger,
        )),
        Connection::Replaced => Some((
            "This device signed in from another window. This one is disconnected.",
            Tone::Danger,
        )),
        Connection::Online | Connection::Connecting | Connection::Offline => None,
    }
}

/// Draws the app mark: the waves icon on an accent tile of `size` points.
pub(super) fn logo(ui: &mut egui::Ui, size: f32) {
    let p = theme::palette(ui.ctx());
    let (rect, _) = ui.allocate_exact_size(egui::Vec2::splat(size), egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, theme::RADIUS_CONTROL, p.accent);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        icons::WAVES,
        egui::FontId::new(size * 0.6, egui::FontFamily::Name(theme::LUCIDE.into())),
        egui::Color32::WHITE,
    );
}

/// Draws the main layout: app bar, banners and the open tab.
fn main_layout(app: &mut ClientApp, ui: &mut egui::Ui) {
    let p = theme::palette(ui.ctx());
    egui::Panel::top("app_bar")
        .frame(
            Frame::new()
                .fill(p.surface)
                .inner_margin(Margin::symmetric(20, 10)),
        )
        .show(ui, |ui| app_bar(app, ui));
    if connection_banner(&app.snap.connection).is_some() || app.snap.banner.is_some() {
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
                            Tab::Settings => settings::show(app, ui),
                        });
                });
        });
}

/// Draws the app bar: mark, section switcher, status chip and the account
/// menu or the sign-in button.
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
        if let Some(tab) = widgets::segmented(ui, &mut tab, &items) {
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
            } else if ui
                .add(widgets::btn(ui, Kind::Secondary, None, "Sign in"))
                .clicked()
            {
                app.open_sign_in();
            }
            let (text, tone) = connection_status(&app.snap.connection);
            widgets::chip(ui, tone, true, text);
        });
    });
}

/// Draws the account button with its dropdown holding Sign out and Delete account.
fn account_menu(app: &mut ClientApp, ui: &mut egui::Ui, account: &str) {
    let p = theme::palette(ui.ctx());
    let button = egui::Button::new((
        RichText::new(account)
            .font(theme::semibold(13.0))
            .color(p.text),
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
            .add(widgets::btn(
                ui,
                Kind::Ghost,
                Some(icons::LOG_OUT),
                "Sign out",
            ))
            .clicked()
        {
            app.send(Command::SignOut);
        }
        if ui
            .add(widgets::btn(ui, Kind::DangerText, None, "Delete account"))
            .clicked()
        {
            app.open_delete_account();
        }
    });
    widgets::avatar(ui, account, 28.0);
}

/// Draws the strip for a stopped connection (update required, device
/// disabled, signed in elsewhere) and the runtime's banner message.
fn banners(app: &mut ClientApp, ui: &mut egui::Ui) {
    let connection = app.snap.connection.clone();
    if let Some((text, tone)) = connection_banner(&connection) {
        widgets::banner(ui, tone, icons::TRIANGLE_ALERT, text, |ui| {
            if connection == Connection::Replaced
                && ui
                    .add(widgets::btn(ui, Kind::Secondary, None, "Reconnect"))
                    .clicked()
            {
                app.send(Command::Reconnect);
            }
        });
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

/// Shows the delete-account dialog while it is open: a warning, the
/// password field, the progress or error of the deletion and the buttons to
/// delete or cancel. It closes once the account is gone.
fn delete_account_dialog(app: &mut ClientApp, ctx: &egui::Context) {
    let Some(account) = app.snap.account.clone() else {
        app.forms.delete_account = None;
        return;
    };
    let Some(mut password) = app.forms.delete_account.take() else {
        return;
    };
    let (message, busy) = if app.forms.account_sent {
        login::account_message(&app.snap.account_task)
    } else {
        (None, false)
    };
    let message = message.map(str::to_string);
    let mut close = false;
    let response = widgets::dialog(ctx, "delete_account_dialog", "Delete account", |ui| {
        ui.spacing_mut().item_spacing.y = 12.0;
        widgets::callout(
            ui,
            Tone::Danger,
            icons::TRIANGLE_ALERT,
            &format!(
                "This deletes the account {account} and its contacts and unlinks every device. \
                 It cannot be undone. Your devices keep their IDs."
            ),
        );
        let field = widgets::labeled(ui, "Confirm with your password", |ui| {
            widgets::text_field(ui, &mut password, "", true)
        });
        let submit = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if let Some(message) = &message {
            if busy {
                widgets::callout(ui, Tone::Neutral, icons::REFRESH, message);
            } else {
                widgets::callout(ui, Tone::Danger, icons::CIRCLE_ALERT, message);
            }
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let ready = !busy && !password.is_empty();
            let button = widgets::btn(ui, Kind::Danger, None, "Delete account");
            if ui.add_enabled(ready, button).clicked() || (submit && ready) {
                app.forms.account_sent = true;
                app.commands.send(Command::DeleteAccount {
                    password: std::mem::take(&mut password),
                });
            }
            if ui
                .add(widgets::btn(ui, Kind::Secondary, None, "Cancel"))
                .clicked()
            {
                close = true;
            }
        });
    });
    if !(close || response.should_close()) {
        app.forms.delete_account = Some(password);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_status_covers_every_connection_state() {
        assert_eq!(connection_status(&Connection::Online), ("Online", Tone::Ok));
        assert_eq!(
            connection_status(&Connection::Connecting),
            ("Connecting...", Tone::Neutral)
        );
        assert_eq!(
            connection_status(&Connection::Offline),
            ("Offline - reconnecting", Tone::Warn)
        );
        assert_eq!(
            connection_status(&Connection::UpdateRequired),
            ("Update required", Tone::Danger)
        );
        assert_eq!(
            connection_status(&Connection::Disabled),
            ("Device disabled", Tone::Danger)
        );
        assert_eq!(
            connection_status(&Connection::Replaced),
            ("Signed in elsewhere", Tone::Danger)
        );
    }

    #[test]
    fn only_stopped_connections_get_a_banner() {
        for quiet in [
            Connection::Online,
            Connection::Connecting,
            Connection::Offline,
        ] {
            assert_eq!(connection_banner(&quiet), None);
        }
        let (text, tone) = connection_banner(&Connection::UpdateRequired).unwrap();
        assert!(text.starts_with("Update required"));
        assert_eq!(tone, Tone::Danger);
        let (text, tone) = connection_banner(&Connection::Disabled).unwrap();
        assert!(text.starts_with("This device is disabled"));
        assert_eq!(tone, Tone::Danger);
        let (text, tone) = connection_banner(&Connection::Replaced).unwrap();
        assert!(text.contains("another window"));
        assert_eq!(tone, Tone::Danger);
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
