//! The My devices tab: every installation linked to the signed-in account
//! with its presence.

use chrono::{DateTime, Utc};
use eframe::egui::{self, Align, Layout, RichText};
use surf_rac_protocol::MyDeviceInfo;

use super::main_window::format_id;
use super::widgets::{self, Kind, Tone};
use super::{ClientApp, icons, theme};
use crate::runtime::{Command, Connection};

/// Returns the presence text of an offline device: when it was last seen,
/// or "Offline" when that is unknown. Online devices get `None`.
pub(super) fn seen_text(online: bool, last_seen_at: Option<DateTime<Utc>>) -> Option<String> {
    if online {
        return None;
    }
    Some(
        last_seen_at
            .map(|t| format!("Last seen {}", t.format("%Y-%m-%d %H:%M")))
            .unwrap_or_else(|| "Offline".into()),
    )
}

/// Draws the My devices tab.
pub(super) fn show(app: &mut ClientApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.label(RichText::new("My devices").font(theme::bold(20.0)));
            ui.label(widgets::muted(ui, "Every computer signed in to your account.").size(13.0));
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui
                .add(widgets::btn(
                    ui,
                    Kind::Secondary,
                    Some(icons::REFRESH),
                    "Refresh",
                ))
                .clicked()
            {
                app.send(Command::RefreshLists);
            }
        });
    });
    ui.add_space(8.0);
    if app.snap.account.is_none() {
        widgets::card_frame(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::Frame::new()
                .inner_margin(egui::Margin::symmetric(16, 18))
                .show(ui, |ui| {
                    ui.label(widgets::muted(
                        ui,
                        "Sign in to an account to see the computers linked to it.",
                    ));
                    if ui
                        .add(widgets::btn(ui, Kind::Secondary, None, "Sign in"))
                        .clicked()
                    {
                        app.forms.sign_in = true;
                    }
                });
        });
        return;
    }
    let devices = app.snap.my_devices.clone();
    widgets::card_frame(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.spacing_mut().item_spacing.y = 0.0;
        if devices.is_empty() {
            egui::Frame::new()
                .inner_margin(egui::Margin::symmetric(16, 18))
                .show(ui, |ui| ui.label(widgets::muted(ui, "No devices yet.")));
        }
        for (i, d) in devices.iter().enumerate() {
            widgets::row(ui, i == 0, |ui| device_row(app, ui, d));
        }
    });
}

/// Draws one device row: icon, name and ID, presence, Connect and the actions menu.
fn device_row(app: &mut ClientApp, ui: &mut egui::Ui, d: &MyDeviceInfo) {
    let this = Some(d.device_id) == app.snap.device_id;
    widgets::icon_tile(ui, icons::MONITOR);
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        if !this {
            widgets::icon_menu(ui, icons::ELLIPSIS, "More actions", |ui| {
                if ui
                    .add(widgets::btn(ui, Kind::DangerText, None, "Remove"))
                    .clicked()
                {
                    app.send(Command::UnlinkDevice(d.device_id));
                }
            });
            let enabled = d.online && app.snap.connection == Connection::Online;
            if ui
                .add_enabled(enabled, widgets::btn(ui, Kind::Secondary, None, "Connect"))
                .clicked()
            {
                app.send(Command::Connect {
                    host: d.device_id,
                    password: None,
                    remember: false,
                });
            }
        }
        match seen_text(d.online, d.last_seen_at) {
            None => {
                widgets::chip(ui, Tone::Ok, true, "Online");
            }
            Some(text) => {
                ui.label(widgets::muted(ui, text).size(12.0));
            }
        }
        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            if this {
                widgets::name_and_id(ui, &d.name, &format_id(d.device_id));
                widgets::chip(ui, Tone::Accent, false, "This device");
            } else {
                widgets::name_and_id(ui, &d.name, &format_id(d.device_id));
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn seen_text_describes_offline_devices_only() {
        assert_eq!(seen_text(true, None), None);
        let t = Utc.with_ymd_and_hms(2026, 10, 8, 18, 42, 0).unwrap();
        assert_eq!(
            seen_text(false, Some(t)).as_deref(),
            Some("Last seen 2026-10-08 18:42")
        );
        assert_eq!(seen_text(false, None).as_deref(), Some("Offline"));
    }
}
