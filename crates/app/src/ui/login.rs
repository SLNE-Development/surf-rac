//! The sign-in and account registration screen.

use eframe::egui::{self, RichText};

use super::widgets::{self, Kind, Tone};
use super::{ClientApp, icons, theme};
use crate::runtime::Command;

/// Width of the sign-in card, in points.
const CARD_WIDTH: f32 = 380.0;

/// Draws the sign-in or registration card centred in the window.
///
/// `message` is the latest error or progress text; `busy` disables the
/// submit button while a sign-in or registration is running.
pub(super) fn show(app: &mut ClientApp, ui: &mut egui::Ui, message: Option<&str>, busy: bool) {
    let p = theme::palette(ui.ctx());
    let register = app.forms.register;
    ui.add_space(((ui.available_height() - 500.0) / 2.0).max(24.0));
    ui.vertical_centered(|ui| {
        super::main_window::logo(ui, 44.0);
        ui.add_space(4.0);
        ui.label(
            RichText::new(if register {
                "Create your account"
            } else {
                "Sign in to surf-rac"
            })
            .font(theme::bold(22.0)),
        );
        ui.label(widgets::muted(
            ui,
            if register {
                "Use the invite code you were given."
            } else {
                "Use your team account."
            },
        ));
        ui.add_space(12.0);
        ui.scope(|ui| {
            ui.set_max_width(CARD_WIDTH);
            widgets::card(ui, 24, |ui| {
                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                    ui.spacing_mut().item_spacing.y = 14.0;
                    form(app, ui, message, busy);
                });
            });
        });
        ui.add_space(12.0);
        let url = app.snap.server_url.clone();
        let width = 14.0
            + 16.0
            + widgets::text_width(ui, &url, egui::FontId::proportional(12.0))
            + widgets::text_width(ui, "Change server", theme::semibold(12.0));
        widgets::centered_row(ui, width, |ui| {
            ui.label(icons::text(icons::SERVER, 14.0).color(p.muted));
            ui.label(widgets::muted(ui, &url).size(12.0));
            if ui
                .link(RichText::new("Change server").font(theme::semibold(12.0)))
                .clicked()
            {
                app.forms.server_dialog = true;
            }
        });
    });
}

/// Draws the fields, message, submit button and the register/sign-in switch.
fn form(app: &mut ClientApp, ui: &mut egui::Ui, message: Option<&str>, busy: bool) {
    let forms = &mut app.forms;
    if forms.register {
        widgets::labeled(ui, "Invite code", |ui| {
            widgets::text_field(ui, &mut forms.invite, "", false)
        });
    }
    widgets::labeled(ui, "Username", |ui| {
        widgets::text_field(ui, &mut forms.username, "", false)
    });
    let password = widgets::labeled(ui, "Password", |ui| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            let width = ui.available_width() - 38.0;
            let response =
                widgets::sized_field(ui, &mut forms.password, "", !forms.show_password, width);
            let (icon, tip) = if forms.show_password {
                (icons::EYE_OFF, "Hide password")
            } else {
                (icons::EYE, "Show password")
            };
            if widgets::icon_button(ui, icon, tip).clicked() {
                forms.show_password = !forms.show_password;
            }
            response
        })
        .inner
    });
    let submit = password.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
    if let Some(message) = message {
        if busy {
            widgets::callout(ui, Tone::Neutral, icons::REFRESH, message);
        } else {
            widgets::callout(ui, Tone::Danger, icons::CIRCLE_ALERT, message);
        }
    }
    let label = if forms.register {
        "Create account"
    } else {
        "Sign in"
    };
    let button = widgets::btn_lg(ui, Kind::Primary, None, label);
    if widgets::full_width(ui, !busy, button).clicked() || (submit && !busy) {
        let (username, password) = (forms.username.trim().to_string(), forms.password.clone());
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
    let (lead, link) = if app.forms.register {
        ("Already have an account?", "Sign in")
    } else {
        ("Have an invite code?", "Create an account")
    };
    let width = widgets::text_width(ui, lead, egui::FontId::proportional(13.0))
        + 8.0
        + widgets::text_width(ui, link, theme::semibold(13.0));
    widgets::centered_row(ui, width, |ui| {
        ui.label(widgets::muted(ui, lead).size(13.0));
        if ui
            .link(RichText::new(link).font(theme::semibold(13.0)))
            .clicked()
        {
            app.forms.register = !app.forms.register;
        }
    });
}
