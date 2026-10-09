//! The Connect tab: connect by ID, this device's ID, and the contact list
//! with search and the add and rename dialogs.

use eframe::egui::{self, Align, Layout, RichText, vec2};

use super::main_window::{format_id, parse_id};
use super::widgets::{self, Kind, Tone};
use super::{ClientApp, ContactDialog, icons, theme};
use crate::runtime::{Auth, Command, ContactView};

/// Width of the "Your ID" card, in points.
const ID_CARD_WIDTH: f32 = 300.0;

/// Minimum inner height of the two top cards, so they line up.
const TOP_CARD_HEIGHT: f32 = 168.0;

/// Width of the contact search field, in points.
const SEARCH_WIDTH: f32 = 220.0;

/// Returns the contacts matching `query`: all for a blank query, by ID
/// digits when the query is only digits and spaces, otherwise by alias,
/// ignoring case.
pub(super) fn filter_contacts<'a>(
    contacts: &'a [ContactView],
    query: &str,
) -> Vec<&'a ContactView> {
    let query = query.trim();
    if query.is_empty() {
        return contacts.iter().collect();
    }
    let digits: String = query.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.chars().all(|c| c.is_ascii_digit()) {
        contacts
            .iter()
            .filter(|c| c.id.to_string().contains(&digits))
            .collect()
    } else {
        let query = query.to_lowercase();
        contacts
            .iter()
            .filter(|c| c.alias.to_lowercase().contains(&query))
            .collect()
    }
}

/// Draws the Connect tab.
pub(super) fn show(app: &mut ClientApp, ui: &mut egui::Ui) {
    let online = app.snap.auth == Auth::Online;
    let gap = 16.0;
    let left = (ui.available_width() - ID_CARD_WIDTH - gap).max(260.0);
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = gap;
        ui.allocate_ui_with_layout(vec2(left, 0.0), Layout::top_down(Align::Min), |ui| {
            ui.set_width(left);
            connect_card(app, ui, online);
        });
        ui.allocate_ui_with_layout(
            vec2(ID_CARD_WIDTH, 0.0),
            Layout::top_down(Align::Min),
            |ui| {
                ui.set_width(ID_CARD_WIDTH);
                id_card(app, ui);
            },
        );
    });
    ui.add_space(gap);
    contacts_card(app, ui, online);
    contact_dialog(app, ui.ctx());
}

/// Draws the card that connects to a typed device ID.
fn connect_card(app: &mut ClientApp, ui: &mut egui::Ui, online: bool) {
    widgets::card(ui, 20, |ui| {
        ui.set_min_height(TOP_CARD_HEIGHT);
        ui.spacing_mut().item_spacing.y = 12.0;
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.label(widgets::title("Connect to a device"));
            ui.label(
                widgets::muted(ui, "Enter the 9-digit ID shown on the other computer.").size(13.0),
            );
        });
        let mut submit = false;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            let field_width = ui.available_width() - 120.0;
            let field =
                widgets::id_field(ui, &mut app.forms.connect_id, "123 456 789", field_width);
            submit |= field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let button =
                widgets::btn(ui, Kind::Primary, None, "Connect").min_size(vec2(110.0, 40.0));
            submit |= ui.add_enabled(online, button).clicked();
        });
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            let width = ui.available_width() - 110.0;
            widgets::sized_field(
                ui,
                &mut app.forms.connect_password,
                "Password (unattended access only)",
                true,
                width,
            );
            widgets::switch(ui, &mut app.forms.connect_remember)
                .on_hover_text("Remember this password");
            ui.label(RichText::new("Remember").size(13.0));
        });
        if let Some(notice) = &app.forms.notice {
            ui.label(widgets::muted(ui, notice).size(13.0));
        }
        if submit && online {
            connect_typed(app);
        }
    });
}

/// Sends a connect request for the typed ID and password, or explains a bad ID.
fn connect_typed(app: &mut ClientApp) {
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

/// Draws the card with this device's ID and its incoming-connection state.
fn id_card(app: &mut ClientApp, ui: &mut egui::Ui) {
    widgets::card(ui, 20, |ui| {
        ui.set_min_height(TOP_CARD_HEIGHT);
        ui.spacing_mut().item_spacing.y = 10.0;
        ui.label(widgets::muted(ui, "YOUR ID").font(theme::bold(11.0)));
        ui.horizontal(|ui| {
            let id = app.snap.device_id.map(format_id);
            ui.label(
                RichText::new(id.as_deref().unwrap_or("--- --- ---")).font(widgets::id_font(26.0)),
            );
            if let Some(id) = app.snap.device_id {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if widgets::icon_button(ui, icons::COPY, "Copy ID").clicked() {
                        ui.ctx().copy_text(id.to_string());
                    }
                });
            }
        });
        widgets::hairline(ui);
        let incoming = if app.snap.settings.allow_incoming {
            (Tone::Ok, "Allowed")
        } else {
            (Tone::Neutral, "Off")
        };
        let unattended = if app.snap.unattended_password_set {
            (Tone::Neutral, "Password set")
        } else {
            (Tone::Neutral, "No password")
        };
        for (label, (tone, text)) in [("Incoming", incoming), ("Unattended", unattended)] {
            ui.horizontal(|ui| {
                ui.label(widgets::muted(ui, label).size(13.0));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    widgets::chip(ui, tone, false, text);
                });
            });
        }
    });
}

/// Draws the contacts card: header with count, search and Add contact, then the rows.
fn contacts_card(app: &mut ClientApp, ui: &mut egui::Ui, online: bool) {
    let contacts = app.snap.contacts.clone();
    widgets::card_frame(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.spacing_mut().item_spacing.y = 0.0;
        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(16, 12))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.set_min_height(40.0);
                    ui.label(widgets::title("Contacts"));
                    widgets::chip(ui, Tone::Neutral, false, &contacts.len().to_string());
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add(widgets::btn(
                                ui,
                                Kind::Secondary,
                                Some(icons::PLUS),
                                "Add contact",
                            ))
                            .clicked()
                        {
                            app.forms.contact_dialog = Some(ContactDialog::default());
                        }
                        widgets::sized_field(
                            ui,
                            &mut app.forms.contact_search,
                            "Search contacts",
                            false,
                            SEARCH_WIDTH,
                        );
                    });
                });
            });
        widgets::hairline(ui);
        let shown = filter_contacts(&contacts, &app.forms.contact_search);
        if shown.is_empty() {
            let text = if contacts.is_empty() {
                "No contacts yet. Add one to connect with a single click."
            } else {
                "No contacts match."
            };
            egui::Frame::new()
                .inner_margin(egui::Margin::symmetric(16, 18))
                .show(ui, |ui| ui.label(widgets::muted(ui, text)));
        }
        for (i, c) in shown.into_iter().enumerate() {
            widgets::row(ui, i == 0, |ui| contact_row(app, ui, c, online));
        }
    });
}

/// Draws one contact row: avatar, name and ID, presence, Connect and the actions menu.
fn contact_row(app: &mut ClientApp, ui: &mut egui::Ui, c: &ContactView, online: bool) {
    widgets::avatar(ui, &c.alias, 36.0);
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        widgets::icon_menu(ui, icons::ELLIPSIS, "More actions", |ui| {
            if ui
                .add(widgets::btn(ui, Kind::Ghost, None, "Rename"))
                .clicked()
            {
                app.forms.contact_dialog = Some(ContactDialog {
                    rename: true,
                    id: c.id.to_string(),
                    alias: c.alias.clone(),
                    error: None,
                });
            }
            if ui
                .add(widgets::btn(ui, Kind::DangerText, None, "Remove"))
                .clicked()
            {
                app.send(Command::DeleteContact(c.id));
            }
        });
        let button = widgets::btn(ui, Kind::Secondary, None, "Connect");
        if ui.add_enabled(online && c.online, button).clicked() {
            app.send(Command::Connect {
                host: c.id,
                password: None,
                remember: false,
            });
        }
        if c.online {
            widgets::chip(ui, Tone::Ok, true, "Online");
        } else {
            widgets::chip(ui, Tone::Neutral, true, "Offline");
        }
        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            widgets::name_and_id(ui, &c.alias, &format_id(c.id));
        });
    });
}

/// Shows the add or rename contact dialog while it is open.
fn contact_dialog(app: &mut ClientApp, ctx: &egui::Context) {
    let Some(mut dialog) = app.forms.contact_dialog.take() else {
        return;
    };
    let title = if dialog.rename {
        "Rename contact"
    } else {
        "Add contact"
    };
    let mut close = false;
    let response = widgets::dialog(ctx, "contact_dialog", title, |ui| {
        ui.spacing_mut().item_spacing.y = 12.0;
        widgets::labeled(ui, "Device ID", |ui| {
            ui.add_enabled_ui(!dialog.rename, |ui| {
                widgets::text_field(ui, &mut dialog.id, "123 456 789", false)
            })
        });
        widgets::labeled(ui, "Name", |ui| {
            widgets::text_field(ui, &mut dialog.alias, "", false)
        });
        if let Some(error) = &dialog.error {
            widgets::callout(ui, Tone::Danger, icons::CIRCLE_ALERT, error);
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui
                .add(widgets::btn(ui, Kind::Primary, None, "Save"))
                .clicked()
            {
                let alias = dialog.alias.trim().to_string();
                match parse_id(&dialog.id) {
                    Some(id) if !alias.is_empty() => {
                        app.send(Command::PutContact { id, alias });
                        close = true;
                    }
                    _ => dialog.error = Some("Enter a 9-digit ID and a name.".into()),
                }
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
        app.forms.contact_dialog = Some(dialog);
    }
}

#[cfg(test)]
mod tests {
    use surf_rac_protocol::DeviceId;

    use super::*;

    fn contact(id: u32, alias: &str) -> ContactView {
        ContactView {
            id: DeviceId::new(id).unwrap(),
            alias: alias.into(),
            online: true,
        }
    }

    fn contacts() -> Vec<ContactView> {
        vec![
            contact(204_551_870, "Build server"),
            contact(731_002_448, "Design laptop"),
        ]
    }

    fn aliases(found: Vec<&ContactView>) -> Vec<&str> {
        found.into_iter().map(|c| c.alias.as_str()).collect()
    }

    #[test]
    fn blank_query_returns_every_contact() {
        let all = contacts();
        assert_eq!(filter_contacts(&all, "").len(), 2);
        assert_eq!(filter_contacts(&all, "   ").len(), 2);
    }

    #[test]
    fn aliases_match_ignoring_case() {
        let all = contacts();
        assert_eq!(aliases(filter_contacts(&all, "build")), ["Build server"]);
        assert_eq!(aliases(filter_contacts(&all, "LAPTOP")), ["Design laptop"]);
    }

    #[test]
    fn digits_match_ids_with_or_without_spaces() {
        let all = contacts();
        assert_eq!(aliases(filter_contacts(&all, "204 551")), ["Build server"]);
        assert_eq!(aliases(filter_contacts(&all, "204551")), ["Build server"]);
        assert_eq!(aliases(filter_contacts(&all, "002")), ["Design laptop"]);
    }

    #[test]
    fn unknown_query_matches_nothing() {
        assert!(filter_contacts(&contacts(), "zzz").is_empty());
    }
}
