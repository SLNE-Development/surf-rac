//! The Settings tab: the account, incoming connections, the unattended
//! password, saved passwords, updates, the Defender exclusion and the server.

use eframe::egui::{self, Align, Frame, Layout, Margin, RichText, Ui};

use super::main_window::format_id;
use super::widgets::{self, Kind, Tone};
use super::{ClientApp, icons};
use crate::access::MIN_PASSWORD_LEN;
use crate::runtime::Command;
use crate::store::Settings;
use crate::update::{UpdateState, status_text};

/// Width of the settings column, in points.
const COLUMN_WIDTH: f32 = 680.0;

/// Returns whether the draft differs from the saved settings in a field the
/// Incoming connections card edits.
pub(super) fn dirty(draft: &Settings, saved: &Settings) -> bool {
    draft.allow_incoming != saved.allow_incoming
        || draft.unattended != saved.unattended
        || draft.clipboard_default != saved.clipboard_default
}

/// Draws the Settings tab as a centred column of cards.
pub(super) fn show(app: &mut ClientApp, ui: &mut Ui) {
    let width = COLUMN_WIDTH.min(ui.available_width());
    ui.horizontal(|ui| {
        ui.add_space(((ui.available_width() - width) / 2.0).max(0.0));
        ui.vertical(|ui| {
            ui.set_width(width);
            ui.spacing_mut().item_spacing.y = 16.0;
            account_card(app, ui);
            incoming_card(app, ui);
            password_card(app, ui);
            saved_passwords_card(app, ui);
            updates_card(app, ui);
            advanced_card(app, ui);
        });
    });
}

/// Draws a card with a header row and the body added by `add`.
fn section(ui: &mut Ui, title: &str, right: impl FnOnce(&mut Ui), add: impl FnOnce(&mut Ui)) {
    widgets::card_frame(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.spacing_mut().item_spacing.y = 0.0;
        widgets::card_header(ui, title, right);
        add(ui);
    });
}

/// Draws one setting: title and description on the left, `control` on the right.
fn setting_row(ui: &mut Ui, first: bool, title: &str, desc: &str, control: impl FnOnce(&mut Ui)) {
    let title = RichText::new(title).font(super::theme::semibold(14.0));
    rich_setting_row(ui, first, title, desc, control);
}

/// Draws one setting row like [`setting_row`] with an already styled title.
fn rich_setting_row(
    ui: &mut Ui,
    first: bool,
    title: RichText,
    desc: &str,
    control: impl FnOnce(&mut Ui),
) {
    if !first {
        widgets::hairline(ui);
    }
    Frame::new()
        .inner_margin(Margin::symmetric(18, 14))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    control(ui);
                    ui.add_space(12.0);
                    ui.with_layout(Layout::top_down(Align::Min), |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.label(title);
                        if !desc.is_empty() {
                            ui.add(egui::Label::new(widgets::muted(ui, desc).size(13.0)).wrap());
                        }
                    });
                });
            });
        });
}

/// Draws the Account card: Sign in while signed out; otherwise the
/// username with Sign out, and Delete account, which asks for the password.
fn account_card(app: &mut ClientApp, ui: &mut Ui) {
    let account = app.snap.account.clone();
    section(
        ui,
        "Account",
        |ui| {
            if account.is_none() {
                widgets::chip(ui, Tone::Neutral, false, "Not signed in");
            }
        },
        |ui| match &account {
            None => setting_row(
                ui,
                true,
                "No account",
                "Optional. Sign in to sync contacts and see your devices.",
                |ui| {
                    if ui
                        .add(widgets::btn(ui, Kind::Secondary, None, "Sign in"))
                        .clicked()
                    {
                        app.open_sign_in();
                    }
                },
            ),
            Some(username) => {
                setting_row(
                    ui,
                    true,
                    username,
                    "Signed in. Your contacts and devices sync with this account.",
                    |ui| {
                        if ui
                            .add(widgets::btn(
                                ui,
                                Kind::Secondary,
                                Some(icons::LOG_OUT),
                                "Sign out",
                            ))
                            .clicked()
                        {
                            app.send(Command::SignOut);
                        }
                    },
                );
                setting_row(
                    ui,
                    false,
                    "Delete account",
                    "Deletes the account and its contacts and unlinks every device. \
                     Asks for your password.",
                    |ui| {
                        if ui
                            .add(widgets::btn(
                                ui,
                                Kind::DangerText,
                                None,
                                "Delete account\u{2026}",
                            ))
                            .clicked()
                        {
                            app.open_delete_account();
                        }
                    },
                );
            }
        },
    );
}

/// Draws the Incoming connections card, editing a draft that is saved or discarded.
fn incoming_card(app: &mut ClientApp, ui: &mut Ui) {
    let saved = app.snap.settings.clone();
    let mut draft = app.forms.settings.take().unwrap_or_else(|| saved.clone());
    let mut save = false;
    let mut discard = false;
    section(
        ui,
        "Incoming connections",
        |_| {},
        |ui| {
            setting_row(
                ui,
                true,
                "Allow incoming connections",
                "Others on your team can request to view this computer.",
                |ui| {
                    widgets::switch(ui, &mut draft.allow_incoming);
                },
            );
            widgets::hairline(ui);
            Frame::new()
                .inner_margin(Margin::symmetric(18, 14))
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 10.0;
                    ui.label(
                        RichText::new("When someone connects").font(super::theme::semibold(14.0)),
                    );
                    ui.columns(2, |cols| {
                        if widgets::option_card(
                            &mut cols[0],
                            !draft.unattended,
                            "Always ask",
                            "You accept or deny every request.",
                        )
                        .clicked()
                        {
                            draft.unattended = false;
                        }
                        if widgets::option_card(
                            &mut cols[1],
                            draft.unattended,
                            "Unattended with password",
                            "Viewers with the password connect without asking.",
                        )
                        .clicked()
                        {
                            draft.unattended = true;
                        }
                    });
                });
            setting_row(
                ui,
                false,
                "Sync clipboard in new sessions",
                "Copy and paste between computers by default. Can be changed per session.",
                |ui| {
                    widgets::switch(ui, &mut draft.clipboard_default);
                },
            );
            if dirty(&draft, &saved) {
                let p = super::theme::palette(ui.ctx());
                widgets::hairline(ui);
                Frame::new()
                    .fill(p.surface2)
                    .inner_margin(Margin::symmetric(18, 10))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(widgets::muted(ui, "Unsaved changes").size(13.0));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                save = ui
                                    .add(widgets::btn(ui, Kind::Primary, None, "Save changes"))
                                    .clicked();
                                discard = ui
                                    .add(widgets::btn(ui, Kind::Ghost, None, "Discard"))
                                    .clicked();
                            });
                        });
                    });
            }
        },
    );
    if save {
        app.send(Command::SaveSettings(draft.clone()));
    }
    if !discard {
        app.forms.settings = Some(draft);
    }
}

/// Draws the Unattended password card: status, the two fields and the actions.
fn password_card(app: &mut ClientApp, ui: &mut Ui) {
    let set = app.snap.unattended_password_set;
    section(
        ui,
        "Unattended password",
        |ui| {
            if set {
                widgets::chip(ui, Tone::Ok, false, "Password set");
            } else {
                widgets::chip(ui, Tone::Neutral, false, "No password");
            }
        },
        |ui| {
            Frame::new()
                .inner_margin(Margin::symmetric(18, 16))
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 12.0;
                    let forms = &mut app.forms;
                    ui.columns(2, |cols| {
                        widgets::labeled(&mut cols[0], "New password", |ui| {
                            widgets::text_field(ui, &mut forms.new_password, "", true)
                        });
                        widgets::labeled(&mut cols[1], "Repeat password", |ui| {
                            widgets::text_field(ui, &mut forms.new_password_again, "", true)
                        });
                    });
                    ui.horizontal(|ui| {
                        ui.label(
                            widgets::muted(ui, format!("At least {MIN_PASSWORD_LEN} characters."))
                                .size(13.0),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui
                                .add(widgets::btn(ui, Kind::Secondary, None, "Set password"))
                                .clicked()
                            {
                                set_password(app);
                            }
                            if set
                                && ui
                                    .add(widgets::btn(
                                        ui,
                                        Kind::DangerText,
                                        None,
                                        "Remove password",
                                    ))
                                    .clicked()
                            {
                                app.send(Command::SetUnattendedPassword(None));
                            }
                        });
                    });
                    if let Some(notice) = &app.forms.notice {
                        ui.label(widgets::muted(ui, notice).size(13.0));
                    }
                });
        },
    );
}

/// Validates the two typed passwords and sets the unattended password when they agree.
fn set_password(app: &mut ClientApp) {
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

/// Draws the passwords this computer remembers for other devices.
fn saved_passwords_card(app: &mut ClientApp, ui: &mut Ui) {
    let saved = app.snap.saved_passwords.clone();
    section(
        ui,
        "Saved passwords",
        |_| {},
        |ui| {
            if saved.is_empty() {
                Frame::new()
                    .inner_margin(Margin::symmetric(18, 14))
                    .show(ui, |ui| ui.label(widgets::muted(ui, "No saved passwords.")));
            }
            for (i, id) in saved.into_iter().enumerate() {
                let alias = app
                    .snap
                    .contacts
                    .iter()
                    .find(|c| c.id == id)
                    .map(|c| c.alias.clone())
                    .unwrap_or_default();
                let title = RichText::new(format_id(id)).font(widgets::id_font(14.0));
                rich_setting_row(ui, i == 0, title, &alias, |ui| {
                    if ui
                        .add(widgets::btn(ui, Kind::Ghost, None, "Forget"))
                        .clicked()
                    {
                        app.send(Command::ForgetPassword(id));
                    }
                });
            }
        },
    );
}

/// Draws the Updates card: the running version with the updater's status,
/// and Restart to update once an update is ready, otherwise Check for updates.
fn updates_card(app: &mut ClientApp, ui: &mut Ui) {
    let state = app.update.clone();
    let title = format!("surf-rac {}", env!("CARGO_PKG_VERSION"));
    section(
        ui,
        "Updates",
        |_| {},
        |ui| {
            setting_row(ui, true, &title, &status_text(&state), |ui| {
                if matches!(state, UpdateState::Ready(_)) {
                    if ui
                        .add(widgets::btn(ui, Kind::Primary, None, "Restart to update"))
                        .clicked()
                    {
                        app.restart_to_update(ui.ctx());
                    }
                } else {
                    let busy = matches!(state, UpdateState::Checking | UpdateState::Downloading(_));
                    if ui
                        .add_enabled(
                            !busy,
                            widgets::btn(
                                ui,
                                Kind::Secondary,
                                Some(icons::REFRESH),
                                "Check for updates",
                            ),
                        )
                        .clicked()
                    {
                        app.updater.check_now();
                    }
                }
            });
        },
    );
}

/// Draws the Defender exclusion and the server rows.
fn advanced_card(app: &mut ClientApp, ui: &mut Ui) {
    let server = app.snap.server_url.clone();
    section(
        ui,
        "Advanced",
        |_| {},
        |ui| {
            setting_row(
                ui,
                true,
                "Microsoft Defender exclusion",
                "surf-rac is not signed, so Defender may block it. Asks for administrator rights.",
                |ui| {
                    if ui
                        .add(widgets::btn(
                            ui,
                            Kind::Secondary,
                            Some(icons::SHIELD),
                            "Add exclusion",
                        ))
                        .clicked()
                    {
                        app.forms.notice = Some(match crate::defender::add_exclusion() {
                            Ok(()) => "Exclusion requested.".into(),
                            Err(e) => e,
                        });
                    }
                },
            );
            setting_row(ui, false, "Server", &server, |ui| {
                if ui
                    .add(widgets::btn(ui, Kind::Secondary, None, "Change\u{2026}"))
                    .clicked()
                {
                    app.forms.server_dialog = true;
                }
            });
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Secret;

    /// Checks that a draft equal to the saved settings is not dirty.
    #[test]
    fn equal_settings_are_clean() {
        assert!(!dirty(&Settings::default(), &Settings::default()));
    }

    /// Checks that changing any editable setting makes the draft dirty.
    #[test]
    fn each_edited_field_makes_the_draft_dirty() {
        let saved = Settings::default();
        for edit in [
            |s: &mut Settings| s.allow_incoming = !s.allow_incoming,
            |s: &mut Settings| s.unattended = !s.unattended,
            |s: &mut Settings| s.clipboard_default = !s.clipboard_default,
        ] {
            let mut draft = saved.clone();
            edit(&mut draft);
            assert!(dirty(&draft, &saved));
        }
    }

    /// Checks that a different password hash alone does not make the draft dirty.
    #[test]
    fn a_differing_password_hash_alone_is_not_an_edit() {
        let saved = Settings::default();
        let draft = Settings {
            password_hash: Some(Secret::new("hash")),
            ..saved.clone()
        };
        assert!(!dirty(&draft, &saved));
    }
}
