//! The optional sign-in and create-account dialog, with the account rules
//! the server applies to new accounts.

use eframe::egui::{self, RichText};

use super::widgets::{self, Kind, Tone};
use super::{ClientApp, icons, theme};
use crate::runtime::{AccountTask, Command};

/// Shown when a new account's username breaks the server's rules.
pub(super) const USERNAME_RULE: &str =
    "Use 3 to 32 characters: lowercase letters, digits, dots, dashes and underscores.";

/// Shown when a new account's password breaks the server's rules.
pub(super) const PASSWORD_RULE: &str = "Use a password of 10 to 256 characters.";

/// Shown when the username or the password is blank.
pub(super) const MISSING_FIELDS: &str = "Enter a username and a password.";

/// Returns whether `username` is 3 to 32 characters of `[a-z0-9._-]`, the
/// usernames the server accepts for new accounts.
pub(super) fn valid_username(username: &str) -> bool {
    (3..=32).contains(&username.len())
        && username.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Returns whether `password` has 10 to 256 characters, the passwords the
/// server accepts for new accounts.
pub(super) fn valid_password(password: &str) -> bool {
    (10..=256).contains(&password.chars().count())
}

/// Returns why the typed account details cannot be sent, or `None` when
/// they can.
///
/// Both fields must be filled in. A new account (`create`) must also meet
/// the server's username and password rules; a sign-in is left to the
/// server, which answers wrong details with an error.
pub(super) fn account_error(create: bool, username: &str, password: &str) -> Option<&'static str> {
    if username.is_empty() || password.is_empty() {
        Some(MISSING_FIELDS)
    } else if create && !valid_username(username) {
        Some(USERNAME_RULE)
    } else if create && !valid_password(password) {
        Some(PASSWORD_RULE)
    } else {
        None
    }
}

/// Returns the progress or error text of the running account action and
/// whether it is still running.
pub(super) fn account_message(task: &AccountTask) -> (Option<&str>, bool) {
    match task {
        AccountTask::Idle => (None, false),
        AccountTask::Working(text) => (Some(text), true),
        AccountTask::Failed(text) => (Some(text), false),
    }
}

/// Shows the sign-in or create-account dialog while it is open and closes
/// it once an account is signed in.
///
/// The dialog holds the username and password fields, the latest progress
/// or error message, the switch between signing in and creating an
/// account, and the server in use with a link to change it.
pub(super) fn dialog(app: &mut ClientApp, ctx: &egui::Context) {
    if app.snap.account.is_some() {
        app.forms.sign_in = false;
    }
    if !app.forms.sign_in {
        return;
    }
    let title = if app.forms.register {
        "Create an account"
    } else {
        "Sign in"
    };
    let response = widgets::dialog(ctx, "sign_in_dialog", title, |ui| {
        ui.spacing_mut().item_spacing.y = 12.0;
        ui.label(
            widgets::muted(
                ui,
                "Optional: an account syncs your contacts and lists your devices.",
            )
            .size(13.0),
        );
        form(app, ui);
        server_row(app, ui);
    });
    if response.should_close() {
        app.forms.sign_in = false;
        app.forms.password.clear();
    }
}

/// Draws the fields, the message, the submit button and the switch between
/// signing in and creating an account.
fn form(app: &mut ClientApp, ui: &mut egui::Ui) {
    let task = app.snap.account_task.clone();
    let (task_message, busy) = if app.forms.account_sent {
        account_message(&task)
    } else {
        (None, false)
    };
    let forms = &mut app.forms;
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
    if forms.register {
        ui.add(
            egui::Label::new(
                widgets::muted(
                    ui,
                    "Usernames use lowercase letters, digits, dots, dashes and underscores. \
                     Passwords need at least 10 characters.",
                )
                .size(12.0),
            )
            .wrap(),
        );
    }
    let submit = password.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
    if let Some(error) = forms.account_error {
        widgets::callout(ui, Tone::Danger, icons::CIRCLE_ALERT, error);
    } else if let Some(message) = task_message {
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
        let username = forms.username.trim().to_string();
        forms.account_error = account_error(forms.register, &username, &forms.password);
        if forms.account_error.is_none() {
            let password = std::mem::take(&mut forms.password);
            let command = if forms.register {
                Command::CreateAccount { username, password }
            } else {
                Command::SignIn { username, password }
            };
            forms.account_sent = true;
            app.commands.send(command);
        }
    }
    let (lead, link) = if app.forms.register {
        ("Already have an account?", "Sign in")
    } else {
        ("No account yet?", "Create an account")
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
            app.forms.account_error = None;
            app.forms.account_sent = false;
        }
    });
}

/// Draws the server in use with a link that closes this dialog and opens
/// the server dialog.
fn server_row(app: &mut ClientApp, ui: &mut egui::Ui) {
    let p = theme::palette(ui.ctx());
    widgets::hairline(ui);
    ui.horizontal(|ui| {
        ui.label(icons::text(icons::SERVER, 14.0).color(p.muted));
        ui.label(widgets::muted(ui, &app.snap.server_url).size(12.0));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .link(RichText::new("Change server").font(theme::semibold(12.0)))
                .clicked()
            {
                app.forms.sign_in = false;
                app.forms.password.clear();
                app.forms.server_dialog = true;
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that usernames must be 3 to 32 lowercase letters, digits, dots,
    /// underscores or hyphens.
    #[test]
    fn usernames_follow_the_server_rules() {
        assert!(valid_username("abc"));
        assert!(valid_username("mia.k_2-x"));
        assert!(valid_username(&"a".repeat(32)));
        assert!(!valid_username("ab"));
        assert!(!valid_username(&"a".repeat(33)));
        assert!(!valid_username("Mia"));
        assert!(!valid_username("mia k"));
        assert!(!valid_username("mia@x"));
        assert!(!valid_username("m\u{e9}lo"));
    }

    /// Checks that passwords must be between 10 and 256 characters long.
    #[test]
    fn passwords_need_ten_to_256_characters() {
        assert!(!valid_password("123456789"));
        assert!(valid_password("1234567890"));
        assert!(valid_password(&"\u{e9}".repeat(10)));
        assert!(valid_password(&"x".repeat(256)));
        assert!(!valid_password(&"x".repeat(257)));
    }

    /// Checks that new accounts must satisfy the username and password rules while
    /// sign-ins only need both fields filled in.
    #[test]
    fn new_accounts_are_checked_and_sign_ins_only_need_both_fields() {
        assert_eq!(account_error(true, "mia", "1234567890"), None);
        assert_eq!(
            account_error(true, "Mia", "1234567890"),
            Some(USERNAME_RULE)
        );
        assert_eq!(account_error(true, "mia", "short"), Some(PASSWORD_RULE));
        assert_eq!(account_error(false, "Mia", "short"), None);
        assert_eq!(account_error(false, "", "pw"), Some(MISSING_FIELDS));
        assert_eq!(account_error(false, "mia", ""), Some(MISSING_FIELDS));
        assert_eq!(account_error(true, "", ""), Some(MISSING_FIELDS));
    }

    /// Checks the message and busy flag shown for idle, working and failed account
    /// tasks.
    #[test]
    fn account_messages_show_progress_and_failures() {
        assert_eq!(account_message(&AccountTask::Idle), (None, false));
        assert_eq!(
            account_message(&AccountTask::Working("Signing in...".into())),
            (Some("Signing in..."), true)
        );
        assert_eq!(
            account_message(&AccountTask::Failed("Wrong password".into())),
            (Some("Wrong password"), false)
        );
    }
}
