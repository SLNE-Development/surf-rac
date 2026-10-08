//! Session windows: request prompts, the host's connections window and viewer windows.

use eframe::egui;
use surf_rac_input::Grants;
use surf_rac_protocol::data::{Control, DataMessage, MouseButton, QualityMode};

use super::{ClientApp, ViewerUi};
use crate::access::PromptNote;
use crate::runtime::{Command, ViewerStatus, ViewerView};
use crate::viewmap::{self, Rect};

/// How long a request prompt is visible before its Accept button works, so a
/// click meant for another window cannot accept a request that pops up under it.
const ACCEPT_DELAY: std::time::Duration = std::time::Duration::from_millis(1500);

/// Returns whether a prompt first shown at `shown` may be accepted at `now`.
fn accept_armed(shown: std::time::Instant, now: std::time::Instant) -> bool {
    now.saturating_duration_since(shown) >= ACCEPT_DELAY
}

/// Wheel units per line of scrolling.
const WHEEL_PER_LINE: f32 = 120.0;

/// Wheel units per point of smooth scrolling.
const WHEEL_PER_POINT: f32 = 3.0;

impl ClientApp {
    /// Shows one always-on-top window per pending request.
    ///
    /// Accept works only after the prompt has been visible for [`ACCEPT_DELAY`].
    pub(super) fn show_prompts(&mut self, ctx: &egui::Context) {
        let now = std::time::Instant::now();
        let prompts = self.snap.prompts.clone();
        self.prompt_shown
            .retain(|id, _| prompts.iter().any(|p| &p.session_id == id));
        for prompt in prompts {
            let shown = *self
                .prompt_shown
                .entry(prompt.session_id.clone())
                .or_insert(now);
            let armed = accept_armed(shown, now);
            if !armed {
                ctx.request_repaint_after(ACCEPT_DELAY);
            }
            let id = egui::ViewportId::from_hash_of(("prompt", &prompt.session_id));
            let builder = egui::ViewportBuilder::default()
                .with_title("Connection request - surf-rac")
                .with_inner_size([380.0, 190.0])
                .with_always_on_top()
                .with_resizable(false);
            ctx.show_viewport_immediate(id, builder, |ui, _| {
                if ui.input(|i| i.viewport().close_requested()) {
                    self.send(Command::Deny(prompt.session_id.clone()));
                }
                egui::CentralPanel::default().show(ui, |ui| {
                    ui.heading(format!("{} wants to connect", prompt.name));
                    ui.label(format!("Device {}", prompt.viewer));
                    ui.small(format!("Key fingerprint {}", prompt.fingerprint));
                    let note = match prompt.note {
                        PromptNote::None => None,
                        PromptNote::CorrectPassword => {
                            Some("The correct unattended password was entered.")
                        }
                        PromptNote::WrongPassword => {
                            Some("A wrong unattended password was entered.")
                        }
                        PromptNote::LockedOut => {
                            Some("Too many wrong passwords: password access is locked.")
                        }
                    };
                    if let Some(note) = note {
                        ui.label(note);
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.add_enabled(armed, egui::Button::new("Accept")).clicked() {
                            self.send(Command::Accept(prompt.session_id.clone()));
                        }
                        if ui.button("Deny").clicked() {
                            self.send(Command::Deny(prompt.session_id.clone()));
                        }
                    });
                });
            });
        }
    }

    /// Shows the always-on-top connections window while viewers are connected.
    pub(super) fn show_connections(&mut self, ctx: &egui::Context) {
        if self.snap.host_viewers.is_empty() {
            self.confirm_disconnect_all = false;
            return;
        }
        let builder = egui::ViewportBuilder::default()
            .with_title("Active connections - surf-rac")
            .with_inner_size([440.0, 220.0])
            .with_always_on_top();
        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("connections"),
            builder,
            |ui, _| {
                if ui.input(|i| i.viewport().close_requested()) {
                    ui.ctx()
                        .send_viewport_cmd(egui::ViewportCommand::CancelClose);
                    self.confirm_disconnect_all = true;
                }
                egui::CentralPanel::default().show(ui, |ui| {
                    ui.heading("Connected to this computer");
                    if self.snap.input_locked {
                        ui.label("You are using this computer: remote input is paused.");
                    }
                    egui::Grid::new("viewers")
                        .num_columns(5)
                        .striped(true)
                        .show(ui, |ui| {
                            for v in self.snap.host_viewers.clone() {
                                ui.label(&v.name);
                                let mut grants = v.grants;
                                let pointer = ui.checkbox(&mut grants.pointer, "Mouse").changed();
                                let keyboard =
                                    ui.checkbox(&mut grants.keyboard, "Keyboard").changed();
                                if pointer || keyboard {
                                    self.send(Command::SetGrants {
                                        viewer: v.id,
                                        grants: Grants { ..grants },
                                    });
                                }
                                let mut clipboard = v.clipboard;
                                if ui.checkbox(&mut clipboard, "Clipboard").changed() {
                                    self.send(Command::HostClipboard {
                                        viewer: v.id,
                                        on: clipboard,
                                    });
                                }
                                if ui.button("Disconnect").clicked() {
                                    self.send(Command::Disconnect(v.id));
                                }
                                ui.end_row();
                            }
                        });
                    let mut follow = self.snap.follow;
                    if ui
                        .checkbox(&mut follow, "Viewers follow my active screen")
                        .changed()
                    {
                        self.send(Command::SetFollow(follow));
                    }
                    if self.confirm_disconnect_all {
                        ui.horizontal(|ui| {
                            ui.label("Disconnect everyone?");
                            if ui.button("Yes").clicked() {
                                self.send(Command::DisconnectAll);
                                self.confirm_disconnect_all = false;
                            }
                            if ui.button("No").clicked() {
                                self.confirm_disconnect_all = false;
                            }
                        });
                    } else if ui.button("Disconnect all").clicked() {
                        self.send(Command::DisconnectAll);
                    }
                });
            },
        );
    }

    /// Shows one window per viewer session.
    pub(super) fn show_viewers(&mut self, ctx: &egui::Context) {
        let views = self.snap.viewers.clone();
        self.viewers
            .retain(|session, _| views.iter().any(|v| v.session == *session));
        for view in views {
            let id = egui::ViewportId::from_hash_of(("viewer", view.session));
            let builder = egui::ViewportBuilder::default()
                .with_title(format!("{} - surf-rac", view.name))
                .with_inner_size([1280.0, 780.0]);
            let mut state = self.viewers.remove(&view.session).unwrap_or_default();
            ctx.show_viewport_immediate(id, builder, |ui, _| {
                self.viewer_window(ui, &view, &mut state);
            });
            self.viewers.insert(view.session, state);
        }
    }

    /// Draws one viewer window and forwards its pointer input.
    fn viewer_window(&mut self, ui: &mut egui::Ui, view: &ViewerView, state: &mut ViewerUi) {
        let session = view.session;
        if ui.input(|i| i.viewport().close_requested()) {
            self.send(Command::ViewerHangup(session));
        }
        state.focused = ui.input(|i| i.viewport().focused.unwrap_or(false));
        egui::Panel::top("toolbar").show(ui, |ui| self.viewer_toolbar(ui, view));
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(egui::Color32::BLACK))
            .show(ui, |ui| {
                let area = ui.max_rect();
                let frame = view.frame.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let Some(frame) = frame else {
                    state.picture = None;
                    ui.centered_and_justified(|ui| {
                        ui.colored_label(egui::Color32::LIGHT_GRAY, status_text(&view.status));
                    });
                    return;
                };
                if frame.seq != state.seq || state.texture.is_none() {
                    let image = egui::ColorImage::from_rgba_unmultiplied(
                        [frame.width as usize, frame.height as usize],
                        &frame.rgba,
                    );
                    match &mut state.texture {
                        Some(texture) => texture.set(image, egui::TextureOptions::LINEAR),
                        None => {
                            state.texture = Some(ui.ctx().load_texture(
                                format!("viewer-{session}"),
                                image,
                                egui::TextureOptions::LINEAR,
                            ))
                        }
                    }
                    state.seq = frame.seq;
                }
                let picture = viewmap::fit(
                    Rect {
                        x: area.min.x,
                        y: area.min.y,
                        w: area.width(),
                        h: area.height(),
                    },
                    frame.width,
                    frame.height,
                );
                state.picture = Some(picture);
                if let Some(texture) = &state.texture {
                    let rect = egui::Rect::from_min_size(
                        egui::pos2(picture.x, picture.y),
                        egui::vec2(picture.w, picture.h),
                    );
                    ui.painter().image(
                        texture.id(),
                        rect,
                        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                        egui::Color32::WHITE,
                    );
                }
                if !matches!(view.status, ViewerStatus::Connected) {
                    ui.colored_label(egui::Color32::YELLOW, status_text(&view.status));
                }
            });
        self.forward_pointer(ui, view, state);
    }

    /// Draws the viewer toolbar: status, monitor, quality, follow, clipboard, disconnect.
    fn viewer_toolbar(&mut self, ui: &mut egui::Ui, view: &ViewerView) {
        let session = view.session;
        let send = |app: &ClientApp, control: Control| {
            app.send(Command::ViewerSend {
                session,
                message: DataMessage::Control(control),
            })
        };
        ui.horizontal(|ui| {
            if let Some(screen) = &view.screen {
                let selected = screen.monitors.iter().find(|m| m.index == screen.selected);
                let label = selected
                    .map(|m| monitor_label(m.index, &m.name))
                    .unwrap_or_default();
                egui::ComboBox::from_id_salt("monitor")
                    .selected_text(label)
                    .show_ui(ui, |ui| {
                        for m in &screen.monitors {
                            let text = monitor_label(m.index, &m.name);
                            if ui
                                .selectable_label(m.index == screen.selected, text)
                                .clicked()
                            {
                                send(self, Control::SelectMonitor { index: m.index });
                            }
                        }
                    });
                egui::ComboBox::from_id_salt("quality")
                    .selected_text(quality_label(screen.mode))
                    .show_ui(ui, |ui| {
                        for mode in [
                            QualityMode::Quality,
                            QualityMode::Balanced,
                            QualityMode::Speed,
                        ] {
                            if ui
                                .selectable_label(screen.mode == mode, quality_label(mode))
                                .clicked()
                            {
                                send(self, Control::SetQuality { mode });
                            }
                        }
                    });
            }
            let mut follow = view.input.follow;
            if ui.checkbox(&mut follow, "Follow").changed() {
                send(self, Control::SetFollow { on: follow });
            }
            let mut clipboard = view.clipboard;
            if ui.checkbox(&mut clipboard, "Clipboard").changed() {
                self.send(Command::ViewerClipboard {
                    session,
                    on: clipboard,
                });
            }
            ui.separator();
            ui.label(input_text(view));
            if view.offer_forget && ui.button("Forget saved password").clicked() {
                self.send(Command::ForgetPassword(view.host));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Disconnect").clicked() {
                    self.send(Command::ViewerHangup(session));
                }
            });
        });
    }

    /// Sends pointer moves, buttons and wheel turns over the picture to the host.
    fn forward_pointer(&self, ui: &egui::Ui, view: &ViewerView, state: &ViewerUi) {
        let (Some(picture), Some(screen)) = (state.picture, view.screen.as_ref()) else {
            return;
        };
        if view.status != ViewerStatus::Connected {
            return;
        }
        let Some(monitor) = screen.monitors.iter().find(|m| m.index == screen.selected) else {
            return;
        };
        let to_host = |pos: egui::Pos2| {
            viewmap::to_monitor((pos.x, pos.y), picture, monitor.width, monitor.height)
        };
        let send = |message: DataMessage| {
            self.send(Command::ViewerSend {
                session: view.session,
                message,
            })
        };
        let hovered = ui
            .input(|i| i.pointer.hover_pos())
            .and_then(to_host)
            .is_some();
        for event in ui.input(|i| i.events.clone()) {
            match event {
                egui::Event::PointerMoved(pos) => {
                    if let Some((x, y)) = to_host(pos) {
                        send(DataMessage::PointerMove {
                            x,
                            y,
                            monitor: monitor.index,
                        });
                    }
                }
                egui::Event::PointerButton {
                    pos,
                    button,
                    pressed,
                    ..
                } => {
                    let Some(button) = mouse_button(button) else {
                        continue;
                    };
                    match to_host(pos) {
                        Some((x, y)) => {
                            send(DataMessage::PointerMove {
                                x,
                                y,
                                monitor: monitor.index,
                            });
                            send(DataMessage::PointerButton {
                                button,
                                down: pressed,
                            });
                        }
                        None if !pressed => send(DataMessage::PointerButton {
                            button,
                            down: false,
                        }),
                        None => {}
                    }
                }
                egui::Event::MouseWheel { unit, delta, .. } if hovered => {
                    let scale = match unit {
                        egui::MouseWheelUnit::Line => WHEEL_PER_LINE,
                        egui::MouseWheelUnit::Point => WHEEL_PER_POINT,
                        egui::MouseWheelUnit::Page => WHEEL_PER_LINE * 3.0,
                    };
                    let (dx, dy) = ((-delta.x * scale) as i32, (delta.y * scale) as i32);
                    if dx != 0 || dy != 0 {
                        send(DataMessage::Wheel { dx, dy });
                    }
                }
                _ => {}
            }
        }
    }
}

/// Maps an egui pointer button to the protocol's mouse button.
fn mouse_button(button: egui::PointerButton) -> Option<MouseButton> {
    Some(match button {
        egui::PointerButton::Primary => MouseButton::Left,
        egui::PointerButton::Secondary => MouseButton::Right,
        egui::PointerButton::Middle => MouseButton::Middle,
        egui::PointerButton::Extra1 => MouseButton::Back,
        egui::PointerButton::Extra2 => MouseButton::Forward,
    })
}

/// Returns a monitor's label in the selector.
fn monitor_label(index: u8, name: &str) -> String {
    format!("Screen {} ({name})", u32::from(index) + 1)
}

/// Returns a quality mode's label.
fn quality_label(mode: QualityMode) -> &'static str {
    match mode {
        QualityMode::Quality => "Best quality",
        QualityMode::Balanced => "Balanced",
        QualityMode::Speed => "Best speed",
    }
}

/// Returns what the viewer may do, as shown in the toolbar.
fn input_text(view: &ViewerView) -> &'static str {
    let input = view.input;
    if input.locked {
        "The host is using the computer"
    } else if input.pointer && input.keyboard {
        "Full control"
    } else if input.pointer {
        "Mouse only"
    } else if input.keyboard {
        "Keyboard only"
    } else {
        "View only"
    }
}

/// Returns the text shown for a session's status.
fn status_text(status: &ViewerStatus) -> String {
    match status {
        ViewerStatus::Requesting => "Waiting for the host to accept...".into(),
        ViewerStatus::Connected => "Connected, waiting for the picture...".into(),
        ViewerStatus::Reconnecting => "Connection lost, reconnecting...".into(),
        ViewerStatus::Ended(text) => text.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pointer_button_maps() {
        assert_eq!(
            mouse_button(egui::PointerButton::Primary),
            Some(MouseButton::Left)
        );
        assert_eq!(
            mouse_button(egui::PointerButton::Extra2),
            Some(MouseButton::Forward)
        );
    }

    #[test]
    fn accept_is_armed_only_after_the_delay() {
        let shown = std::time::Instant::now();
        assert!(!accept_armed(shown, shown));
        assert!(!accept_armed(shown, shown + ACCEPT_DELAY / 2));
        assert!(accept_armed(shown, shown + ACCEPT_DELAY));
    }

    #[test]
    fn monitors_are_numbered_from_one() {
        assert_eq!(monitor_label(0, "DELL"), "Screen 1 (DELL)");
    }
}
