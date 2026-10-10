//! Session windows: request prompts, the host's connections window and viewer windows.

use eframe::egui::{self, Align, Frame, Layout, Margin, RichText};
use surf_rac_input::Grants;
use surf_rac_protocol::DeviceId;
use surf_rac_protocol::data::{Control, DataMessage, MouseButton, QualityMode};

use super::main_window::format_id;
use super::widgets::{self, Kind, Tone};
use super::{ClientApp, ViewerUi, icons, theme};
use crate::access::PromptNote;
use crate::runtime::{Command, HostViewerView, ViewerStatus, ViewerView};
use crate::viewmap::{self, Rect};

/// How long a request prompt is visible before its Accept button works, so a
/// click meant for another window cannot accept a request that pops up under it.
const ACCEPT_DELAY: std::time::Duration = std::time::Duration::from_millis(1500);

/// Returns whether a prompt first shown at `shown` may be accepted at `now`.
fn accept_armed(shown: std::time::Instant, now: std::time::Instant) -> bool {
    now.saturating_duration_since(shown) >= ACCEPT_DELAY
}

/// Returns how far the Accept button has armed, from 0 when the prompt
/// appears to 1 once [`ACCEPT_DELAY`] has passed.
pub(super) fn arm_progress(shown: std::time::Instant, now: std::time::Instant) -> f32 {
    let elapsed = now.saturating_duration_since(shown).as_secs_f32();
    (elapsed / ACCEPT_DELAY.as_secs_f32()).clamp(0.0, 1.0)
}

/// Wheel units per line of scrolling.
const WHEEL_PER_LINE: f32 = 120.0;

/// Wheel units per point of smooth scrolling.
const WHEEL_PER_POINT: f32 = 3.0;

/// Returns the headline name of a request prompt: the local contact alias when
/// the viewer is a contact, otherwise its formatted ID. The device name the
/// viewer chose for itself is never the headline.
fn prompt_headline(alias: Option<&str>, viewer: DeviceId) -> String {
    alias.map_or_else(|| format_id(viewer), str::to_string)
}

/// Returns the callout tone, icon and text for a prompt's password note.
fn note_callout(note: PromptNote) -> Option<(Tone, char, &'static str)> {
    match note {
        PromptNote::None => None,
        PromptNote::CorrectPassword => Some((
            Tone::Ok,
            icons::CHECK,
            "The correct unattended password was entered.",
        )),
        PromptNote::WrongPassword => Some((
            Tone::Warn,
            icons::TRIANGLE_ALERT,
            "A wrong unattended password was entered.",
        )),
        PromptNote::LockedOut => Some((
            Tone::Warn,
            icons::LOCK,
            "Too many wrong passwords: password access is locked.",
        )),
    }
}

impl ClientApp {
    /// Shows one always-on-top window per pending request.
    ///
    /// Accept works only after the prompt has been visible for [`ACCEPT_DELAY`];
    /// until then the button fills up as a progress bar.
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
            let progress = arm_progress(shown, now);
            let id = egui::ViewportId::from_hash_of(("prompt", &prompt.session_id));
            let builder = egui::ViewportBuilder::default()
                .with_title("Connection request - surf-rac")
                .with_inner_size([420.0, 250.0])
                .with_always_on_top()
                .with_resizable(false);
            ctx.show_viewport_immediate(id, builder, |ui, _| {
                if !armed {
                    ui.ctx().request_repaint();
                }
                if ui.input(|i| i.viewport().close_requested()) {
                    self.send(Command::Deny(prompt.session_id.clone()));
                }
                let p = theme::palette(ui.ctx());
                egui::CentralPanel::no_frame()
                    .frame(Frame::new().fill(p.surface).inner_margin(Margin::same(20)))
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 12.0;
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 14.0;
                            let headline = prompt_headline(prompt.alias.as_deref(), prompt.viewer);
                            widgets::avatar(ui, &headline, 44.0);
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 2.0;
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(format!("{headline} wants to connect"))
                                            .font(theme::bold(17.0)),
                                    )
                                    .truncate(),
                                );
                                ui.add(
                                    egui::Label::new(
                                        widgets::muted(
                                            ui,
                                            format!("Device name: {}", prompt.device_name),
                                        )
                                        .size(13.0),
                                    )
                                    .truncate(),
                                );
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 6.0;
                                    ui.label(widgets::muted(ui, "Device").size(13.0));
                                    ui.label(
                                        widgets::muted(ui, format_id(prompt.viewer))
                                            .font(widgets::id_font(13.0)),
                                    );
                                });
                            });
                        });
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            ui.label(icons::text(icons::LOCK, 13.0).color(p.muted));
                            ui.add(
                                egui::Label::new(
                                    widgets::muted(
                                        ui,
                                        format!("Key fingerprint {}", prompt.fingerprint),
                                    )
                                    .size(12.0),
                                )
                                .truncate(),
                            );
                        });
                        if let Some((tone, icon, text)) = note_callout(prompt.note) {
                            widgets::callout(ui, tone, icon, text);
                        }
                        ui.add_space(4.0);
                        ui.scope(|ui| {
                            ui.columns(2, |cols| {
                                let deny = widgets::btn_lg(&cols[0], Kind::Secondary, None, "Deny");
                                if widgets::full_width(&mut cols[0], true, deny).clicked() {
                                    self.send(Command::Deny(prompt.session_id.clone()));
                                }
                                let accept =
                                    widgets::btn_lg(&cols[1], Kind::Primary, None, "Accept");
                                let response = widgets::full_width(&mut cols[1], armed, accept);
                                if !armed {
                                    let bar = response.rect;
                                    let fill = egui::Rect::from_min_size(
                                        egui::pos2(bar.left(), bar.bottom() - 3.0),
                                        egui::vec2(bar.width() * progress, 3.0),
                                    );
                                    cols[1].painter().rect_filled(fill, 1.5, p.accent);
                                }
                                if response.clicked() {
                                    self.send(Command::Accept(prompt.session_id.clone()));
                                }
                            });
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
            .with_inner_size([660.0, 340.0])
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
                let p = theme::palette(ui.ctx());
                egui::Panel::bottom("connections_footer")
                    .frame(
                        Frame::new()
                            .fill(p.surface2)
                            .inner_margin(Margin::symmetric(16, 10)),
                    )
                    .show(ui, |ui| self.connections_footer(ui));
                egui::CentralPanel::no_frame()
                    .frame(Frame::new().fill(p.surface))
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        let count = self.snap.host_viewers.len();
                        Frame::new()
                            .inner_margin(Margin::symmetric(16, 14))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let (rect, _) = ui.allocate_exact_size(
                                        egui::Vec2::splat(18.0),
                                        egui::Sense::hover(),
                                    );
                                    ui.painter().circle_filled(rect.center(), 8.0, p.ok_soft);
                                    ui.painter().circle_filled(rect.center(), 4.5, p.ok);
                                    let title = if count == 1 {
                                        "1 person is connected to this computer".to_string()
                                    } else {
                                        format!("{count} people are connected to this computer")
                                    };
                                    ui.label(RichText::new(title).font(theme::semibold(15.0)));
                                });
                            });
                        if self.snap.input_locked {
                            widgets::banner(
                                ui,
                                Tone::Warn,
                                icons::PAUSE,
                                "You are using this computer, so remote input is paused.",
                                |_| {},
                            );
                        } else {
                            widgets::hairline(ui);
                        }
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            for (i, v) in self.snap.host_viewers.clone().into_iter().enumerate() {
                                widgets::row(ui, i == 0, |ui| self.viewer_row(ui, &v));
                            }
                        });
                    });
            },
        );
    }

    /// Draws one connected viewer: avatar, name and ID, control toggles and Disconnect.
    fn viewer_row(&mut self, ui: &mut egui::Ui, v: &HostViewerView) {
        let p = theme::palette(ui.ctx());
        widgets::avatar(ui, &v.name, 36.0);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            let disconnect = egui::Button::new(icons::text(icons::POWER, 16.0).color(p.danger))
                .frame_when_inactive(false)
                .corner_radius(theme::RADIUS_CONTROL)
                .min_size(egui::Vec2::splat(32.0));
            if ui
                .add(disconnect)
                .on_hover_text(format!("Disconnect {}", v.name))
                .clicked()
            {
                self.send(Command::Disconnect(v.id));
            }
            let mut clipboard = v.clipboard;
            if widgets::toggle_chip(ui, &mut clipboard, icons::CLIPBOARD, "Clip").changed() {
                self.send(Command::HostClipboard {
                    viewer: v.id,
                    on: clipboard,
                });
            }
            let mut grants = v.grants;
            let keyboard =
                widgets::toggle_chip(ui, &mut grants.keyboard, icons::KEYBOARD, "Keys").changed();
            let pointer =
                widgets::toggle_chip(ui, &mut grants.pointer, icons::MOUSE, "Mouse").changed();
            let pointing =
                widgets::toggle_chip(ui, &mut grants.pointing, icons::CROSSHAIR, "Pointing")
                    .changed();
            if pointer || keyboard || pointing {
                self.send(Command::SetGrants {
                    viewer: v.id,
                    grants: Grants { ..grants },
                });
            }
            let mut paused = v.paused;
            if widgets::toggle_chip(ui, &mut paused, icons::PAUSE, "Pause view").changed() {
                self.send(Command::PauseView {
                    viewer: v.id,
                    paused,
                });
            }
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                widgets::name_and_id(ui, &v.name, &format_id(v.id));
            });
        });
    }

    /// Draws the footer of the connections window: follow switch and Disconnect all,
    /// or the confirmation after the window's close button was pressed.
    fn connections_footer(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if self.confirm_disconnect_all {
                ui.label(RichText::new("Disconnect everyone?").font(theme::semibold(13.0)));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add(widgets::btn(ui, Kind::Danger, None, "Disconnect all"))
                        .clicked()
                    {
                        self.send(Command::DisconnectAll);
                        self.confirm_disconnect_all = false;
                    }
                    if ui
                        .add(widgets::btn(ui, Kind::Ghost, None, "Cancel"))
                        .clicked()
                    {
                        self.confirm_disconnect_all = false;
                    }
                });
                return;
            }
            let mut follow = self.snap.follow;
            if widgets::switch(ui, &mut follow).changed() {
                self.send(Command::SetFollow(follow));
            }
            ui.label(RichText::new("Viewers follow my active screen").size(13.0));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add(widgets::btn(ui, Kind::Danger, None, "Disconnect all"))
                    .clicked()
                {
                    self.send(Command::DisconnectAll);
                }
                let resume = all_paused(self.snap.all_paused, &self.snap.host_viewers);
                let label = if resume { "Resume all" } else { "Pause all" };
                if ui.add(widgets::btn(ui, Kind::Ghost, None, label)).clicked() {
                    self.send(Command::PauseAll(!resume));
                }
            });
        });
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
        let p = theme::palette(ui.ctx());
        egui::Panel::top("toolbar")
            .frame(
                Frame::new()
                    .fill(p.surface)
                    .inner_margin(Margin::symmetric(12, 8)),
            )
            .show(ui, |ui| self.viewer_toolbar(ui, view));
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(egui::Color32::BLACK))
            .show(ui, |ui| {
                let area = ui.max_rect();
                let frame = view.frame.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let Some(frame) = frame else {
                    state.picture = None;
                    state.texture = None;
                    ui.centered_and_justified(|ui| {
                        ui.label(RichText::new(status_text(&view.status)).color(p.muted));
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
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        ui.add_space(12.0);
                        widgets::chip(ui, Tone::Warn, true, &status_text(&view.status));
                    });
                }
            });
        self.forward_pointer(ui, view, state);
    }

    /// Draws the viewer toolbar: host name and control level, screen picker,
    /// quality, follow and clipboard toggles, and Disconnect.
    fn viewer_toolbar(&mut self, ui: &mut egui::Ui, view: &ViewerView) {
        let session = view.session;
        let send = |app: &ClientApp, control: Control| {
            app.send(Command::ViewerSend {
                session,
                message: DataMessage::Control(control),
            })
        };
        ui.horizontal(|ui| {
            ui.set_min_height(34.0);
            ui.add_space(4.0);
            ui.label(RichText::new(&view.name).font(theme::semibold(14.0)));
            widgets::chip(ui, input_tone(view), true, input_text(view));
            ui.separator();
            if let Some(screen) = &view.screen {
                let selected = screen.monitors.iter().find(|m| m.index == screen.selected);
                let label = selected
                    .map(|m| monitor_label(m.index, &m.name))
                    .unwrap_or_default();
                egui::ComboBox::from_id_salt("monitor")
                    .selected_text(RichText::new(label).font(theme::semibold(13.0)))
                    .height(240.0)
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
                let mut mode = screen.mode;
                let items = [
                    (QualityMode::Quality, quality_label(QualityMode::Quality)),
                    (QualityMode::Balanced, quality_label(QualityMode::Balanced)),
                    (QualityMode::Speed, quality_label(QualityMode::Speed)),
                ];
                if let Some(mode) = widgets::segmented(ui, &mut mode, &items) {
                    send(self, Control::SetQuality { mode });
                }
            }
            ui.separator();
            let mut follow = view.input.follow;
            if widgets::toggle_icon(
                ui,
                &mut follow,
                icons::CROSSHAIR,
                "Follow the host's active screen",
            )
            .changed()
            {
                send(self, Control::SetFollow { on: follow });
            }
            let mut clipboard = view.clipboard;
            if widgets::toggle_icon(ui, &mut clipboard, icons::CLIPBOARD, "Sync clipboard")
                .changed()
            {
                self.send(Command::ViewerClipboard {
                    session,
                    on: clipboard,
                });
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add(widgets::btn(
                        ui,
                        Kind::Danger,
                        Some(icons::POWER),
                        "Disconnect",
                    ))
                    .clicked()
                {
                    self.send(Command::ViewerHangup(session));
                }
                if view.offer_forget
                    && ui
                        .add(widgets::btn(ui, Kind::Ghost, None, "Forget saved password"))
                        .clicked()
                {
                    self.send(Command::ForgetPassword(view.host));
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
        let ctx = ui.ctx().clone();
        let blocked = |pos: egui::Pos2| pointer_blocked(ctx.layer_id_at(pos).map(|l| l.order));
        let to_host = |pos: egui::Pos2| if blocked(pos) { None } else { to_host(pos) };
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

/// Returns whether a pointer event over a layer of `order` belongs to egui
/// itself, such as an open menu, rather than to the picture.
fn pointer_blocked(order: Option<egui::Order>) -> bool {
    order.is_some_and(|o| o != egui::Order::Background)
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

/// Returns whether the view counts as paused for everyone: the host paused
/// all viewers, or every connected viewer is paused.
fn all_paused(all: bool, viewers: &[HostViewerView]) -> bool {
    all || (!viewers.is_empty() && viewers.iter().all(|v| v.paused))
}

/// Returns what the viewer may do, as shown in the toolbar.
fn input_text(view: &ViewerView) -> &'static str {
    let input = view.input;
    if input.locked {
        "The host is using the computer"
    } else if !input.pointing && input.keyboard {
        "Pointing off, keyboard only"
    } else if !input.pointing {
        "Pointing off"
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

/// Returns the chip tone for what the viewer may do: warning while the host
/// is using the computer, accent while pointing is off or for partial
/// control, positive for full control and neutral for view only.
fn input_tone(view: &ViewerView) -> Tone {
    let input = view.input;
    if input.locked {
        Tone::Warn
    } else if !input.pointing {
        Tone::Accent
    } else if input.pointer && input.keyboard {
        Tone::Ok
    } else if input.pointer || input.keyboard {
        Tone::Accent
    } else {
        Tone::Neutral
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
    fn arm_progress_runs_from_zero_to_one_over_the_delay() {
        let shown = std::time::Instant::now();
        assert_eq!(arm_progress(shown, shown), 0.0);
        assert!((arm_progress(shown, shown + ACCEPT_DELAY / 2) - 0.5).abs() < 1e-3);
        assert_eq!(arm_progress(shown, shown + ACCEPT_DELAY), 1.0);
        assert_eq!(arm_progress(shown, shown + ACCEPT_DELAY * 3), 1.0);
    }

    #[test]
    fn arm_progress_is_zero_when_the_clock_is_behind() {
        let now = std::time::Instant::now();
        let shown = now + std::time::Duration::from_secs(1);
        assert_eq!(arm_progress(shown, now), 0.0);
    }

    #[test]
    fn headline_is_the_contact_alias_or_the_formatted_id() {
        let id = DeviceId::new(123_456_789).unwrap();
        assert_eq!(prompt_headline(Some("Anna"), id), "Anna");
        assert_eq!(prompt_headline(None, id), format_id(id));
    }

    #[test]
    fn every_password_note_but_none_gets_a_callout() {
        assert!(note_callout(PromptNote::None).is_none());
        assert_eq!(
            note_callout(PromptNote::CorrectPassword).unwrap().0,
            Tone::Ok
        );
        assert_eq!(
            note_callout(PromptNote::WrongPassword).unwrap().0,
            Tone::Warn
        );
        assert_eq!(note_callout(PromptNote::LockedOut).unwrap().0, Tone::Warn);
    }

    #[test]
    fn accept_is_armed_only_after_the_delay() {
        let shown = std::time::Instant::now();
        assert!(!accept_armed(shown, shown));
        assert!(!accept_armed(shown, shown + ACCEPT_DELAY / 2));
        assert!(accept_armed(shown, shown + ACCEPT_DELAY));
    }

    #[test]
    fn clicks_on_popups_are_not_forwarded() {
        assert!(!pointer_blocked(None));
        assert!(!pointer_blocked(Some(egui::Order::Background)));
        assert!(pointer_blocked(Some(egui::Order::Foreground)));
        assert!(pointer_blocked(Some(egui::Order::Tooltip)));
    }

    #[test]
    fn input_tone_follows_the_control_level() {
        let view = |pointer, keyboard, locked| view_with(pointer, keyboard, locked, true);
        assert_eq!(input_tone(&view(true, true, true)), Tone::Warn);
        assert_eq!(input_tone(&view(true, true, false)), Tone::Ok);
        assert_eq!(input_tone(&view(true, false, false)), Tone::Accent);
        assert_eq!(input_tone(&view(false, false, false)), Tone::Neutral);
        assert_eq!(
            input_tone(&view_with(true, true, false, false)),
            Tone::Accent
        );
        assert_eq!(input_tone(&view_with(true, true, true, false)), Tone::Warn);
    }

    /// Checks that the toolbar names a pointing-off state, unless the host
    /// locks input.
    #[test]
    fn input_text_shows_pointing_off() {
        assert_eq!(
            input_text(&view_with(true, false, false, false)),
            "Pointing off"
        );
        assert_eq!(
            input_text(&view_with(true, true, false, false)),
            "Pointing off, keyboard only"
        );
        assert_eq!(
            input_text(&view_with(true, true, true, false)),
            "The host is using the computer"
        );
        assert_eq!(
            input_text(&view_with(true, true, false, true)),
            "Full control"
        );
    }

    /// Returns a connected viewer view with the given input state.
    fn view_with(pointer: bool, keyboard: bool, locked: bool, pointing: bool) -> ViewerView {
        use std::sync::{Arc, Mutex};
        use surf_rac_protocol::DeviceId;
        use surf_rac_protocol::data::InputState;

        ViewerView {
            session: 1,
            host: DeviceId::new(123_456_789).unwrap(),
            name: "host".into(),
            status: ViewerStatus::Connected,
            frame: Arc::new(Mutex::new(None)),
            screen: None,
            input: InputState {
                pointer,
                keyboard,
                locked,
                follow: false,
                pointing,
            },
            clipboard: false,
            offer_forget: false,
        }
    }

    /// Returns a connected host viewer with offset `n` and the given pause state.
    fn host_viewer(n: u32, paused: bool) -> HostViewerView {
        HostViewerView {
            id: DeviceId::new(100_000_000 + n).unwrap(),
            name: format!("viewer {n}"),
            grants: Grants::default(),
            clipboard: false,
            paused,
        }
    }

    /// The footer offers Resume all once every viewer is paused or all were
    /// paused at once, and Pause all otherwise.
    #[test]
    fn resume_all_once_everyone_is_paused() {
        assert!(!all_paused(false, &[]));
        assert!(all_paused(true, &[]));
        assert!(!all_paused(
            false,
            &[host_viewer(1, true), host_viewer(2, false)]
        ));
        assert!(all_paused(
            false,
            &[host_viewer(1, true), host_viewer(2, true)]
        ));
    }

    #[test]
    fn monitors_are_numbered_from_one() {
        assert_eq!(monitor_label(0, "DELL"), "Screen 1 (DELL)");
    }
}
