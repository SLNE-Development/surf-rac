//! Reusable components drawn in the client's theme: buttons, fields,
//! switches, chips, avatars, cards, banners, option cards and dialogs.

use eframe::egui::{
    self, Align, Button, Color32, CornerRadius, Frame, Label, Layout, Margin, Response, RichText,
    Sense, Stroke, StrokeKind, TextEdit, Ui, Vec2, vec2,
};

use super::icons;
use super::theme::{self, Palette, RADIUS_CARD, RADIUS_CONTROL, RADIUS_INNER};

/// The colour role of a chip, banner or callout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Tone {
    /// Positive: online, allowed, done.
    Ok,
    /// Needs attention but nothing failed.
    Warn,
    /// Failed or destructive.
    Danger,
    /// Plain information.
    Neutral,
    /// Highlighted, in the accent colour.
    Accent,
}

impl Tone {
    /// Returns the text and background colour of this tone.
    fn colors(self, p: &Palette) -> (Color32, Color32) {
        match self {
            Tone::Ok => (p.ok, p.ok_soft),
            Tone::Warn => (p.warn, p.warn_soft),
            Tone::Danger => (p.danger, p.danger_soft),
            Tone::Neutral => (p.muted, p.surface2),
            Tone::Accent => (p.accent_text, p.accent_soft),
        }
    }
}

/// The emphasis of a button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// The main action: filled with the accent colour.
    Primary,
    /// A secondary action: outlined.
    Secondary,
    /// A quiet action without a frame.
    Ghost,
    /// A destructive action on a tinted background.
    Danger,
    /// A destructive action as coloured text only.
    DangerText,
}

/// Height of a regular button, in points.
const BUTTON_HEIGHT: f32 = 34.0;

/// Height of a large button, in points.
const BUTTON_HEIGHT_LG: f32 = 44.0;

/// Builds a regular button of `kind` with an optional leading icon.
pub(super) fn btn(ui: &Ui, kind: Kind, icon: Option<char>, label: &str) -> Button<'static> {
    styled(ui, kind, icon, label, BUTTON_HEIGHT, 13.0)
}

/// Builds a large button of `kind` with an optional leading icon.
pub(super) fn btn_lg(ui: &Ui, kind: Kind, icon: Option<char>, label: &str) -> Button<'static> {
    styled(ui, kind, icon, label, BUTTON_HEIGHT_LG, 14.0)
}

/// Builds a button with the colours of `kind` at the given height and font size.
fn styled(
    ui: &Ui,
    kind: Kind,
    icon: Option<char>,
    label: &str,
    height: f32,
    size: f32,
) -> Button<'static> {
    let p = theme::palette(ui.ctx());
    let (fg, fill, stroke) = match kind {
        Kind::Primary => (Color32::WHITE, p.accent, Stroke::new(1.0, p.accent)),
        Kind::Secondary => (p.text, p.surface, Stroke::new(1.0, p.strong)),
        Kind::Ghost => (p.muted, Color32::TRANSPARENT, Stroke::NONE),
        Kind::Danger => (p.danger, p.danger_soft, Stroke::new(1.0, p.danger_soft)),
        Kind::DangerText => (p.danger, Color32::TRANSPARENT, Stroke::NONE),
    };
    let text = RichText::new(label).font(theme::semibold(size)).color(fg);
    let button = match icon {
        Some(icon) => Button::new((icons::text(icon, size + 2.0).color(fg), text)),
        None => Button::new(text),
    };
    button
        .fill(fill)
        .stroke(stroke)
        .corner_radius(RADIUS_CONTROL)
        .min_size(vec2(0.0, height))
}

/// Shows a square, frameless button holding only `icon`, with a tooltip.
pub(super) fn icon_button(ui: &mut Ui, icon: char, tooltip: &str) -> Response {
    let p = theme::palette(ui.ctx());
    ui.scope(|ui| {
        ui.spacing_mut().button_padding = Vec2::splat(8.0);
        ui.add(
            Button::new(icons::text(icon, 16.0).color(p.muted))
                .frame_when_inactive(false)
                .corner_radius(RADIUS_CONTROL)
                .min_size(Vec2::splat(32.0)),
        )
    })
    .inner
    .on_hover_text(tooltip)
}

/// Shows a square, frameless button holding `icon` that opens a dropdown
/// menu filled by `add`.
pub(super) fn icon_menu(ui: &mut Ui, icon: char, tooltip: &str, add: impl FnOnce(&mut Ui)) {
    let p = theme::palette(ui.ctx());
    ui.scope(|ui| {
        ui.spacing_mut().button_padding = Vec2::splat(8.0);
        let button = Button::new(icons::text(icon, 16.0).color(p.muted))
            .frame_when_inactive(false)
            .corner_radius(RADIUS_CONTROL)
            .min_size(Vec2::splat(32.0));
        let (response, _) = egui::containers::menu::MenuButton::from_button(button).ui(ui, |ui| {
            ui.set_min_width(140.0);
            add(ui);
        });
        response.on_hover_text(tooltip);
    });
}

/// Shows a full-width single-line text field with a hint; `password` hides the text.
pub(super) fn text_field(ui: &mut Ui, value: &mut String, hint: &str, password: bool) -> Response {
    let width = ui.available_width();
    sized_field(ui, value, hint, password, width)
}

/// Shows a single-line text field of `width` points with a hint; `password` hides the text.
pub(super) fn sized_field(
    ui: &mut Ui,
    value: &mut String,
    hint: &str,
    password: bool,
    width: f32,
) -> Response {
    ui.add(
        TextEdit::singleline(value)
            .hint_text(hint.to_string())
            .password(password)
            .margin(Margin::symmetric(10, 9))
            .desired_width(width)
            .min_size(vec2(width, 38.0)),
    )
}

/// Shows `button` stretched to the full available width with its label centred.
pub(super) fn full_width(ui: &mut Ui, enabled: bool, button: Button<'static>) -> Response {
    let size = vec2(ui.available_width(), BUTTON_HEIGHT_LG);
    ui.add_enabled_ui(enabled, |ui| ui.add_sized(size, button)).inner
}

/// Shows a large text field for a device ID.
pub(super) fn id_field(ui: &mut Ui, value: &mut String, hint: &str, width: f32) -> Response {
    ui.add(
        TextEdit::singleline(value)
            .hint_text(hint.to_string())
            .font(theme::semibold(18.0))
            .margin(Margin::symmetric(12, 11))
            .desired_width(width)
            .min_size(vec2(width, 46.0)),
    )
}

/// Shows a small muted label above the contents added by `add`.
pub(super) fn labeled<R>(ui: &mut Ui, label: &str, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 6.0;
        ui.label(muted(ui, label).font(theme::semibold(12.0)));
        add(ui)
    })
    .inner
}

/// Returns `text` in the muted colour.
pub(super) fn muted(ui: &Ui, text: impl Into<String>) -> RichText {
    RichText::new(text).color(theme::palette(ui.ctx()).muted)
}

/// Returns `text` as a 15-point semibold section title.
pub(super) fn title(text: impl Into<String>) -> RichText {
    RichText::new(text).font(theme::semibold(15.0))
}

/// Returns the width of `text` laid out in `font` on one line.
pub(super) fn text_width(ui: &Ui, text: &str, font: egui::FontId) -> f32 {
    ui.fonts_mut(|f| f.layout_no_wrap(text.to_string(), font, Color32::WHITE).size().x)
}

/// Shows a horizontal row of `width` points centred in the available width.
pub(super) fn centered_row<R>(ui: &mut Ui, width: f32, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.horizontal(|ui| {
        ui.add_space(((ui.available_width() - width) / 2.0).max(0.0));
        add(ui)
    })
    .inner
}

/// Shows an on/off switch bound to `on`; the response is marked changed when toggled.
pub(super) fn switch(ui: &mut Ui, on: &mut bool) -> Response {
    let (rect, mut response) = ui.allocate_exact_size(vec2(40.0, 22.0), Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    let p = theme::palette(ui.ctx());
    let t = ui.ctx().animate_bool(response.id, *on);
    let track = if *on { p.accent } else { p.strong };
    ui.painter().rect_filled(rect, CornerRadius::same(11), track);
    let x = egui::lerp(rect.left() + 11.0..=rect.right() - 11.0, t);
    ui.painter()
        .circle_filled(egui::pos2(x, rect.center().y), 9.0, Color32::WHITE);
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, ui.is_enabled(), *on, "")
    });
    response
}

/// Shows a small rounded status chip, with a leading dot when `dot` is set.
pub(super) fn chip(ui: &mut Ui, tone: Tone, dot: bool, text: &str) -> Response {
    let p = theme::palette(ui.ctx());
    let (fg, bg) = tone.colors(p);
    let galley = ui.painter().layout_no_wrap(text.to_string(), theme::semibold(12.0), fg);
    let dot_w = if dot { 13.0 } else { 0.0 };
    let size = vec2(galley.size().x + 20.0 + dot_w, 24.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter().rect_filled(rect, RADIUS_CONTROL, bg);
    if dot {
        ui.painter()
            .circle_filled(egui::pos2(rect.left() + 13.5, rect.center().y), 3.5, fg);
    }
    let pos = egui::pos2(
        rect.left() + 10.0 + dot_w,
        rect.center().y - galley.size().y / 2.0,
    );
    ui.painter().galley(pos, galley, fg);
    response
}

/// Returns up to two initials for `name`: the first character of its first
/// two words, upper-cased, or `?` when the name is blank.
pub(super) fn initials(name: &str) -> String {
    let letters: String = name
        .split_whitespace()
        .take(2)
        .filter_map(|word| word.chars().next())
        .flat_map(char::to_uppercase)
        .collect();
    if letters.is_empty() {
        "?".into()
    } else {
        letters
    }
}

/// Shows a round avatar of `size` points with the initials of `name`.
pub(super) fn avatar(ui: &mut Ui, name: &str, size: f32) -> Response {
    let p = theme::palette(ui.ctx());
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    ui.painter()
        .circle_filled(rect.center(), size / 2.0, p.accent_soft);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        initials(name),
        theme::bold(size * 0.36),
        p.accent_text,
    );
    response
}

/// Shows a square tile with `icon` in the muted colour, used for device rows.
pub(super) fn icon_tile(ui: &mut Ui, icon: char) -> Response {
    let p = theme::palette(ui.ctx());
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
    ui.painter().rect_filled(rect, RADIUS_CONTROL, p.surface2);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        icon,
        egui::FontId::new(20.0, egui::FontFamily::Name(theme::LUCIDE.into())),
        p.muted,
    );
    response
}

/// Returns the frame of a card: surface fill, hairline border, card radius.
pub(super) fn card_frame(ui: &Ui) -> Frame {
    let p = theme::palette(ui.ctx());
    Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(RADIUS_CARD)
}

/// Shows a card with `padding` points of inner margin around `add`.
pub(super) fn card<R>(ui: &mut Ui, padding: i8, add: impl FnOnce(&mut Ui) -> R) -> R {
    card_frame(ui)
        .inner_margin(Margin::same(padding))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// Shows a card header: `title` on the left, `right` laid out from the right
/// edge, and a hairline below.
pub(super) fn card_header(ui: &mut Ui, title_text: &str, right: impl FnOnce(&mut Ui)) {
    Frame::new()
        .inner_margin(Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.set_min_height(34.0);
                ui.label(title(title_text));
                ui.with_layout(Layout::right_to_left(Align::Center), right);
            });
        });
    hairline(ui);
}

/// Draws a full-width hairline in the border colour.
pub(super) fn hairline(ui: &mut Ui) {
    let p = theme::palette(ui.ctx());
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, 0.0, p.border);
}

/// Shows one list row with the row padding; draws a hairline above it unless `first`.
pub(super) fn row<R>(ui: &mut Ui, first: bool, add: impl FnOnce(&mut Ui) -> R) -> R {
    if !first {
        hairline(ui);
    }
    Frame::new()
        .inner_margin(Margin::symmetric(16, 10))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.set_min_height(36.0);
                add(ui)
            })
            .inner
        })
        .inner
}

/// Shows a primary and a secondary line of text that truncate to the space left.
pub(super) fn two_lines(ui: &mut Ui, primary: &str, secondary: &str) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 1.0;
        ui.add(Label::new(RichText::new(primary).font(theme::semibold(14.0))).truncate());
        ui.add(Label::new(muted(ui, secondary).size(12.0)).truncate());
    });
}

/// Shows a segmented control choosing `value` among `items`; returns whether it changed.
pub(super) fn segmented<T: PartialEq + Copy>(
    ui: &mut Ui,
    value: &mut T,
    items: &[(T, &str)],
) -> bool {
    let p = theme::palette(ui.ctx());
    let mut changed = false;
    Frame::new()
        .fill(p.surface2)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(RADIUS_CARD)
        .inner_margin(Margin::same(3))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                for (item, label) in items {
                    let selected = *value == *item;
                    let (fg, fill) = if selected {
                        (p.text, p.surface)
                    } else {
                        (p.muted, Color32::TRANSPARENT)
                    };
                    let button = Button::new(
                        RichText::new(*label).font(theme::semibold(13.0)).color(fg),
                    )
                    .fill(fill)
                    .stroke(Stroke::NONE)
                    .corner_radius(RADIUS_INNER)
                    .min_size(vec2(0.0, 28.0));
                    if ui.add(button).clicked() && !selected {
                        *value = *item;
                        changed = true;
                    }
                }
            });
        });
    changed
}

/// Shows a chip-like toggle with an icon and label bound to `on`; the
/// response is marked changed when toggled.
pub(super) fn toggle_chip(ui: &mut Ui, on: &mut bool, icon: char, label: &str) -> Response {
    let p = theme::palette(ui.ctx());
    let (fg, fill, stroke) = if *on {
        (p.accent_text, p.accent_soft, Stroke::new(1.0, p.accent_soft))
    } else {
        (p.muted, p.surface, Stroke::new(1.0, p.strong))
    };
    let mut response = ui.add(
        Button::new((
            icons::text(icon, 14.0).color(fg),
            RichText::new(label).font(theme::semibold(12.0)).color(fg),
        ))
        .fill(fill)
        .stroke(stroke)
        .corner_radius(RADIUS_CONTROL)
        .min_size(vec2(0.0, 30.0)),
    );
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    response
}

/// Shows a square icon-only toggle bound to `on`; the response is marked
/// changed when toggled.
pub(super) fn toggle_icon(ui: &mut Ui, on: &mut bool, icon: char, tooltip: &str) -> Response {
    let p = theme::palette(ui.ctx());
    let (fg, fill) = if *on {
        (p.accent_text, p.accent_soft)
    } else {
        (p.muted, Color32::TRANSPARENT)
    };
    let mut response = ui
        .scope(|ui| {
            ui.spacing_mut().button_padding = Vec2::splat(8.0);
            ui.add(
                Button::new(icons::text(icon, 16.0).color(fg))
                    .fill(fill)
                    .stroke(Stroke::NONE)
                    .corner_radius(RADIUS_CONTROL)
                    .min_size(Vec2::splat(32.0)),
            )
        })
        .inner
        .on_hover_text(tooltip);
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    response
}

/// Shows a full-width strip in `tone` with an icon, wrapping text and
/// actions laid out from the right edge.
pub(super) fn banner(ui: &mut Ui, tone: Tone, icon: char, text: &str, actions: impl FnOnce(&mut Ui)) {
    let p = theme::palette(ui.ctx());
    let (fg, bg) = tone.colors(p);
    Frame::new()
        .fill(bg)
        .inner_margin(Margin::symmetric(20, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(icons::text(icon, 16.0).color(fg));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    actions(ui);
                    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                        ui.add(Label::new(RichText::new(text).color(fg)).wrap());
                    });
                });
            });
        });
}

/// Shows a rounded in-place message in `tone` with an icon and wrapping text.
pub(super) fn callout(ui: &mut Ui, tone: Tone, icon: char, text: &str) {
    let p = theme::palette(ui.ctx());
    let (fg, bg) = tone.colors(p);
    Frame::new()
        .fill(bg)
        .corner_radius(RADIUS_CONTROL)
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(icons::text(icon, 15.0).color(fg));
                ui.add(Label::new(RichText::new(text).color(fg).size(13.0)).wrap());
            });
        });
}

/// Shows a selectable card with a radio mark, a title and a description;
/// the response reports clicks on the whole card.
pub(super) fn option_card(ui: &mut Ui, selected: bool, title_text: &str, desc: &str) -> Response {
    let p = theme::palette(ui.ctx());
    let (fill, stroke) = if selected {
        (p.accent_soft, Stroke::new(2.0, p.accent))
    } else {
        (p.surface, Stroke::new(1.0, p.strong))
    };
    let inner = Frame::new()
        .fill(fill)
        .stroke(stroke)
        .corner_radius(RADIUS_CONTROL)
        .inner_margin(Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
                let ring = if selected { p.accent } else { p.strong };
                ui.painter().circle_stroke(rect.center(), 7.0, Stroke::new(1.5, ring));
                if selected {
                    ui.painter().circle_filled(rect.center(), 4.0, p.accent);
                }
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.label(RichText::new(title_text).font(theme::semibold(14.0)));
                    ui.add(Label::new(muted(ui, desc).size(13.0)).wrap());
                });
            });
        });
    let response = inner.response.interact(Sense::click());
    if response.hovered() && !selected {
        ui.painter().rect_stroke(
            response.rect,
            RADIUS_CONTROL,
            Stroke::new(1.0, p.muted),
            StrokeKind::Inside,
        );
    }
    response
}

/// Shows a modal dialog titled `title_text`, 360 points wide, with `add`
/// below the title. The response says whether the user asked to close it.
pub(super) fn dialog<R>(
    ctx: &egui::Context,
    id: &str,
    title_text: &str,
    add: impl FnOnce(&mut Ui) -> R,
) -> egui::ModalResponse<R> {
    let p = theme::palette(ctx);
    egui::Modal::new(egui::Id::new(id))
        .frame(
            Frame::new()
                .fill(p.surface)
                .stroke(Stroke::new(1.0, p.border))
                .corner_radius(RADIUS_CONTROL)
                .inner_margin(Margin::same(20)),
        )
        .show(ctx, |ui| {
            ui.set_width(360.0);
            ui.label(RichText::new(title_text).font(theme::semibold(17.0)));
            ui.add_space(4.0);
            add(ui)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initials_take_the_first_letters_of_two_words() {
        assert_eq!(initials("Build server"), "BS");
        assert_eq!(initials("Office NUC 2"), "ON");
        assert_eq!(initials("mia"), "M");
    }

    #[test]
    fn initials_fall_back_for_blank_names_and_keep_whole_characters() {
        assert_eq!(initials(""), "?");
        assert_eq!(initials("   "), "?");
        assert_eq!(initials("\u{1F680} Rig"), "\u{1F680}R");
        assert_eq!(initials("élan vital"), "ÉV");
    }
}

