//! Lucide icons used by the client, as codepoints of the bundled icon font.

use eframe::egui::{FontFamily, FontId, RichText};

use super::theme::LUCIDE;

/// Two overlapping pages.
pub(super) const COPY: char = '\u{e0a2}';
/// A desktop monitor.
pub(super) const MONITOR: char = '\u{e121}';
/// A computer mouse.
pub(super) const MOUSE: char = '\u{e28e}';
/// A keyboard.
pub(super) const KEYBOARD: char = '\u{e284}';
/// A clipboard.
pub(super) const CLIPBOARD: char = '\u{e089}';
/// A shield.
pub(super) const SHIELD: char = '\u{e15c}';
/// A power symbol.
pub(super) const POWER: char = '\u{e144}';
/// A closed padlock.
pub(super) const LOCK: char = '\u{e10f}';
/// A check mark.
pub(super) const CHECK: char = '\u{e070}';
/// A cross.
pub(super) const X: char = '\u{e1b2}';
/// A plus sign.
pub(super) const PLUS: char = '\u{e141}';
/// Three horizontal dots.
pub(super) const ELLIPSIS: char = '\u{e0ba}';
/// A downward chevron.
pub(super) const CHEVRON_DOWN: char = '\u{e071}';
/// Two circular arrows.
pub(super) const REFRESH: char = '\u{e149}';
/// An open eye.
pub(super) const EYE: char = '\u{e0be}';
/// A struck-through eye.
pub(super) const EYE_OFF: char = '\u{e0bf}';
/// A warning triangle.
pub(super) const TRIANGLE_ALERT: char = '\u{e193}';
/// An exclamation mark in a circle.
pub(super) const CIRCLE_ALERT: char = '\u{e07b}';
/// A door with an outgoing arrow.
pub(super) const LOG_OUT: char = '\u{e112}';
/// A server rack.
pub(super) const SERVER: char = '\u{e157}';
/// A crosshair.
pub(super) const CROSSHAIR: char = '\u{e0b0}';
/// Two vertical pause bars.
pub(super) const PAUSE: char = '\u{e132}';
/// Waves, used as the app mark.
pub(super) const WAVES: char = '\u{e283}';

/// Returns `icon` as text in the icon font at `size` points.
pub(super) fn text(icon: char, size: f32) -> RichText {
    RichText::new(icon.to_string()).font(FontId::new(size, FontFamily::Name(LUCIDE.into())))
}
