//! The client's look: light and dark palettes, bundled fonts, text styles,
//! spacing and the egui visuals built from them.

use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Shadow, Stroke,
    TextStyle, Theme, ThemePreference, Visuals, vec2,
};

/// Font family of the semibold Inter weight.
pub(super) const INTER_SEMIBOLD: &str = "inter-semibold";

/// Font family of the bold Inter weight.
pub(super) const INTER_BOLD: &str = "inter-bold";

/// Font family of the Lucide icon font.
pub(super) const LUCIDE: &str = "lucide";

/// Corner radius of windows and cards, in points.
pub(super) const RADIUS_CARD: u8 = 8;

/// Corner radius of buttons, inputs, chips and dialogs, in points.
pub(super) const RADIUS_CONTROL: u8 = 6;

/// Corner radius of items inside a segmented control, in points.
pub(super) const RADIUS_INNER: u8 = 4;

/// The colours of one theme.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct Palette {
    /// Window background behind cards.
    pub bg: Color32,
    /// Cards, bars and dialogs.
    pub surface: Color32,
    /// Subtle fills: segmented tracks, footers, hovered rows.
    pub surface2: Color32,
    /// Hairlines between rows and around cards.
    pub border: Color32,
    /// Outlines of inputs and secondary buttons, switch tracks when off.
    pub strong: Color32,
    /// Background of text inputs.
    pub input: Color32,
    /// Main text.
    pub text: Color32,
    /// Secondary text and icons.
    pub muted: Color32,
    /// Primary actions, selection and focus.
    pub accent: Color32,
    /// Tinted background for accent chips, avatars and toggles.
    pub accent_soft: Color32,
    /// Accent-coloured text on `surface` or `accent_soft`.
    pub accent_text: Color32,
    /// Positive status text.
    pub ok: Color32,
    /// Positive status background.
    pub ok_soft: Color32,
    /// Warning text.
    pub warn: Color32,
    /// Warning background.
    pub warn_soft: Color32,
    /// Destructive and error text.
    pub danger: Color32,
    /// Destructive and error background.
    pub danger_soft: Color32,
}

/// The light palette, used when Windows is in light mode.
pub(super) const LIGHT: Palette = Palette {
    bg: Color32::from_rgb(0xF4, 0xF5, 0xF7),
    surface: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    surface2: Color32::from_rgb(0xEE, 0xF0, 0xF3),
    border: Color32::from_rgb(0xE3, 0xE6, 0xEA),
    strong: Color32::from_rgb(0xCB, 0xD0, 0xD7),
    input: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    text: Color32::from_rgb(0x15, 0x18, 0x1D),
    muted: Color32::from_rgb(0x5B, 0x63, 0x71),
    accent: Color32::from_rgb(0x25, 0x63, 0xEB),
    accent_soft: Color32::from_rgb(0xE5, 0xEC, 0xFD),
    accent_text: Color32::from_rgb(0x1F, 0x54, 0xC8),
    ok: Color32::from_rgb(0x15, 0x80, 0x3D),
    ok_soft: Color32::from_rgb(0xE3, 0xF4, 0xE8),
    warn: Color32::from_rgb(0xB4, 0x53, 0x09),
    warn_soft: Color32::from_rgb(0xFD, 0xF0, 0xE1),
    danger: Color32::from_rgb(0xB9, 0x1C, 0x1C),
    danger_soft: Color32::from_rgb(0xFC, 0xE8, 0xE8),
};

/// The dark palette, used when Windows is in dark mode or reports no preference.
pub(super) const DARK: Palette = Palette {
    bg: Color32::from_rgb(0x0E, 0x10, 0x14),
    surface: Color32::from_rgb(0x17, 0x1A, 0x20),
    surface2: Color32::from_rgb(0x1F, 0x23, 0x2B),
    border: Color32::from_rgb(0x27, 0x2C, 0x35),
    strong: Color32::from_rgb(0x3A, 0x41, 0x4C),
    input: Color32::from_rgb(0x11, 0x13, 0x18),
    text: Color32::from_rgb(0xE8, 0xEA, 0xEE),
    muted: Color32::from_rgb(0x9A, 0xA3, 0xB0),
    accent: Color32::from_rgb(0x25, 0x63, 0xEB),
    accent_soft: Color32::from_rgb(0x1A, 0x2C, 0x51),
    accent_text: Color32::from_rgb(0x87, 0xA9, 0xF4),
    ok: Color32::from_rgb(0x4A, 0xDE, 0x80),
    ok_soft: Color32::from_rgb(0x13, 0x29, 0x1C),
    warn: Color32::from_rgb(0xF5, 0xA5, 0x4A),
    warn_soft: Color32::from_rgb(0x2E, 0x22, 0x13),
    danger: Color32::from_rgb(0xF8, 0x71, 0x71),
    danger_soft: Color32::from_rgb(0x2D, 0x15, 0x17),
};

/// Installs fonts, text styles, spacing and both themes' visuals, and makes
/// the app follow the Windows light/dark setting with dark as the fallback.
pub(super) fn install(ctx: &egui::Context) {
    ctx.set_fonts(font_definitions());
    ctx.set_visuals_of(Theme::Light, visuals(&LIGHT, false));
    ctx.set_visuals_of(Theme::Dark, visuals(&DARK, true));
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (TextStyle::Heading, bold(20.0)),
            (TextStyle::Body, FontId::proportional(14.0)),
            (TextStyle::Button, semibold(13.0)),
            (TextStyle::Small, FontId::proportional(12.0)),
            (TextStyle::Monospace, FontId::monospace(13.0)),
        ]
        .into();
        let spacing = &mut style.spacing;
        spacing.item_spacing = vec2(8.0, 8.0);
        spacing.button_padding = vec2(14.0, 7.0);
        spacing.interact_size.y = 32.0;
        spacing.window_margin = egui::Margin::same(16);
        spacing.menu_margin = egui::Margin::same(6);
    });
    ctx.options_mut(|o| {
        o.theme_preference = ThemePreference::System;
        o.fallback_theme = Theme::Dark;
    });
}

/// Returns the palette of the theme `ctx` currently draws with.
pub(super) fn palette(ctx: &egui::Context) -> &'static Palette {
    match ctx.theme() {
        Theme::Dark => &DARK,
        Theme::Light => &LIGHT,
    }
}

/// Returns a semibold Inter font of `size` points.
pub(super) fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(INTER_SEMIBOLD.into()))
}

/// Returns a bold Inter font of `size` points.
pub(super) fn bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(INTER_BOLD.into()))
}

/// Builds the font set: Inter first in the proportional family, the bold
/// weights and Lucide (backed by Inter) as named families, and egui's default fonts behind
/// each Inter family for glyphs Inter lacks.
fn font_definitions() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    let defaults = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    for (name, bytes) in [
        (
            "inter-regular",
            &include_bytes!("../../assets/fonts/Inter-Regular.ttf")[..],
        ),
        (
            INTER_SEMIBOLD,
            &include_bytes!("../../assets/fonts/Inter-SemiBold.ttf")[..],
        ),
        (
            INTER_BOLD,
            &include_bytes!("../../assets/fonts/Inter-Bold.ttf")[..],
        ),
        (LUCIDE, &include_bytes!("../../assets/fonts/lucide.ttf")[..]),
    ] {
        fonts
            .font_data
            .insert(name.into(), Arc::new(FontData::from_static(bytes)));
    }
    let with_fallback = |first: &str| {
        let mut list = vec![first.to_string()];
        if first != "inter-regular" {
            list.push("inter-regular".into());
        }
        list.extend(defaults.iter().cloned());
        list
    };
    fonts
        .families
        .insert(FontFamily::Proportional, with_fallback("inter-regular"));
    fonts.families.insert(
        FontFamily::Name(INTER_SEMIBOLD.into()),
        with_fallback(INTER_SEMIBOLD),
    );
    fonts.families.insert(
        FontFamily::Name(INTER_BOLD.into()),
        with_fallback(INTER_BOLD),
    );
    fonts.families.insert(
        FontFamily::Name(LUCIDE.into()),
        vec![LUCIDE.into(), "inter-regular".into()],
    );
    fonts
}

/// Builds egui visuals from a palette.
fn visuals(p: &Palette, dark: bool) -> Visuals {
    let mut v = if dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    let control = CornerRadius::same(RADIUS_CONTROL);
    v.panel_fill = p.bg;
    v.window_fill = p.surface;
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(RADIUS_CARD);
    v.menu_corner_radius = control;
    v.window_shadow = Shadow {
        offset: [0, 8],
        blur: 24,
        spread: 0,
        color: Color32::from_black_alpha(if dark { 120 } else { 40 }),
    };
    v.popup_shadow = Shadow {
        offset: [0, 4],
        blur: 12,
        spread: 0,
        color: Color32::from_black_alpha(if dark { 110 } else { 30 }),
    };
    v.extreme_bg_color = p.input;
    v.text_edit_bg_color = Some(p.input);
    v.faint_bg_color = p.surface2;
    v.code_bg_color = p.surface2;
    v.hyperlink_color = p.accent_text;
    v.warn_fg_color = p.warn;
    v.error_fg_color = p.danger;
    v.weak_text_color = Some(p.muted);
    v.selection.bg_fill = p.accent_soft;
    v.selection.stroke = Stroke::new(1.0, p.accent_text);
    v.text_cursor.stroke = Stroke::new(2.0, p.accent);
    v.striped = false;

    let w = &mut v.widgets;
    w.noninteractive.bg_fill = p.surface;
    w.noninteractive.weak_bg_fill = p.surface;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    w.noninteractive.corner_radius = control;
    for (state, fill, stroke) in [
        (&mut w.inactive, p.surface, p.strong),
        (&mut w.hovered, p.surface2, p.strong),
        (&mut w.active, p.border, p.accent),
        (&mut w.open, p.surface2, p.strong),
    ] {
        state.bg_fill = fill;
        state.weak_bg_fill = fill;
        state.bg_stroke = Stroke::new(1.0, stroke);
        state.fg_stroke = Stroke::new(1.0, p.text);
        state.corner_radius = control;
        state.expansion = 0.0;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that the light and dark palettes have different backgrounds and share the
    /// same accent colour.
    #[test]
    fn palettes_differ_and_accent_is_shared() {
        assert_ne!(LIGHT.bg, DARK.bg);
        assert_eq!(LIGHT.accent, DARK.accent);
        assert_eq!(LIGHT.accent, Color32::from_rgb(0x25, 0x63, 0xEB));
    }

    /// Checks that Inter is the first proportional font with egui's fonts as fallback
    /// and that the bold, semibold and icon families are registered.
    #[test]
    fn fonts_load_with_inter_first_and_egui_fallbacks() {
        let fonts = font_definitions();
        let proportional = &fonts.families[&FontFamily::Proportional];
        assert_eq!(proportional[0], "inter-regular");
        assert!(
            proportional.len() > 1,
            "egui default fonts stay as fallback"
        );
        for family in [INTER_SEMIBOLD, INTER_BOLD, LUCIDE] {
            assert!(
                fonts
                    .families
                    .contains_key(&FontFamily::Name(family.into()))
            );
        }
        assert_eq!(
            fonts.families[&FontFamily::Name(INTER_BOLD.into())][0],
            INTER_BOLD
        );
    }

    /// Checks that installing the theme follows the system preference with dark as the
    /// fallback.
    #[test]
    fn theme_follows_the_system_with_dark_fallback() {
        let ctx = egui::Context::default();
        install(&ctx);
        assert_eq!(ctx.options(|o| o.theme_preference), ThemePreference::System);
        assert_eq!(ctx.options(|o| o.fallback_theme), Theme::Dark);
    }
}
