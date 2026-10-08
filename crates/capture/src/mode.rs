//! Quality modes: the resolution and bitrate each mode encodes at.

use surf_rac_protocol::data::QualityMode;

/// Frames per second captured and encoded in every mode.
pub const FRAME_RATE: u32 = 30;

/// Returns the longest side, in pixels, `mode` allows, or `None` for native resolution.
fn longest_side(mode: QualityMode) -> Option<u32> {
    match mode {
        QualityMode::Quality => None,
        QualityMode::Balanced => Some(1920),
        QualityMode::Speed => Some(1280),
    }
}

/// Returns the size a `width` x `height` monitor is encoded at in `mode`.
///
/// The result keeps the aspect ratio, has even dimensions of at least 2, and
/// is never larger than the monitor.
pub fn target_size(mode: QualityMode, width: u32, height: u32) -> (u32, u32) {
    let (w, h) = (even(width), even(height));
    match longest_side(mode) {
        Some(cap) if w.max(h) > cap => {
            let scale = f64::from(cap) / f64::from(w.max(h));
            (
                round_even(f64::from(w) * scale),
                round_even(f64::from(h) * scale),
            )
        }
        _ => (w, h),
    }
}

/// Rounds `v` down to an even number of at least 2.
fn even(v: u32) -> u32 {
    (v & !1).max(2)
}

/// Rounds `v` to the nearest even number of at least 2.
fn round_even(v: f64) -> u32 {
    ((v / 2.0).round() as u32 * 2).max(2)
}

/// Returns the highest bitrate, in bits per second, a hardware encoder uses in `mode`.
pub fn bitrate_cap(mode: QualityMode) -> u64 {
    match mode {
        QualityMode::Quality => 8_000_000,
        QualityMode::Balanced => 5_000_000,
        QualityMode::Speed => 2_500_000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Asserts that `(w, h)` has even sides and the aspect ratio of `(ow, oh)` within 1 %.
    fn assert_shape((w, h): (u32, u32), (ow, oh): (u32, u32)) {
        assert!(w % 2 == 0 && h % 2 == 0, "{w}x{h} is not even");
        let (a, b) = (w as f64 / h as f64, ow as f64 / oh as f64);
        assert!((a / b - 1.0).abs() < 0.01, "{w}x{h} does not keep the aspect of {ow}x{oh}");
    }

    #[test]
    fn quality_keeps_native() {
        assert_eq!(target_size(QualityMode::Quality, 2560, 1440), (2560, 1440));
        assert_eq!(target_size(QualityMode::Quality, 3840, 2160), (3840, 2160));
    }

    #[test]
    fn balanced_caps_longest_side() {
        assert_eq!(target_size(QualityMode::Balanced, 2560, 1440), (1920, 1080));
        assert_eq!(target_size(QualityMode::Balanced, 3840, 2160), (1920, 1080));
    }

    #[test]
    fn speed_caps_longest_side() {
        assert_eq!(target_size(QualityMode::Speed, 1920, 1080), (1280, 720));
    }

    #[test]
    fn never_upscales() {
        assert_eq!(target_size(QualityMode::Balanced, 1280, 720), (1280, 720));
        assert_eq!(target_size(QualityMode::Speed, 800, 600), (800, 600));
    }

    #[test]
    fn odd_sizes_round_to_even() {
        let size = target_size(QualityMode::Speed, 1366, 767);
        assert_shape(size, (1366, 767));
        assert!(size.0 <= 1280 && size.1 <= 1280);
        assert_eq!(target_size(QualityMode::Quality, 1366, 767), (1366, 766));
        assert_eq!(target_size(QualityMode::Quality, 3, 3), (2, 2));
    }

    #[test]
    fn portrait_balanced() {
        assert_eq!(target_size(QualityMode::Balanced, 1080, 1920), (1080, 1920));
        let size = target_size(QualityMode::Balanced, 1440, 2560);
        assert_eq!(size, (1080, 1920));
        assert_shape(size, (1440, 2560));
    }

    #[test]
    fn bitrate_caps_per_mode() {
        assert_eq!(bitrate_cap(QualityMode::Quality), 8_000_000);
        assert_eq!(bitrate_cap(QualityMode::Balanced), 5_000_000);
        assert_eq!(bitrate_cap(QualityMode::Speed), 2_500_000);
    }
}
