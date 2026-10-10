//! Mapping between the viewer window and the host monitor: where the picture
//! is drawn and which monitor pixel a pointer position hits.

/// An axis-aligned rectangle in window points.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    /// Left edge.
    pub x: f32,
    /// Top edge.
    pub y: f32,
    /// Width.
    pub w: f32,
    /// Height.
    pub h: f32,
}

/// Returns the largest rectangle with the frame's aspect ratio that fits in
/// `area`, centred in it; zero-sized for a zero-sized frame.
pub fn fit(area: Rect, frame_w: u32, frame_h: u32) -> Rect {
    if frame_w == 0 || frame_h == 0 || area.w <= 0.0 || area.h <= 0.0 {
        return Rect {
            x: area.x,
            y: area.y,
            w: 0.0,
            h: 0.0,
        };
    }
    let scale = (area.w / frame_w as f32).min(area.h / frame_h as f32);
    let (w, h) = (frame_w as f32 * scale, frame_h as f32 * scale);
    Rect {
        x: area.x + (area.w - w) / 2.0,
        y: area.y + (area.h - h) / 2.0,
        w,
        h,
    }
}

/// Maps a pointer position to a pixel of a `monitor_w` x `monitor_h` monitor
/// shown in `picture`.
///
/// Returns `None` when the position lies outside the picture, so clicks on
/// the letterbox bars are not sent.
pub fn to_monitor(
    pos: (f32, f32),
    picture: Rect,
    monitor_w: u32,
    monitor_h: u32,
) -> Option<(i32, i32)> {
    if picture.w <= 0.0 || picture.h <= 0.0 || monitor_w == 0 || monitor_h == 0 {
        return None;
    }
    let rx = (pos.0 - picture.x) / picture.w;
    let ry = (pos.1 - picture.y) / picture.h;
    if !(0.0..1.0).contains(&rx) || !(0.0..1.0).contains(&ry) {
        return None;
    }
    let x = ((rx * monitor_w as f32) as i32).min(monitor_w as i32 - 1);
    let y = ((ry * monitor_h as f32) as i32).min(monitor_h as i32 - 1);
    Some((x, y))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AREA: Rect = Rect {
        x: 10.0,
        y: 20.0,
        w: 800.0,
        h: 600.0,
    };

    /// Checks that a frame wider than the area is scaled to its width and centred
    /// vertically.
    #[test]
    fn wide_frame_is_letterboxed_top_and_bottom() {
        let pic = fit(AREA, 1600, 900);
        assert_eq!(pic.w, 800.0);
        assert_eq!(pic.h, 450.0);
        assert_eq!(pic.x, 10.0);
        assert_eq!(pic.y, 20.0 + 75.0);
    }

    /// Checks that a frame taller than the area is scaled to its height and centred
    /// horizontally.
    #[test]
    fn tall_frame_is_pillarboxed() {
        let pic = fit(AREA, 600, 900);
        assert_eq!(pic.h, 600.0);
        assert_eq!(pic.w, 400.0);
        assert_eq!(pic.x, 10.0 + 200.0);
    }

    /// Checks that an empty frame fits to a zero-sized picture that maps no
    /// positions.
    #[test]
    fn empty_frame_fits_to_nothing() {
        let pic = fit(AREA, 0, 0);
        assert_eq!((pic.w, pic.h), (0.0, 0.0));
        assert_eq!(to_monitor((100.0, 100.0), pic, 1920, 1080), None);
    }

    /// Checks that positions in the picture map to native monitor pixels, including
    /// the last pixel.
    #[test]
    fn pointer_maps_to_native_monitor_pixels() {
        let pic = Rect {
            x: 0.0,
            y: 0.0,
            w: 960.0,
            h: 540.0,
        };
        assert_eq!(to_monitor((0.0, 0.0), pic, 1920, 1080), Some((0, 0)));
        assert_eq!(
            to_monitor((480.0, 270.0), pic, 1920, 1080),
            Some((960, 540))
        );
        assert_eq!(
            to_monitor((959.99, 539.99), pic, 1920, 1080),
            Some((1919, 1079))
        );
    }

    /// Checks that positions map onto the monitor's size even when the frame is
    /// smaller than the monitor.
    #[test]
    fn monitor_size_differs_from_frame_size() {
        // A Speed-mode frame drawn at 640x400 still maps onto a 2560x1600 monitor.
        let pic = Rect {
            x: 100.0,
            y: 50.0,
            w: 640.0,
            h: 400.0,
        };
        assert_eq!(
            to_monitor((420.0, 250.0), pic, 2560, 1600),
            Some((1280, 800))
        );
    }

    /// Checks that positions outside the picture, including its right edge, map to
    /// nothing.
    #[test]
    fn positions_outside_the_picture_are_ignored() {
        let pic = fit(AREA, 1600, 900);
        assert_eq!(to_monitor((50.0, 30.0), pic, 1920, 1080), None);
        assert_eq!(
            to_monitor((pic.x - 1.0, pic.y + 10.0), pic, 1920, 1080),
            None
        );
        assert_eq!(
            to_monitor((pic.x + pic.w, pic.y + 10.0), pic, 1920, 1080),
            None
        );
    }
}
