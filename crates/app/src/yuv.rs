//! Conversion of decoded video frames to RGBA for drawing.

use livekit::webrtc::native::yuv_helper;
use surf_rac_session::{Frame, PixelFormat};

/// Converts a tightly packed I420 or NV12 frame to RGBA, 4 bytes per pixel,
/// using BT.601 limited-range coefficients.
///
/// Returns an empty vector for a frame whose size and data length disagree.
pub fn to_rgba(frame: &Frame) -> Vec<u8> {
    if frame.validate().is_err() {
        return Vec::new();
    }
    let (w, h) = (frame.width as usize, frame.height as usize);
    let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
    let (luma, chroma) = frame.data.split_at(w * h);
    let interleaved;
    let uv = match frame.format {
        PixelFormat::Nv12 => chroma,
        PixelFormat::I420 => {
            let (u, v) = chroma.split_at(cw * ch);
            interleaved = u
                .iter()
                .zip(v)
                .flat_map(|(u, v)| [*u, *v])
                .collect::<Vec<u8>>();
            &interleaved
        }
    };
    let mut rgba = vec![0u8; w * h * 4];
    yuv_helper::nv12_to_abgr(
        luma,
        w as u32,
        uv,
        (cw * 2) as u32,
        &mut rgba,
        (w * 4) as u32,
        w as i32,
        h as i32,
    );
    rgba
}

#[cfg(test)]
mod tests {
    use super::*;
    use surf_rac_session::{Frame, PixelFormat};

    /// Builds an I420 frame filled with one Y, U, V value.
    fn i420(w: u32, h: u32, y: u8, u: u8, v: u8) -> Frame {
        let (cw, ch) = (w.div_ceil(2) as usize, h.div_ceil(2) as usize);
        let mut data = vec![y; (w * h) as usize];
        data.extend(std::iter::repeat_n(u, cw * ch));
        data.extend(std::iter::repeat_n(v, cw * ch));
        Frame {
            width: w,
            height: h,
            timestamp_us: 0,
            format: PixelFormat::I420,
            data,
        }
    }

    /// Builds an NV12 frame filled with one Y, U, V value.
    fn nv12(w: u32, h: u32, y: u8, u: u8, v: u8) -> Frame {
        let (cw, ch) = (w.div_ceil(2) as usize, h.div_ceil(2) as usize);
        let mut data = vec![y; (w * h) as usize];
        for _ in 0..cw * ch {
            data.extend([u, v]);
        }
        Frame {
            width: w,
            height: h,
            timestamp_us: 0,
            format: PixelFormat::Nv12,
            data,
        }
    }

    /// Asserts every pixel is close to `rgb` and opaque.
    fn assert_all(rgba: &[u8], rgb: [u8; 3]) {
        for px in rgba.as_chunks::<4>().0 {
            for c in 0..3 {
                assert!(px[c].abs_diff(rgb[c]) <= 3, "pixel {px:?} is not {rgb:?}");
            }
            assert_eq!(px[3], 255);
        }
    }

    #[test]
    fn limited_range_black_and_white() {
        assert_all(&to_rgba(&i420(4, 2, 16, 128, 128)), [0, 0, 0]);
        assert_all(&to_rgba(&i420(4, 2, 235, 128, 128)), [255, 255, 255]);
    }

    #[test]
    fn red_in_both_layouts() {
        // BT.601 limited-range red: Y 81, U 90, V 240.
        assert_all(&to_rgba(&i420(4, 4, 81, 90, 240)), [255, 0, 0]);
        assert_all(&to_rgba(&nv12(4, 4, 81, 90, 240)), [255, 0, 0]);
    }

    #[test]
    fn odd_sizes_convert_every_pixel() {
        let rgba = to_rgba(&i420(5, 3, 235, 128, 128));
        assert_eq!(rgba.len(), 5 * 3 * 4);
        assert_all(&rgba, [255, 255, 255]);
        let rgba = to_rgba(&nv12(5, 3, 16, 128, 128));
        assert_eq!(rgba.len(), 5 * 3 * 4);
        assert_all(&rgba, [0, 0, 0]);
    }

    #[test]
    fn invalid_frame_gives_empty_image() {
        let mut frame = i420(4, 4, 16, 128, 128);
        frame.data.truncate(3);
        assert!(to_rgba(&frame).is_empty());
    }
}
