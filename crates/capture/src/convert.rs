//! Conversion of captured BGRA frames into the YUV layouts the encoders take.

use livekit::webrtc::native::yuv_helper;
use livekit::webrtc::prelude::I420Buffer;
use surf_rac_session::{Frame, PixelFormat};

/// One captured frame: 8-bit B, G, R, A per pixel, rows `stride` bytes apart.
#[derive(Clone)]
pub struct BgraFrame {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes from the start of one row to the next; at least `width * 4`.
    pub stride: u32,
    /// Pixel data, at least `stride * height` bytes.
    pub data: Vec<u8>,
}

impl std::fmt::Debug for BgraFrame {
    /// Writes the frame's size without its pixel data.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgraFrame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("stride", &self.stride)
            .finish_non_exhaustive()
    }
}

/// Converts `src` to a tightly packed I420 frame of `out_w` x `out_h`, scaling when the sizes differ.
///
/// An odd source width or height drops the last column or row. `timestamp_us`
/// becomes the frame's capture time.
///
/// # Panics
///
/// Panics when `src` is smaller than 2x2, its data is shorter than
/// `stride * height`, or the output size is odd or zero.
pub fn to_i420(src: &BgraFrame, out_w: u32, out_h: u32, timestamp_us: i64) -> Frame {
    let buf = i420(src, out_w, out_h);
    let (w, h) = (out_w as usize, out_h as usize);
    let (sy, su, sv) = buf.strides();
    let (y, u, v) = buf.data();
    let mut data = Vec::with_capacity(Frame::expected_len(PixelFormat::I420, out_w, out_h));
    pack(y, sy as usize, w, h, &mut data);
    pack(u, su as usize, w / 2, h / 2, &mut data);
    pack(v, sv as usize, w / 2, h / 2, &mut data);
    Frame {
        width: out_w,
        height: out_h,
        timestamp_us,
        format: PixelFormat::I420,
        data,
    }
}

/// Converts `src` to tightly packed NV12 of `out_w` x `out_h`, scaling when the sizes differ.
///
/// # Panics
///
/// Panics under the same conditions as [`to_i420`].
pub fn to_nv12(src: &BgraFrame, out_w: u32, out_h: u32) -> Vec<u8> {
    let buf = i420(src, out_w, out_h);
    let (sy, su, sv) = buf.strides();
    let (y, u, v) = buf.data();
    let luma = (out_w * out_h) as usize;
    let mut out = vec![0u8; luma + luma / 2];
    let (dst_y, dst_uv) = out.split_at_mut(luma);
    yuv_helper::i420_to_nv12(
        y,
        sy,
        u,
        su,
        v,
        sv,
        dst_y,
        out_w,
        dst_uv,
        out_w,
        out_w as i32,
        out_h as i32,
    );
    out
}

/// Converts `src`, cropped to even dimensions, to I420 and scales it to `out_w` x `out_h`.
fn i420(src: &BgraFrame, out_w: u32, out_h: u32) -> I420Buffer {
    let (w, h) = (src.width & !1, src.height & !1);
    assert!(w >= 2 && h >= 2, "frame {}x{} is smaller than 2x2", src.width, src.height);
    assert!(
        out_w >= 2 && out_h >= 2 && out_w.is_multiple_of(2) && out_h.is_multiple_of(2),
        "output size {out_w}x{out_h} must be even and at least 2x2"
    );
    assert!(
        src.stride >= src.width * 4 && src.data.len() >= (src.stride * src.height) as usize,
        "frame data does not cover {} rows of {} bytes",
        src.height,
        src.stride
    );
    let mut buf = I420Buffer::new(w, h);
    let (sy, su, sv) = buf.strides();
    let (y, u, v) = buf.data_mut();
    yuv_helper::argb_to_i420(
        &src.data, src.stride, y, sy, u, su, v, sv, w as i32, h as i32,
    );
    if (w, h) == (out_w, out_h) {
        buf
    } else {
        buf.scale(out_w as i32, out_h as i32)
    }
}

/// Appends `rows` rows of `row_len` bytes from a plane with `stride` bytes per row to `out`.
fn pack(plane: &[u8], stride: usize, row_len: usize, rows: usize, out: &mut Vec<u8>) {
    for r in 0..rows {
        out.extend_from_slice(&plane[r * stride..r * stride + row_len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a `w` x `h` frame filled with one colour, rows padded to `stride` bytes.
    fn solid(w: u32, h: u32, stride: u32, [r, g, b]: [u8; 3]) -> BgraFrame {
        let mut data = vec![0u8; (stride * h) as usize];
        for y in 0..h as usize {
            for x in 0..w as usize {
                let i = y * stride as usize + x * 4;
                data[i..i + 4].copy_from_slice(&[b, g, r, 255]);
            }
        }
        BgraFrame {
            width: w,
            height: h,
            stride,
            data,
        }
    }

    /// Returns the Y, U and V value at the centre of a tightly packed I420 frame.
    fn centre_yuv(f: &Frame) -> (u8, u8, u8) {
        let (w, h) = (f.width as usize, f.height as usize);
        let (cw, ch) = (w / 2, h / 2);
        let y = f.data[(h / 2) * w + w / 2];
        let u = f.data[w * h + (ch / 2) * cw + cw / 2];
        let v = f.data[w * h + cw * ch + (ch / 2) * cw + cw / 2];
        (y, u, v)
    }

    /// Asserts that `got` is within 3 of `want` in every component.
    fn assert_near(got: (u8, u8, u8), want: (u8, u8, u8)) {
        let close = |a: u8, b: u8| a.abs_diff(b) <= 3;
        assert!(
            close(got.0, want.0) && close(got.1, want.1) && close(got.2, want.2),
            "got {got:?}, want {want:?}"
        );
    }

    #[test]
    fn pure_colors_convert() {
        for (rgb, yuv) in [
            ([255, 255, 255], (235, 128, 128)),
            ([0, 0, 0], (16, 128, 128)),
            ([255, 0, 0], (82, 90, 240)),
            ([0, 255, 0], (145, 54, 34)),
            ([0, 0, 255], (41, 240, 110)),
        ] {
            let f = to_i420(&solid(16, 16, 64, rgb), 16, 16, 7);
            assert_eq!(f.format, PixelFormat::I420);
            assert_eq!(f.timestamp_us, 7);
            f.validate().unwrap();
            assert_near(centre_yuv(&f), yuv);
        }
    }

    #[test]
    fn padded_stride_converts() {
        let tight = to_i420(&solid(32, 16, 128, [10, 200, 30]), 32, 16, 0);
        let padded = to_i420(&solid(32, 16, 128 + 64, [10, 200, 30]), 32, 16, 0);
        assert_eq!(tight.data, padded.data);
    }

    #[test]
    fn odd_source_drops_last_column_and_row() {
        let f = to_i420(&solid(33, 17, 33 * 4, [255, 255, 255]), 32, 16, 0);
        f.validate().unwrap();
        assert_near(centre_yuv(&f), (235, 128, 128));
    }

    #[test]
    fn scaled_output_has_target_size() {
        let f = to_i420(&solid(64, 32, 256, [0, 0, 255]), 32, 16, 0);
        assert_eq!((f.width, f.height), (32, 16));
        assert_eq!(f.data.len(), Frame::expected_len(PixelFormat::I420, 32, 16));
        assert_near(centre_yuv(&f), (41, 240, 110));
    }

    #[test]
    fn nv12_matches_i420_planes() {
        let mut src = solid(16, 8, 64, [0, 0, 0]);
        for (i, px) in src.data.chunks_mut(4).enumerate() {
            px[0] = (i * 7) as u8;
            px[1] = (i * 13) as u8;
            px[2] = (i * 3) as u8;
        }
        let i420 = to_i420(&src, 16, 8, 0);
        let nv12 = to_nv12(&src, 16, 8);
        assert_eq!(nv12.len(), i420.data.len());
        let luma = 16 * 8;
        assert_eq!(nv12[..luma], i420.data[..luma]);
        let chroma = 8 * 4;
        let (u, v) = i420.data[luma..].split_at(chroma);
        for i in 0..chroma {
            assert_eq!(nv12[luma + 2 * i], u[i]);
            assert_eq!(nv12[luma + 2 * i + 1], v[i]);
        }
    }
}
