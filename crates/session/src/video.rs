//! Raw video frames and their conversion to and from LiveKit frames.

use livekit::webrtc::prelude::{
    BoxVideoBuffer, BoxVideoFrame, I420Buffer, NV12Buffer, VideoBuffer, VideoFrame,
    VideoResolution, VideoRotation,
};
use livekit::webrtc::video_frame::{EncodedFrameType, EncodedVideoCodec, EncodedVideoFrame};

/// What a host's video track is fed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoInput {
    /// Uncompressed frames that libwebrtc encodes.
    Raw,
    /// H.264 access units encoded before they reach the session.
    Encoded,
}

/// One H.264 access unit in Annex-B format.
#[derive(Debug, Clone, Copy)]
pub struct EncodedFrame<'a> {
    /// Width of the encoded picture in pixels.
    pub width: u32,
    /// Height of the encoded picture in pixels.
    pub height: u32,
    /// Capture time in microseconds.
    pub timestamp_us: i64,
    /// Whether the access unit is an IDR frame.
    pub keyframe: bool,
    /// The Annex-B bytes, including SPS and PPS before an IDR.
    pub data: &'a [u8],
}

/// Bitrate and frame rate the network can currently carry, for an external encoder.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateRequest {
    /// Target bitrate in bits per second.
    pub bitrate_bps: u64,
    /// Target frame rate in frames per second.
    pub framerate: f64,
}

/// Layout of a frame's pixel data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// Planar Y, then U, then V; chroma subsampled 2x2.
    I420,
    /// Planar Y, then interleaved UV; chroma subsampled 2x2.
    Nv12,
}

/// One uncompressed video frame with tightly packed planes.
#[derive(Clone)]
pub struct Frame {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Capture time in microseconds.
    pub timestamp_us: i64,
    /// Pixel layout of `data`.
    pub format: PixelFormat,
    /// Pixel data: the luma plane followed by the chroma plane(s), without padding.
    pub data: Vec<u8>,
}

impl std::fmt::Debug for Frame {
    /// Writes the frame's metadata without its pixel data.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("timestamp_us", &self.timestamp_us)
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

/// Why a frame cannot be published.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// Width or height is zero.
    #[error("frame width and height must be non-zero")]
    ZeroSize,
    /// The data length does not match the format and size.
    #[error("frame data has {actual} bytes, expected {expected}")]
    Length {
        /// Bytes the format and size require.
        expected: usize,
        /// Bytes the frame has.
        actual: usize,
    },
    /// The frame is raw while the track takes encoded frames, or the other way round.
    #[error("frame kind does not match the track's video input")]
    WrongInput,
}

impl Frame {
    /// Returns the number of bytes a tightly packed frame of `format` and size has.
    pub fn expected_len(format: PixelFormat, width: u32, height: u32) -> usize {
        let _ = format;
        let (w, h) = (width as usize, height as usize);
        w * h + 2 * w.div_ceil(2) * h.div_ceil(2)
    }

    /// Checks that the frame has a non-zero size and matching data length.
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.width == 0 || self.height == 0 {
            return Err(FrameError::ZeroSize);
        }
        let expected = Self::expected_len(self.format, self.width, self.height);
        if self.data.len() != expected {
            return Err(FrameError::Length {
                expected,
                actual: self.data.len(),
            });
        }
        Ok(())
    }
}

/// Copies a validated frame into a LiveKit frame buffer.
pub(crate) fn to_livekit(frame: &Frame) -> VideoFrame<BoxVideoBuffer> {
    let (w, h) = (frame.width as usize, frame.height as usize);
    let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
    let (luma, chroma) = frame.data.split_at(w * h);
    let buffer: BoxVideoBuffer = match frame.format {
        PixelFormat::I420 => {
            let mut buf = I420Buffer::new(frame.width, frame.height);
            let (sy, su, sv) = buf.strides();
            let (y, u, v) = buf.data_mut();
            copy_rows_in(luma, y, sy as usize, w, h);
            let (cu, cv) = chroma.split_at(cw * ch);
            copy_rows_in(cu, u, su as usize, cw, ch);
            copy_rows_in(cv, v, sv as usize, cw, ch);
            Box::new(buf)
        }
        PixelFormat::Nv12 => {
            let mut buf = NV12Buffer::new(frame.width, frame.height);
            let (sy, suv) = buf.strides();
            let (y, uv) = buf.data_mut();
            copy_rows_in(luma, y, sy as usize, w, h);
            copy_rows_in(chroma, uv, suv as usize, 2 * cw, ch);
            Box::new(buf)
        }
    };
    let mut out = VideoFrame::new(VideoRotation::VideoRotation0, buffer);
    out.timestamp_us = frame.timestamp_us;
    out
}

/// Describes an encoded access unit as a LiveKit encoded frame.
pub(crate) fn to_livekit_encoded<'a>(frame: &EncodedFrame<'a>) -> EncodedVideoFrame<'a> {
    EncodedVideoFrame {
        codec: EncodedVideoCodec::H264,
        payload: frame.data,
        timestamp_us: frame.timestamp_us,
        frame_type: if frame.keyframe {
            EncodedFrameType::Key
        } else {
            EncodedFrameType::Delta
        },
        resolution: VideoResolution {
            width: frame.width,
            height: frame.height,
        },
        frame_metadata: None,
    }
}

/// Copies a received LiveKit frame into a tightly packed I420 [`Frame`].
pub(crate) fn from_livekit(frame: &BoxVideoFrame) -> Frame {
    let i420 = frame.buffer.to_i420();
    let (width, height) = (i420.width(), i420.height());
    let (w, h) = (width as usize, height as usize);
    let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
    let (sy, su, sv) = i420.strides();
    let (y, u, v) = i420.data();
    let mut data = Vec::with_capacity(Frame::expected_len(PixelFormat::I420, width, height));
    copy_rows_out(y, sy as usize, w, h, &mut data);
    copy_rows_out(u, su as usize, cw, ch, &mut data);
    copy_rows_out(v, sv as usize, cw, ch, &mut data);
    Frame {
        width,
        height,
        timestamp_us: frame.timestamp_us,
        format: PixelFormat::I420,
        data,
    }
}

/// Copies `rows` rows of `row_len` bytes from a strided plane into `out`.
fn copy_rows_out(plane: &[u8], stride: usize, row_len: usize, rows: usize, out: &mut Vec<u8>) {
    for r in 0..rows {
        out.extend_from_slice(&plane[r * stride..r * stride + row_len]);
    }
}

/// Copies tightly packed rows of `row_len` bytes from `src` into a strided plane.
fn copy_rows_in(src: &[u8], plane: &mut [u8], stride: usize, row_len: usize, rows: usize) {
    for r in 0..rows {
        plane[r * stride..r * stride + row_len]
            .copy_from_slice(&src[r * row_len..(r + 1) * row_len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(format: PixelFormat, w: u32, h: u32) -> Frame {
        let len = Frame::expected_len(format, w, h);
        Frame {
            width: w,
            height: h,
            timestamp_us: 42,
            format,
            data: (0..len).map(|i| (i % 251) as u8).collect(),
        }
    }

    #[test]
    fn frame_len_odd_dimensions() {
        assert_eq!(Frame::expected_len(PixelFormat::I420, 3, 3), 9 + 2 * 2 * 2);
        assert_eq!(Frame::expected_len(PixelFormat::Nv12, 4, 2), 8 + 4);
        assert_eq!(
            Frame::expected_len(PixelFormat::I420, 640, 480),
            640 * 480 * 3 / 2
        );
    }

    #[test]
    fn validate_rejects_wrong_length_and_zero() {
        let mut f = frame(PixelFormat::I420, 4, 4);
        assert_eq!(f.validate(), Ok(()));
        f.data.pop();
        assert_eq!(
            f.validate(),
            Err(FrameError::Length {
                expected: 24,
                actual: 23
            })
        );
        let z = Frame {
            width: 0,
            ..frame(PixelFormat::I420, 4, 4)
        };
        assert_eq!(z.validate(), Err(FrameError::ZeroSize));
    }

    #[test]
    fn livekit_round_trip_i420() {
        let f = frame(PixelFormat::I420, 33, 17);
        let lk = to_livekit(&f);
        let boxed: BoxVideoFrame = lk;
        let back = from_livekit(&boxed);
        assert_eq!(
            (back.width, back.height, back.format),
            (33, 17, PixelFormat::I420)
        );
        assert_eq!(back.timestamp_us, 42);
        assert_eq!(back.data, f.data);
    }

    #[test]
    fn livekit_from_nv12_keeps_luma() {
        let f = frame(PixelFormat::Nv12, 16, 8);
        let back = from_livekit(&to_livekit(&f));
        assert_eq!(back.format, PixelFormat::I420);
        assert_eq!(&back.data[..16 * 8], &f.data[..16 * 8]);
        assert_eq!(
            back.data.len(),
            Frame::expected_len(PixelFormat::I420, 16, 8)
        );
    }
}
