//! Synthetic video frames carrying a capture timestamp in their luma plane.
//!
//! The timestamp's 64 bits and a 16-bit checksum are drawn as 16x16-pixel
//! black or white blocks along the top of the frame, which survives lossy
//! video encoding. The rest of the frame is mid grey.

use surf_rac_session::{Frame, PixelFormat};

/// Edge length of one bit block in pixels.
const BLOCK: usize = 16;

/// Number of encoded bits: 64 timestamp bits and 16 checksum bits.
const BITS: usize = 80;

/// Returns the 16-bit checksum of `micros`: the sum of its bytes.
fn checksum(micros: i64) -> u16 {
    micros.to_be_bytes().iter().map(|&b| b as u16).sum()
}

/// Returns the bits to draw for `micros`, most significant first.
fn bits(micros: i64) -> Vec<bool> {
    let value = ((micros as u128) << 16) | checksum(micros) as u128;
    (0..BITS).rev().map(|i| (value >> i) & 1 == 1).collect()
}

/// Returns the top-left pixel of bit block `i` in a frame `width` pixels wide.
fn block_origin(i: usize, width: usize) -> (usize, usize) {
    let per_row = width / BLOCK;
    ((i % per_row) * BLOCK, (i / per_row) * BLOCK)
}

/// Returns the current wall-clock time in microseconds since the Unix epoch.
pub fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

/// Builds an I420 frame of `width` x `height` with `micros` stamped into it.
pub fn stamp_frame(width: u32, height: u32, micros: i64) -> Frame {
    let (w, h) = (width as usize, height as usize);
    let mut data = vec![128u8; Frame::expected_len(PixelFormat::I420, width, height)];
    for (i, bit) in bits(micros).into_iter().enumerate() {
        let (x0, y0) = block_origin(i, w);
        let luma = if bit { 235 } else { 16 };
        for y in y0..(y0 + BLOCK).min(h) {
            data[y * w + x0..y * w + (x0 + BLOCK).min(w)].fill(luma);
        }
    }
    Frame {
        width,
        height,
        timestamp_us: micros,
        format: PixelFormat::I420,
        data,
    }
}

/// Reads the timestamp stamped into `frame`, or `None` when it is absent or corrupt.
pub fn read_stamp(frame: &Frame) -> Option<i64> {
    let w = frame.width as usize;
    if w / BLOCK == 0 || frame.data.len() < w * BLOCK * BITS.div_ceil(w / BLOCK) {
        return None;
    }
    let mut value: u128 = 0;
    for i in 0..BITS {
        let (x0, y0) = block_origin(i, w);
        let mut sum = 0u32;
        for y in y0 + 4..y0 + 12 {
            for x in x0 + 4..x0 + 12 {
                sum += frame.data[y * w + x] as u32;
            }
        }
        value = (value << 1) | u128::from(sum / 64 > 128);
    }
    let micros = (value >> 16) as u64 as i64;
    (checksum(micros) == (value & 0xffff) as u16 && micros > 0).then_some(micros)
}

/// A stamped timestamp is read back from frames of two sizes, and a uniformly grey frame yields no
/// stamp.
#[test]
fn stamp_round_trip() {
    assert_eq!(
        read_stamp(&stamp_frame(640, 480, 123_456_789)),
        Some(123_456_789)
    );
    assert!(read_stamp(&stamp_frame(320, 240, now_micros())).is_some());
    let mut grey = stamp_frame(640, 480, 1);
    grey.data.fill(128);
    assert_eq!(read_stamp(&grey), None);
}
