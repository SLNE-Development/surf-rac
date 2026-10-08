//! Clipboard sync: detects local clipboard changes, applies remote ones and
//! keeps the two from echoing each other. Text travels as UTF-8, images as PNG.

use surf_rac_protocol::data::{ClipboardKind, DataMessage, MAX_CLIPBOARD_BYTES};

/// Most bytes a decoded clipboard image may take in memory.
const MAX_DECODED_BYTES: usize = 256 * 1024 * 1024;

/// One clipboard item.
#[derive(Clone, PartialEq, Eq)]
pub enum Item {
    /// Unicode text.
    Text(String),
    /// A bitmap with 8-bit R, G, B, A per pixel, rows top to bottom.
    Image {
        /// Width in pixels.
        width: u32,
        /// Height in pixels.
        height: u32,
        /// Pixel data, `width * height * 4` bytes.
        rgba: Vec<u8>,
    },
}

impl std::fmt::Debug for Item {
    /// Writes the item's kind and size without its contents.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Item::Text(t) => write!(f, "Text({} bytes)", t.len()),
            Item::Image { width, height, .. } => write!(f, "Image({width}x{height})"),
        }
    }
}

/// Builds the data message for `item`; `None` when its encoding exceeds
/// [`MAX_CLIPBOARD_BYTES`] or an image's buffer does not match its size.
pub fn encode(item: &Item) -> Option<DataMessage> {
    let (kind, bytes) = match item {
        Item::Text(text) => (ClipboardKind::Text, text.as_bytes().to_vec()),
        Item::Image {
            width,
            height,
            rgba,
        } => (ClipboardKind::Image, encode_png(*width, *height, rgba)?),
    };
    if bytes.len() > MAX_CLIPBOARD_BYTES {
        tracing::info!(size = bytes.len(), "clipboard item too large to send");
        return None;
    }
    Some(DataMessage::Clipboard { kind, bytes })
}

/// Reads the clipboard item a data message carries; `None` for other
/// messages, invalid UTF-8 and undecodable images.
pub fn decode(message: &DataMessage) -> Option<Item> {
    let DataMessage::Clipboard { kind, bytes } = message else {
        return None;
    };
    match kind {
        ClipboardKind::Text => String::from_utf8(bytes.clone()).ok().map(Item::Text),
        ClipboardKind::Image => decode_png(bytes),
    }
}

/// Encodes an RGBA bitmap as PNG.
fn encode_png(width: u32, height: u32, rgba: &[u8]) -> Option<Vec<u8>> {
    if width == 0 || height == 0 || rgba.len() != width as usize * height as usize * 4 {
        return None;
    }
    let mut out = Vec::new();
    let mut encoder = png::Encoder::new(&mut out, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.set_compression(png::Compression::Fast);
    let mut writer = encoder.write_header().ok()?;
    writer.write_image_data(rgba).ok()?;
    writer.finish().ok()?;
    Some(out)
}

/// Returns whether a `width` x `height` RGBA bitmap stays within [`MAX_DECODED_BYTES`].
fn rgba_fits(width: u32, height: u32) -> bool {
    (u64::from(width) * u64::from(height))
        .checked_mul(4)
        .is_some_and(|bytes| bytes <= MAX_DECODED_BYTES as u64)
}

/// Decodes a PNG of any 8-bit-convertible colour type into an RGBA bitmap.
///
/// Images whose RGBA form would exceed [`MAX_DECODED_BYTES`] are refused
/// before any pixel memory is allocated.
fn decode_png(bytes: &[u8]) -> Option<Item> {
    let mut decoder = png::Decoder::new_with_limits(
        std::io::Cursor::new(bytes),
        png::Limits {
            bytes: MAX_DECODED_BYTES,
        },
    );
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().ok()?;
    let (width, height) = (reader.info().width, reader.info().height);
    if !rgba_fits(width, height) {
        tracing::info!(width, height, "clipboard image too large to decode");
        return None;
    }
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    buf.truncate(info.buffer_size());
    let rgba = match info.color_type {
        png::ColorType::Rgba => buf,
        png::ColorType::Rgb => buf
            .as_chunks::<3>()
            .0
            .iter()
            .flat_map(|p| [p[0], p[1], p[2], 255])
            .collect(),
        png::ColorType::GrayscaleAlpha => buf
            .as_chunks::<2>()
            .0
            .iter()
            .flat_map(|p| [p[0], p[0], p[0], p[1]])
            .collect(),
        png::ColorType::Grayscale => buf.iter().flat_map(|g| [*g, *g, *g, 255]).collect(),
        png::ColorType::Indexed => return None,
    };
    Some(Item::Image {
        width: info.width,
        height: info.height,
        rgba,
    })
}

/// Access to a clipboard.
pub trait Board {
    /// Returns a number that changes whenever the clipboard's contents change.
    fn sequence(&self) -> u32;
    /// Reads the current text or image, if the clipboard holds one.
    fn read(&mut self) -> Option<Item>;
    /// Replaces the clipboard's contents; returns whether it worked.
    fn write(&mut self, item: &Item) -> bool;
}

/// Tracks one clipboard for sync: reports local changes and applies remote
/// items without reporting them back.
pub struct ClipboardSync<B> {
    /// The clipboard.
    board: B,
    /// Sequence number last seen, `None` before the first poll.
    seen: Option<u32>,
    /// The item last written from the remote side.
    remote: Option<Item>,
}

impl<B: Board> ClipboardSync<B> {
    /// Starts tracking `board`; the first [`ClipboardSync::poll`] reports what it already holds.
    pub fn new(board: B) -> Self {
        Self {
            board,
            seen: None,
            remote: None,
        }
    }

    /// Returns the tracked clipboard.
    pub fn board_mut(&mut self) -> &mut B {
        &mut self.board
    }

    /// Returns the clipboard's item when it changed locally since the last poll.
    pub fn poll(&mut self) -> Option<Item> {
        let seq = self.board.sequence();
        if self.seen == Some(seq) {
            return None;
        }
        self.seen = Some(seq);
        let item = self.board.read()?;
        if self.remote.as_ref() == Some(&item) {
            return None;
        }
        Some(item)
    }

    /// Writes an item received from the remote side to the clipboard.
    pub fn apply(&mut self, item: Item) {
        if self.board.write(&item) {
            self.seen = Some(self.board.sequence());
            self.remote = Some(item);
        } else {
            tracing::warn!("clipboard could not be written");
        }
    }
}

/// The Windows clipboard.
#[cfg(windows)]
pub struct SystemBoard {
    /// Clipboard access.
    clipboard: arboard::Clipboard,
}

#[cfg(windows)]
impl SystemBoard {
    /// Opens the system clipboard.
    pub fn open() -> Result<SystemBoard, String> {
        arboard::Clipboard::new()
            .map(|clipboard| SystemBoard { clipboard })
            .map_err(|e| e.to_string())
    }
}

#[cfg(windows)]
impl Board for SystemBoard {
    /// Returns the system clipboard sequence number.
    fn sequence(&self) -> u32 {
        // SAFETY: the call has no preconditions.
        unsafe { windows::Win32::System::DataExchange::GetClipboardSequenceNumber() }
    }

    /// Reads text first, then an image.
    fn read(&mut self) -> Option<Item> {
        if let Ok(text) = self.clipboard.get_text() {
            return Some(Item::Text(text));
        }
        let image = self.clipboard.get_image().ok()?;
        Some(Item::Image {
            width: u32::try_from(image.width).ok()?,
            height: u32::try_from(image.height).ok()?,
            rgba: image.bytes.into_owned(),
        })
    }

    /// Writes text or an image.
    fn write(&mut self, item: &Item) -> bool {
        let result = match item {
            Item::Text(text) => self.clipboard.set_text(text.clone()),
            Item::Image {
                width,
                height,
                rgba,
            } => self.clipboard.set_image(arboard::ImageData {
                width: *width as usize,
                height: *height as usize,
                bytes: std::borrow::Cow::Borrowed(rgba),
            }),
        };
        result.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory clipboard whose sequence number grows on every write.
    #[derive(Default)]
    struct FakeBoard {
        seq: u32,
        item: Option<Item>,
    }

    impl FakeBoard {
        fn copy(&mut self, item: Item) {
            self.seq += 1;
            self.item = Some(item);
        }
    }

    impl Board for FakeBoard {
        fn sequence(&self) -> u32 {
            self.seq
        }
        fn read(&mut self) -> Option<Item> {
            self.item.clone()
        }
        fn write(&mut self, item: &Item) -> bool {
            self.copy(item.clone());
            true
        }
    }

    fn image(w: u32, h: u32) -> Item {
        Item::Image {
            width: w,
            height: h,
            rgba: (0..w * h * 4).map(|i| (i % 251) as u8).collect(),
        }
    }

    #[test]
    fn existing_content_is_offered_once() {
        let mut board = FakeBoard::default();
        board.copy(Item::Text("before".into()));
        let mut sync = ClipboardSync::new(board);
        assert_eq!(sync.poll(), Some(Item::Text("before".into())));
        assert_eq!(sync.poll(), None);
    }

    #[test]
    fn local_change_is_reported_once() {
        let mut sync = ClipboardSync::new(FakeBoard::default());
        assert_eq!(sync.poll(), None);
        sync.board_mut().copy(Item::Text("hello".into()));
        assert_eq!(sync.poll(), Some(Item::Text("hello".into())));
        assert_eq!(sync.poll(), None);
    }

    #[test]
    fn remote_item_is_not_echoed() {
        let mut sync = ClipboardSync::new(FakeBoard::default());
        sync.apply(Item::Text("from remote".into()));
        assert_eq!(
            sync.board_mut().item,
            Some(Item::Text("from remote".into()))
        );
        assert_eq!(sync.poll(), None);
        sync.board_mut().copy(Item::Text("typed here".into()));
        assert_eq!(sync.poll(), Some(Item::Text("typed here".into())));
    }

    #[test]
    fn text_round_trips() {
        let item = Item::Text("grüße 👋".into());
        let msg = encode(&item).unwrap();
        assert!(matches!(
            msg,
            DataMessage::Clipboard {
                kind: ClipboardKind::Text,
                ..
            }
        ));
        assert_eq!(decode(&msg), Some(item));
    }

    #[test]
    fn image_round_trips_as_png() {
        let item = image(7, 5);
        let msg = encode(&item).unwrap();
        let DataMessage::Clipboard { kind, bytes } = &msg else {
            panic!("not a clipboard message")
        };
        assert_eq!(*kind, ClipboardKind::Image);
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(decode(&msg), Some(item));
    }

    #[test]
    fn oversize_items_are_not_encoded() {
        let text = Item::Text("x".repeat(MAX_CLIPBOARD_BYTES + 1));
        assert!(encode(&text).is_none());
    }

    #[test]
    fn malformed_payloads_decode_to_nothing() {
        let bad_png = DataMessage::Clipboard {
            kind: ClipboardKind::Image,
            bytes: b"not a png".to_vec(),
        };
        assert_eq!(decode(&bad_png), None);
        let bad_text = DataMessage::Clipboard {
            kind: ClipboardKind::Text,
            bytes: vec![0xff, 0xfe],
        };
        assert_eq!(decode(&bad_text), None);
        assert_eq!(decode(&DataMessage::Wheel { dx: 0, dy: 1 }), None);
    }

    #[test]
    fn image_with_wrong_buffer_size_is_not_encoded() {
        let item = Item::Image {
            width: 4,
            height: 4,
            rgba: vec![0; 3],
        };
        assert!(encode(&item).is_none());
    }

    #[test]
    fn rgba_size_is_capped_before_decoding() {
        assert!(rgba_fits(4096, 4096));
        // A 16000x16000 grayscale image passes the decoder's own limit but
        // would take about 1 GiB once expanded to RGBA.
        assert!(!rgba_fits(16_000, 16_000));
        assert!(!rgba_fits(u32::MAX, u32::MAX));
    }
}
