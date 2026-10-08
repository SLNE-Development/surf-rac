//! Keyboard codes as the input protocol carries them: set-1 scan codes with
//! 0x100 marking E0-extended keys, plus tracking of keys held down.

use std::collections::BTreeSet;

/// Flag added to the scan code of E0-extended keys.
pub const EXTENDED: u32 = 0x100;

/// Returns the protocol key code of a scan code, or `None` for codes outside 1..=0xFF.
pub fn code(scan: u32, extended: bool) -> Option<u32> {
    if scan == 0 || scan > 0xFF {
        return None;
    }
    Some(if extended { scan | EXTENDED } else { scan })
}

/// The keys a viewer currently holds down on the remote side.
#[derive(Debug, Default)]
pub struct KeyTracker {
    /// Codes pressed and not yet released.
    down: BTreeSet<u32>,
}

impl KeyTracker {
    /// Creates a tracker with no keys held.
    pub const fn new() -> Self {
        Self {
            down: BTreeSet::new(),
        }
    }

    /// Records that `code` went down; repeats are harmless.
    pub fn press(&mut self, code: u32) {
        self.down.insert(code);
    }

    /// Records that `code` went up.
    pub fn release(&mut self, code: u32) {
        self.down.remove(&code);
    }

    /// Returns every held key and forgets them, so the caller can send their releases.
    pub fn release_all(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.down).into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_codes_carry_the_extended_bit() {
        assert_eq!(code(0x1E, false), Some(0x1E));
        assert_eq!(code(0x4B, true), Some(0x14B));
        assert_eq!(code(0, false), None);
        assert_eq!(code(0x100, false), None);
    }

    #[test]
    fn release_all_returns_held_keys_once() {
        let mut keys = KeyTracker::default();
        keys.press(0x38);
        keys.press(0x0F);
        keys.press(0x0F);
        keys.release(0x0F);
        assert_eq!(keys.release_all(), vec![0x38]);
        assert!(keys.release_all().is_empty());
    }
}
