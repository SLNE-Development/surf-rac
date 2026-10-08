//! Inspection of H.264 Annex-B access units.

/// NAL unit type of an IDR slice.
pub const NAL_IDR: u8 = 5;

/// NAL unit type of a sequence parameter set.
pub const NAL_SPS: u8 = 7;

/// NAL unit type of a picture parameter set.
pub const NAL_PPS: u8 = 8;

/// Returns the NAL unit types in an Annex-B byte stream, in order.
pub fn nal_types(au: &[u8]) -> Vec<u8> {
    let mut types = Vec::new();
    let mut i = 0;
    while i + 3 < au.len() {
        if au[i] == 0 && au[i + 1] == 0 && au[i + 2] == 1 {
            types.push(au[i + 3] & 0x1f);
            i += 3;
        } else {
            i += 1;
        }
    }
    types
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_nal_types_after_both_start_code_lengths() {
        let au = [
            0, 0, 0, 1, 0x67, 1, 2, 3, //
            0, 0, 1, 0x68, 4, //
            0, 0, 0, 1, 0x65, 0, 0, 3, 1, //
        ];
        assert_eq!(nal_types(&au), [NAL_SPS, NAL_PPS, NAL_IDR]);
    }

    #[test]
    fn empty_and_garbage_have_no_units() {
        assert!(nal_types(&[]).is_empty());
        assert!(nal_types(&[1, 2, 3, 0, 0]).is_empty());
        assert!(nal_types(&[0, 0, 1]).is_empty());
    }
}
