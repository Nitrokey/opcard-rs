// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

//! Utilities for dealing with TLV (Tag-Length-Value) encoded data

pub fn get_do<'input>(tag_path: &[u16], data: &'input [u8]) -> Option<&'input [u8]> {
    let mut to_ret = data;
    let mut remainder = data;
    for tag in tag_path {
        loop {
            let (cur_tag, cur_value, cur_remainder) = take_do(remainder)?;
            remainder = cur_remainder;
            if *tag == cur_tag {
                to_ret = cur_value;
                remainder = cur_value;
                break;
            }
        }
    }
    Some(to_ret)
}

/// Returns (tag, data, remainder)
fn take_do(data: &[u8]) -> Option<(u16, &[u8], &[u8])> {
    let (tag, remainder) = take_tag(data)?;
    let (len, remainder) = take_len(remainder)?;
    if remainder.len() < len {
        warn!("Tried to parse TLV with data length shorter that the length data");
        None
    } else {
        let (value, remainder) = remainder.split_at(len);
        Some((tag, value, remainder))
    }
}

// See
// https://www.emvco.com/wp-content/uploads/2017/05/EMV_v4.3_Book_3_Application_Specification_20120607062110791.pdf
// Annex B1
fn take_tag(data: &[u8]) -> Option<(u16, &[u8])> {
    let b1 = *data.first()?;
    if (b1 & 0x1f) == 0x1f {
        let b2 = *data.get(1)?;

        if (b2 & 0b10000000) != 0 {
            // OpenPGP doesn't have any DO with a tag longer than 2 bytes
            warn!("Got a tag larger than 2 bytes: {data:x?}");
            return None;
        }
        Some((u16::from_be_bytes([b1, b2]), &data[2..]))
    } else {
        Some((u16::from_be_bytes([0, b1]), &data[1..]))
    }
}

pub fn take_len(data: &[u8]) -> Option<(usize, &[u8])> {
    let l1 = *data.first()?;
    if l1 <= 0x7F {
        Some((l1 as usize, &data[1..]))
    } else if l1 == 0x81 {
        Some((*data.get(1)? as usize, &data[2..]))
    } else {
        if l1 != 0x82 {
            warn!(
                "Got an unexpected length tag: {l1:x}, data: {:x?}",
                &data[..3]
            );
            return None;
        }
        let l2 = *data.get(1)?;
        let l3 = *data.get(2)?;
        let len = u16::from_be_bytes([l2, l3]) as usize;
        Some((len as usize, &data[3..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use test_log::test;

    #[test]
    fn dos() {
        assert_eq!(
            get_do(&[0x02], &hex!("02 02 1DB9 02 02 1DB9")),
            Some(hex!("1DB9").as_slice())
        );
        assert_eq!(
            get_do(&[0xA6, 0x7F49, 0x86], &hex!("A6 26 7F49 23 86 21 04 2525252525252525252525252525252525252525252525252525252525252525")),
            Some(hex!("04 2525252525252525252525252525252525252525252525252525252525252525").as_slice())
        );

        // Multiple nested
        assert_eq!(
            get_do(&[0xA6, 0x7F49, 0x86], &hex!("A6 2A 02 02 DEAD 7F49 23 86 21 04 2525252525252525252525252525252525252525252525252525252525252525")),
            Some(hex!("04 2525252525252525252525252525252525252525252525252525252525252525").as_slice())
        );
    }
}
