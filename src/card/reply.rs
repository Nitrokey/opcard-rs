// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;

use core::ops::{Deref, DerefMut};

#[derive(Debug)]
pub struct Reply<'v, const R: usize>(pub &'v mut heapless::Vec<u8, R>);

impl<'v, const R: usize> Deref for Reply<'v, R> {
    type Target = &'v mut heapless::Vec<u8, R>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'v, const R: usize> DerefMut for Reply<'v, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'v, const R: usize> Reply<'v, R> {
    /// Extend the reply and return an error otherwise
    /// The MoreAvailable and GET RESPONSE mechanisms are handled by adpu_dispatch
    ///
    /// Named expand and not extend to avoid conflicts with Deref
    pub fn expand(&mut self, data: &[u8]) -> Result<(), Status> {
        self.0.extend_from_slice(data).map_err(|_| {
            error!("Buffer full");
            Status::NotEnoughMemory
        })
    }

    fn serialize_len(len: usize) -> Result<heapless::Vec<u8, 3>, Status> {
        let mut buf = heapless::Vec::new();
        if let Ok(len) = u8::try_from(len) {
            if len <= 0x7f {
                buf.extend_from_slice(&[len]).ok();
            } else {
                buf.extend_from_slice(&[0x81, len]).ok();
            }
        } else if let Ok(len) = u16::try_from(len) {
            let arr = len.to_be_bytes();
            buf.extend_from_slice(&[0x82, arr[0], arr[1]]).ok();
        } else {
            error!("Length too long to be encoded");
            return Err(Status::UnspecifiedNonpersistentExecutionError);
        }
        Ok(buf)
    }

    /// Prepend the length to some data.
    ///
    /// Input:
    /// AAAAAAAAAABBBBBBB
    ///           ↑  
    ///          offset
    ///    
    /// Output:
    ///
    /// AAAAAAAAAA 7 BBBBBBB
    /// (There are seven Bs, the length is encoded as specified in § 4.4.4)
    pub fn prepend_len(&mut self, offset: usize) -> Result<(), Status> {
        if self.len() < offset {
            error!("`prepend_len` called with offset lower than buffer length");
            return Err(Status::UnspecifiedNonpersistentExecutionError);
        }
        let len = self.len() - offset;
        let encoded = Self::serialize_len(len)?;
        self.extend_from_slice(&encoded).map_err(|_| {
            error!("Buffer full");
            Status::UnspecifiedNonpersistentExecutionError
        })?;
        self[offset..].rotate_right(encoded.len());
        Ok(())
    }

    pub fn append_len(&mut self, len: usize) -> Result<(), Status> {
        let encoded = Self::serialize_len(len)?;
        self.extend_from_slice(&encoded).map_err(|_| {
            error!("Buffer full");
            Status::UnspecifiedNonpersistentExecutionError
        })
    }

    pub fn lend(&mut self) -> Reply<'_, R> {
        Reply(self.0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    #[test]
    fn prep_length() {
        let mut tmp = heapless::Vec::<u8, 1000>::new();
        let mut buf = Reply(&mut tmp);
        let offset = buf.len();
        buf.extend_from_slice(&[0; 0]).unwrap();
        buf.prepend_len(offset).unwrap();
        assert_eq!(&buf[offset..], [0]);

        let offset = buf.len();
        buf.extend_from_slice(&[0; 20]).unwrap();
        buf.prepend_len(offset).unwrap();
        let mut expected = vec![20];
        expected.extend_from_slice(&[0; 20]);
        assert_eq!(&buf[offset..], expected,);

        let offset = buf.len();
        buf.extend_from_slice(&[1; 127]).unwrap();
        buf.prepend_len(offset).unwrap();
        let mut expected = vec![127];
        expected.extend_from_slice(&[1; 127]);
        assert_eq!(&buf[offset..], expected);

        let offset = buf.len();
        buf.extend_from_slice(&[2; 128]).unwrap();
        buf.prepend_len(offset).unwrap();
        let mut expected = vec![0x81, 128];
        expected.extend_from_slice(&[2; 128]);
        assert_eq!(&buf[offset..], expected);

        let offset = buf.len();
        buf.extend_from_slice(&[3; 256]).unwrap();
        buf.prepend_len(offset).unwrap();
        let mut expected = vec![0x82, 0x01, 0x00];
        expected.extend_from_slice(&[3; 256]);
        assert_eq!(&buf[offset..], expected);
    }
}
