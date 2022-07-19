// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

/// This module provides support for efficient (de)serialization of bytes using heapless. The need
/// for this is the same as the need for [serde_bytes](https://lib.rs/crates/serde_bytes):
///
/// Heapless implements (de)serialization generically over the T type it holds. Since specialization is still not stable, it can't special case for when T = u8, see here and here.
///
/// This means that serialization of Vec<u8, N> is inefficient and doesn't use serde's built-in support for byte slices. This means that by default, a Vec::<u8,N>::from[1,2,3] would be serialized as "this is an array of len 3, this is an u8 , 0x01, this is a u8, 0x02, this is a u8, 0x03". By serializing them as bytes, we get: "this is a byte array of len 3, 0x010203".
///
/// In CBOR each "this is a u8" tag adds 1 byte, and likely slows down parsing (because for u8 < 25 the value is actually held directly in the tag itself.
pub mod serde_bytes_heapless {
    use serde::{
        de::{Error, SeqAccess, Visitor},
        Deserializer, Serializer,
    };

    pub fn serialize<S, const N: usize>(
        v: &heapless::Vec<u8, N>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(v)
    }

    struct HeaplessBytesVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for HeaplessBytesVisitor<N> {
        type Value = heapless::Vec<u8, N>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("byte array")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<heapless::Vec<u8, N>, E>
        where
            E: Error,
        {
            v.try_into().map_err(|_| E::custom("Byte array too long"))
        }

        fn visit_seq<V>(self, mut visitor: V) -> Result<heapless::Vec<u8, N>, V::Error>
        where
            V: SeqAccess<'de>,
        {
            let mut bytes = heapless::Vec::new();

            while let Some(b) = visitor.next_element()? {
                bytes
                    .push(b)
                    .map_err(|_| V::Error::custom("Byte array too long"))?;
            }

            Ok(bytes)
        }
    }

    pub fn deserialize<'de, D, const N: usize>(
        deserializer: D,
    ) -> Result<heapless::Vec<u8, N>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(HeaplessBytesVisitor::<N>)
    }
}
