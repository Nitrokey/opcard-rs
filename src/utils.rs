// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

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
