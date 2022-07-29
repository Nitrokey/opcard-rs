// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

// This is a re-implementation of the Result::inspect_err method that is currently only available
// in nightly Rust.  Once it is stablizied, we should remove this trait.
pub trait InspectErr<E>: Sized {
    fn inspect_err_stable<F: FnOnce(&E)>(self, f: F) -> Self;
}

impl<T, E> InspectErr<E> for Result<T, E> {
    fn inspect_err_stable<F: FnOnce(&E)>(self, f: F) -> Self {
        if let Self::Err(e) = &self {
            f(e);
        }
        self
    }
}

/// See https://github.com/serde-rs/bytes/pull/28
pub mod serde_bytes {
    use core::fmt;
    use serde::{
        de::{self, Visitor},
        Deserializer, Serializer,
    };

    pub fn serialize<const N: usize, S>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    struct ArrayVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for ArrayVisitor<N> {
        type Value = [u8; N];
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "An array of bytes")
        }

        fn visit_bytes<E>(self, bytes: &[u8]) -> Result<[u8; N], E>
        where
            E: de::Error,
        {
            Self::Value::try_from(bytes)
                .map_err(|_| E::custom("Expected a array of specific length"))
        }
    }

    pub fn deserialize<'de, const N: usize, D>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ArrayVisitor)
    }
}
