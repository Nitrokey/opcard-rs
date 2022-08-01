// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use hex_literal::hex;
use iso7816::Status;
use serde_repr::{Deserialize_repr, Serialize_repr};

/// Creates an enum with an `iter_all` associated function giving an iterator over all variants
macro_rules! iterable_enum {
    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident {
            $($var:ident),+
            $(,)*
        }
    ) => {
        $(#[$outer])*
        $vis enum $name {
            $(
                $var,
            )*
        }

        #[allow(unused)]
        impl $name {
            $vis fn iter_all() -> impl Iterator<Item = Self> {
                [
                    $(
                        $name::$var,
                    )*
                ].into_iter()
            }
        }
    }
}

const ED255_ATTRIBUTES: &[u8] = hex!("16 2B 06 01 04 01 DA 47 0F 01").as_slice();
const ECDSA_P256_ATTRIBUTES: &[u8] = hex!("13 2A 86 48 CE 3D 03 01 07").as_slice();
const ECDH_P256_ATTRIBUTES: &[u8] = hex!("12 2A 86 48 CE 3D 03 01 07").as_slice();
const X255_ATTRIBUTES: &[u8] = hex!("12 2B 06 01 04 01 97 55 01 05 01").as_slice();
const RSA_2K_ATTRIBUTES: &[u8] = hex!("
    01
    0800 // Length modulus (in bit): 2048                                                                                                                                        
    0020 // Length exponent (in bit): 32
    00   // 0: Acceptable format is: P and Q
").as_slice();
const RSA_4K_ATTRIBUTES: &[u8] = hex!(
    "
    01
    1000 // Length modulus (in bit): 4096
    0020 // Length exponent (in bit): 32
    00   // 0: Acceptable format is: P and Q
"
)
.as_slice();

iterable_enum! {
    #[derive(Serialize_repr, Deserialize_repr, Clone, Copy, PartialEq, Eq, Debug)]
    #[repr(u8)]
    pub enum SignatureAlgorithms {
        // Part of draft https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/
        Ed255,
        EcDsaP256,
        Rsa2k,
        Rsa4k,
    }
}

impl Default for SignatureAlgorithms {
    fn default() -> Self {
        Self::Rsa2k
    }
}

impl SignatureAlgorithms {
    #[allow(unused)]
    pub fn id(&self) -> u8 {
        self.attributes()[0]
    }

    pub fn attributes(&self) -> &'static [u8] {
        match self {
            Self::Ed255 => ED255_ATTRIBUTES,
            Self::EcDsaP256 => ECDSA_P256_ATTRIBUTES,
            Self::Rsa2k => RSA_2K_ATTRIBUTES,
            Self::Rsa4k => RSA_4K_ATTRIBUTES,
        }
    }

    #[allow(unused)]
    pub fn oid(&self) -> &'static [u8] {
        &self.attributes()[1..]
    }
}

iterable_enum! {
    #[derive(Serialize_repr, Deserialize_repr, Clone, Copy, PartialEq, Eq, Debug)]
    #[repr(u8)]
    pub enum DecryptionAlgorithms {
        // Part of draft https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/
        X255,
        EcDhP256,
        Rsa2k,
        Rsa4k,
    }
}

impl Default for DecryptionAlgorithms {
    fn default() -> Self {
        Self::Rsa2k
    }
}

impl DecryptionAlgorithms {
    #[allow(unused)]
    pub fn id(&self) -> u8 {
        self.attributes()[0]
    }

    pub fn attributes(&self) -> &'static [u8] {
        match self {
            Self::X255 => X255_ATTRIBUTES,
            Self::EcDhP256 => ECDH_P256_ATTRIBUTES,
            Self::Rsa2k => RSA_2K_ATTRIBUTES,
            Self::Rsa4k => RSA_4K_ATTRIBUTES,
        }
    }

    #[allow(unused)]
    pub fn oid(&self) -> &'static [u8] {
        &self.attributes()[1..]
    }
}

iterable_enum! {
    #[derive(Serialize_repr, Deserialize_repr, Clone, Copy, PartialEq, Eq, Debug)]
    #[repr(u8)]
    pub enum AuthenticationAlgorithms {
        // Part of draft https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/
        X255,
        EcDhP256,
        Rsa2k,
        Rsa4k,
    }
}

impl Default for AuthenticationAlgorithms {
    fn default() -> Self {
        Self::Rsa2k
    }
}

impl AuthenticationAlgorithms {
    #[allow(unused)]
    pub fn id(&self) -> u8 {
        self.attributes()[0]
    }

    pub fn attributes(&self) -> &'static [u8] {
        match self {
            Self::X255 => X255_ATTRIBUTES,
            Self::EcDhP256 => ECDH_P256_ATTRIBUTES,
            Self::Rsa2k => RSA_2K_ATTRIBUTES,
            Self::Rsa4k => RSA_4K_ATTRIBUTES,
        }
    }

    #[allow(unused)]
    pub fn oid(&self) -> &'static [u8] {
        &self.attributes()[1..]
    }
}

#[derive(Clone, Debug, Copy)]
#[allow(unused)]
pub enum KeyType {
    Sign,
    Confidentiality,
    Aut,
}

impl KeyType {
    #[allow(unused)]
    pub fn try_from_crt(v: &[u8]) -> Result<Self, Status> {
        match v {
            hex!("B6 00") | hex!("B6 03 84 01 01") => Ok(KeyType::Sign),
            hex!("B8 00") | hex!("B8 03 84 01 02") => Ok(KeyType::Confidentiality),
            hex!("A4 00") | hex!("A4 03 84 01 03") => Ok(KeyType::Aut),
            _ => Err(Status::KeyReferenceNotFound),
        }
    }
}
