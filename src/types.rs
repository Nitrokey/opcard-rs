// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use hex_literal::hex;
use iso7816::Status;
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::error::Error;

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

#[derive(Debug, Copy, Clone)]
pub struct AlgorithmFromAttributesError;

iterable_enum! {
    #[derive(Serialize_repr, Deserialize_repr, Clone, Copy, PartialEq, Eq, Debug)]
    #[repr(u8)]
    pub enum SignatureAlgorithm {
        // Part of draft https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/
        Ed255,
        EcDsaP256,
        Rsa2k,
        Rsa4k,
    }
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::Rsa2k
    }
}

impl SignatureAlgorithm {
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

impl TryFrom<&[u8]> for SignatureAlgorithm {
    type Error = AlgorithmFromAttributesError;

    fn try_from(v: &[u8]) -> Result<SignatureAlgorithm, AlgorithmFromAttributesError> {
        match v {
            ED255_ATTRIBUTES => Ok(Self::Ed255),
            ECDSA_P256_ATTRIBUTES => Ok(Self::EcDsaP256),
            RSA_2K_ATTRIBUTES => Ok(Self::Rsa2k),
            RSA_4K_ATTRIBUTES => Ok(Self::Rsa4k),
            _ => Err(AlgorithmFromAttributesError),
        }
    }
}

iterable_enum! {
    #[derive(Serialize_repr, Deserialize_repr, Clone, Copy, PartialEq, Eq, Debug)]
    #[repr(u8)]
    pub enum DecryptionAlgorithm {
        // Part of draft https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/
        X255,
        EcDhP256,
        Rsa2k,
        Rsa4k,
    }
}

impl Default for DecryptionAlgorithm {
    fn default() -> Self {
        Self::Rsa2k
    }
}

impl DecryptionAlgorithm {
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

impl TryFrom<&[u8]> for DecryptionAlgorithm {
    type Error = AlgorithmFromAttributesError;

    fn try_from(v: &[u8]) -> Result<DecryptionAlgorithm, AlgorithmFromAttributesError> {
        match v {
            X255_ATTRIBUTES => Ok(Self::X255),
            ECDH_P256_ATTRIBUTES => Ok(Self::EcDhP256),
            RSA_2K_ATTRIBUTES => Ok(Self::Rsa2k),
            RSA_4K_ATTRIBUTES => Ok(Self::Rsa4k),
            _ => Err(AlgorithmFromAttributesError),
        }
    }
}

iterable_enum! {
    #[derive(Serialize_repr, Deserialize_repr, Clone, Copy, PartialEq, Eq, Debug)]
    #[repr(u8)]
    pub enum AuthenticationAlgorithm {
        // Part of draft https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/
        Ed255,
        EcDsaP256,
        Rsa2k,
        Rsa4k,
    }
}

impl Default for AuthenticationAlgorithm {
    fn default() -> Self {
        Self::Rsa2k
    }
}

impl AuthenticationAlgorithm {
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

impl TryFrom<&[u8]> for AuthenticationAlgorithm {
    type Error = AlgorithmFromAttributesError;

    fn try_from(v: &[u8]) -> Result<AuthenticationAlgorithm, AlgorithmFromAttributesError> {
        match v {
            ED255_ATTRIBUTES => Ok(Self::Ed255),
            ECDSA_P256_ATTRIBUTES => Ok(Self::EcDsaP256),
            RSA_2K_ATTRIBUTES => Ok(Self::Rsa2k),
            RSA_4K_ATTRIBUTES => Ok(Self::Rsa4k),
            _ => Err(AlgorithmFromAttributesError),
        }
    }
}

#[derive(Clone, Debug, Copy)]
#[allow(unused)]
pub enum KeyType {
    Sign,
    Dec,
    Aut,
}

impl KeyType {
    #[allow(unused)]
    pub fn try_from_crt(v: &[u8]) -> Result<Self, Status> {
        match v {
            hex!("B6 00") | hex!("B6 03 84 01 01") => Ok(KeyType::Sign),
            hex!("B8 00") | hex!("B8 03 84 01 02") => Ok(KeyType::Dec),
            hex!("A4 00") | hex!("A4 03 84 01 03") => Ok(KeyType::Aut),
            _ => Err(Status::KeyReferenceNotFound),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Copy, Deserialize_repr, Serialize_repr)]
#[repr(u8)]
pub enum Uif {
    Disabled = 0,
    Enabled = 1,
    PermanentlyEnabled = 2,
}

impl Default for Uif {
    fn default() -> Self {
        Uif::Disabled
    }
}

impl TryFrom<u8> for Uif {
    type Error = Error;
    fn try_from(v: u8) -> Result<Uif, Error> {
        match v {
            0 => Ok(Uif::Disabled),
            1 => Ok(Uif::Enabled),
            2 => Ok(Uif::PermanentlyEnabled),
            _ => Err(Error::BadRequest),
        }
    }
}

impl Uif {
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    pub fn is_enabled(self) -> bool {
        matches!(self, Uif::Enabled | Uif::PermanentlyEnabled)
    }
}

/// Instace of a curDO pointer. Guaranteed to be <3
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum Occurrence {
    First = 0,
    Second = 1,
    Third = 2,
}

impl TryFrom<u8> for Occurrence {
    type Error = Status;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Occurrence::First),
            1 => Ok(Occurrence::Second),
            2 => Ok(Occurrence::Third),
            _ => Err(Status::IncorrectP1OrP2Parameter),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tag(pub u16);

impl From<(u8, u8)> for Tag {
    fn from((p1, p2): (u8, u8)) -> Self {
        Self(u16::from_be_bytes([p1, p2]))
    }
}

impl From<u8> for Tag {
    fn from(p1: u8) -> Self {
        Self(p1.into())
    }
}

impl<const C: usize> From<&iso7816::Command<C>> for Tag {
    fn from(command: &iso7816::Command<C>) -> Self {
        Self::from((command.p1, command.p2))
    }
}
