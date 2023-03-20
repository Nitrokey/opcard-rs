// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use hex_literal::hex;
use iso7816::Status;
use serde_repr::{Deserialize_repr, Serialize_repr};
use trussed::types::Mechanism;

use crate::error::Error;
use crate::tlv::get_do;

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
    00   // import in standard format
").as_slice();
const RSA_3K_ATTRIBUTES: &[u8] = hex!("
    01
    0C00 // Length modulus (in bit): 2048                                                                                                                                        
    0020 // Length exponent (in bit): 32
    00   // import in standard format
").as_slice();
const RSA_4K_ATTRIBUTES: &[u8] = hex!(
    "
    01
    1000 // Length modulus (in bit): 4096
    0020 // Length exponent (in bit): 32
    00   // import in standard format
"
)
.as_slice();
const RSA_2K_ATTRIBUTES_CRT: &[u8] = hex!("
    01
    0800 // Length modulus (in bit): 2048                                                                                                                                        
    0020 // Length exponent (in bit): 32
    02   // import in CRT Format
").as_slice();
const RSA_3K_ATTRIBUTES_CRT: &[u8] = hex!("
    01
    0C00 // Length modulus (in bit): 2048                                                                                                                                        
    0020 // Length exponent (in bit): 32
    02   // import in CRT Format
").as_slice();
const RSA_4K_ATTRIBUTES_CRT: &[u8] = hex!(
    "
    01
    1000 // Length modulus (in bit): 4096
    0020 // Length exponent (in bit): 32
    02   // import in CRT Format
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
        Rsa2048,
        Rsa3072,
        Rsa4096,
    }
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::Rsa2048
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
            Self::Rsa2048 => RSA_2K_ATTRIBUTES,
            Self::Rsa3072 => RSA_3K_ATTRIBUTES,
            Self::Rsa4096 => RSA_4K_ATTRIBUTES,
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
            RSA_2K_ATTRIBUTES | RSA_2K_ATTRIBUTES_CRT => Ok(Self::Rsa2048),
            RSA_3K_ATTRIBUTES | RSA_3K_ATTRIBUTES_CRT => Ok(Self::Rsa3072),
            RSA_4K_ATTRIBUTES | RSA_4K_ATTRIBUTES_CRT => Ok(Self::Rsa4096),
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
        Rsa2048,
        Rsa3072,
        Rsa4096,
    }
}

impl Default for DecryptionAlgorithm {
    fn default() -> Self {
        Self::Rsa2048
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
            Self::Rsa2048 => RSA_2K_ATTRIBUTES,
            Self::Rsa3072 => RSA_3K_ATTRIBUTES,
            Self::Rsa4096 => RSA_4K_ATTRIBUTES,
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
            RSA_2K_ATTRIBUTES | RSA_2K_ATTRIBUTES_CRT => Ok(Self::Rsa2048),
            RSA_3K_ATTRIBUTES | RSA_3K_ATTRIBUTES_CRT => Ok(Self::Rsa3072),
            RSA_4K_ATTRIBUTES | RSA_4K_ATTRIBUTES_CRT => Ok(Self::Rsa4096),
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
        Rsa2048,
        Rsa3072,
        Rsa4096,
    }
}

impl Default for AuthenticationAlgorithm {
    fn default() -> Self {
        Self::Rsa2048
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
            Self::Rsa2048 => RSA_2K_ATTRIBUTES,
            Self::Rsa3072 => RSA_3K_ATTRIBUTES,
            Self::Rsa4096 => RSA_4K_ATTRIBUTES,
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
            RSA_2K_ATTRIBUTES | RSA_2K_ATTRIBUTES_CRT => Ok(Self::Rsa2048),
            RSA_3K_ATTRIBUTES | RSA_3K_ATTRIBUTES_CRT => Ok(Self::Rsa3072),
            RSA_4K_ATTRIBUTES | RSA_4K_ATTRIBUTES_CRT => Ok(Self::Rsa4096),
            _ => Err(AlgorithmFromAttributesError),
        }
    }
}

#[derive(Clone, Debug, Copy)]
pub enum KeyType {
    Sign,
    Dec,
    Aut,
}

impl KeyType {
    pub fn try_from_crt(data: &[u8]) -> Result<Self, Status> {
        if let Some(d) = get_do(&[0xB6], data) {
            if !matches!(d, [] | hex!("84 01 01")) {
                warn!("Incorrect CRT for Sign key");
                return Err(Status::IncorrectDataParameter);
            }
            Ok(KeyType::Sign)
        } else if let Some(d) = get_do(&[0xB8], data) {
            if !matches!(d, [] | hex!("84 01 02")) {
                warn!("Incorrect CRT for DEC key");
                return Err(Status::IncorrectDataParameter);
            }
            Ok(KeyType::Dec)
        } else if let Some(d) = get_do(&[0xA4], data) {
            if !matches!(d, [] | hex!("84 01 03")) {
                warn!("Incorrect CRT for AUT key");
                return Err(Status::IncorrectDataParameter);
            }
            Ok(KeyType::Aut)
        } else {
            Err(Status::IncorrectDataParameter)
        }
    }

    pub fn path(&self) -> &'static str {
        match self {
            KeyType::Sign => crate::state::SIGNING_KEY_PATH,
            KeyType::Aut => crate::state::AUTH_KEY_PATH,
            KeyType::Dec => crate::state::DEC_KEY_PATH,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Copy, Deserialize_repr, Serialize_repr, Default)]
#[repr(u8)]
pub enum Uif {
    #[default]
    Disabled = 0,
    Enabled = 1,
    PermanentlyEnabled = 2,
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

#[derive(Debug, Copy, Clone)]
pub enum CurveAlgo {
    EcDhP256,
    EcDsaP256,
    X255,
    Ed255,
}

impl CurveAlgo {
    pub fn mechanism(self) -> Mechanism {
        match self {
            Self::EcDsaP256 | Self::EcDhP256 => Mechanism::P256,
            Self::X255 => Mechanism::X255,
            Self::Ed255 => Mechanism::Ed255,
        }
    }
}
