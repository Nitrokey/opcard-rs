// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use hex_literal::hex;
use iso7816::Status;
use littlefs2_core::Path;
use serde_repr::{Deserialize_repr, Serialize_repr};
use trussed_core::types::Mechanism;

use crate::card::AllowedAlgorithms;
use crate::error::Error;
use crate::tlv::get_do;

/// Creates an enum with an `iter_all` associated function giving an iterator over all variants
macro_rules! iterable_enum {
    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident {
            $($var:ident $(= $val:literal)?),+
            $(,)*
        }
    ) => {
        $(#[$outer])*
        $vis enum $name {
            $(
                $var $(= $val)?,
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

macro_rules! iterable_sub_enum {

    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident($parent:ident) {
            $($var:ident $(= $val:literal)?),+
            $(,)*
        }
    ) => {
        $(#[$outer])*
        $vis enum $name {
            $(
                $var $(= $val)?,
            )*
        }

        impl From<$name> for $parent {
            fn from(value: $name) -> $parent {
                match value {
                    $(
                        $name::$var => $parent::$var,
                    )*
                }
            }
        }

        impl TryFrom<$parent> for $name {
            type Error = AlgorithmFromAttributesError;
            fn try_from(value: $parent) -> Result<$name, AlgorithmFromAttributesError> {
                match value {
                    $(
                        $parent::$var => Ok($name::$var),
                    )*
                    _ => Err(AlgorithmFromAttributesError),
                }
            }
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

const ED255_ATTRIBUTES: &[u8] = hex!("162B06010401DA470F01").as_slice();
const ED255_ATTRIBUTES_PK: &[u8] = hex!("162B06010401DA470F01 FF").as_slice();
const ECDSA_P256_ATTRIBUTES: &[u8] = hex!("132A8648CE3D030107").as_slice();
const ECDSA_P384_ATTRIBUTES: &[u8] = hex!("132b81040022").as_slice();
const ECDSA_P521_ATTRIBUTES: &[u8] = hex!("132b81040023").as_slice();
const ECDSA_P256_ATTRIBUTES_PK: &[u8] = hex!("132A8648CE3D030107 FF").as_slice();
const ECDSA_P384_ATTRIBUTES_PK: &[u8] = hex!("132b81040022 FF").as_slice();
const ECDSA_P521_ATTRIBUTES_PK: &[u8] = hex!("132b81040023 FF").as_slice();
const ECDSA_SECP256K1_ATTRIBUTES: &[u8] = hex!("132B8104000A").as_slice();
const ECDSA_SECP256K1_ATTRIBUTES_PK: &[u8] = hex!("132B8104000A FF").as_slice();
const ECDSA_BRAINPOOL_P256R1_ATTRIBUTES: &[u8] = hex!("132b2403030208010107").as_slice();
const ECDSA_BRAINPOOL_P384R1_ATTRIBUTES: &[u8] = hex!("132b240303020801010b").as_slice();
const ECDSA_BRAINPOOL_P512R1_ATTRIBUTES: &[u8] = hex!("132b240303020801010d").as_slice();
const ECDSA_BRAINPOOL_P256R1_ATTRIBUTES_PK: &[u8] = hex!("132b2403030208010107 FF").as_slice();
const ECDSA_BRAINPOOL_P384R1_ATTRIBUTES_PK: &[u8] = hex!("132b240303020801010b FF").as_slice();
const ECDSA_BRAINPOOL_P512R1_ATTRIBUTES_PK: &[u8] = hex!("132b240303020801010d FF").as_slice();
const ECDH_P256_ATTRIBUTES: &[u8] = hex!("122A8648CE3D030107").as_slice();
const ECDH_P384_ATTRIBUTES: &[u8] = hex!("122b81040022").as_slice();
const ECDH_P521_ATTRIBUTES: &[u8] = hex!("122b81040023").as_slice();
const ECDH_P256_ATTRIBUTES_PK: &[u8] = hex!("122A8648CE3D030107 FF").as_slice();
const ECDH_P384_ATTRIBUTES_PK: &[u8] = hex!("122b81040022 FF").as_slice();
const ECDH_P521_ATTRIBUTES_PK: &[u8] = hex!("122b81040023 FF").as_slice();
const ECDH_SECP256K1_ATTRIBUTES: &[u8] = hex!("122B8104000A").as_slice();
const ECDH_SECP256K1_ATTRIBUTES_PK: &[u8] = hex!("122B8104000A FF").as_slice();
const ECDH_BRAINPOOL_P256R1_ATTRIBUTES: &[u8] = hex!("122b2403030208010107").as_slice();
const ECDH_BRAINPOOL_P384R1_ATTRIBUTES: &[u8] = hex!("122b240303020801010b").as_slice();
const ECDH_BRAINPOOL_P512R1_ATTRIBUTES: &[u8] = hex!("122b240303020801010d").as_slice();
const ECDH_BRAINPOOL_P256R1_ATTRIBUTES_PK: &[u8] = hex!("122b2403030208010107 FF").as_slice();
const ECDH_BRAINPOOL_P384R1_ATTRIBUTES_PK: &[u8] = hex!("122b240303020801010b FF").as_slice();
const ECDH_BRAINPOOL_P512R1_ATTRIBUTES_PK: &[u8] = hex!("122b240303020801010d FF").as_slice();
const X255_ATTRIBUTES: &[u8] = hex!("12 2B 06 01 04 01 97 55 01 05 01").as_slice();
const X255_ATTRIBUTES_PK: &[u8] = hex!("12 2B 06 01 04 01 97 55 01 05 01 FF").as_slice();
const RSA_2K_ATTRIBUTES: &[u8] = hex!(
    "01"
    "0800" // Length modulus (in bit): 2048
    "0020" // Length exponent (in bit): 32
    "00"   // import in standard format
)
.as_slice();
const RSA_3K_ATTRIBUTES: &[u8] = hex!(
    "01"
    "0C00" // Length modulus (in bit): 2048
    "0020" // Length exponent (in bit): 32
    "00"   // import in standard format
)
.as_slice();
const RSA_4K_ATTRIBUTES: &[u8] = hex!(
    "01"
    "1000" // Length modulus (in bit): 4096
    "0020" // Length exponent (in bit): 32
    "00"   // import in standard format
)
.as_slice();
const RSA_2K_ATTRIBUTES_CRT: &[u8] = hex!(
    "01"
    "0800" // Length modulus (in bit): 2048
    "0020" // Length exponent (in bit): 32
    "02"   // import in CRT Format
)
.as_slice();
const RSA_3K_ATTRIBUTES_CRT: &[u8] = hex!(
    "01"
    "0C00" // Length modulus (in bit): 2048
    "0020" // Length exponent (in bit): 32
    "02"   // import in CRT Format
)
.as_slice();
const RSA_4K_ATTRIBUTES_CRT: &[u8] = hex!(
    "01"
    "1000" // Length modulus (in bit): 4096
    "0020" // Length exponent (in bit): 32
    "02"   // import in CRT Format

)
.as_slice();

#[derive(Debug, Copy, Clone)]
pub struct AlgorithmFromAttributesError;

iterable_enum! {
    #[derive(Serialize_repr, Deserialize_repr, Clone, Copy, PartialEq, Eq, Debug)]
    #[repr(u8)]
    pub enum Algorithm {
        X255 = 0,
        Ed255 = 1,
        EcDhP256 = 2,
        EcDsaP256 = 3,
        Rsa2048 = 4,
        Rsa3072 = 5,
        Rsa4096 = 6,
        EcDhP384 = 7,
        EcDsaP384 = 8,
        EcDhP521 = 9,
        EcDsaP521 = 10,
        EcDhBrainpoolP256R1 = 11,
        EcDsaBrainpoolP256R1 = 12,
        EcDhBrainpoolP384R1 = 13,
        EcDsaBrainpoolP384R1 = 14,
        EcDhBrainpoolP512R1 = 15,
        EcDsaBrainpoolP512R1 = 16,
        EcDhSecp256k1 = 17,
        EcDsaSecp256k1 = 18,
    }
}

impl TryFrom<&[u8]> for Algorithm {
    type Error = AlgorithmFromAttributesError;

    fn try_from(v: &[u8]) -> Result<Self, AlgorithmFromAttributesError> {
        match v {
            X255_ATTRIBUTES | X255_ATTRIBUTES_PK => Ok(Self::X255),
            ED255_ATTRIBUTES | ED255_ATTRIBUTES_PK => Ok(Self::Ed255),
            ECDH_P256_ATTRIBUTES | ECDH_P256_ATTRIBUTES_PK => Ok(Self::EcDhP256),
            ECDSA_P256_ATTRIBUTES | ECDSA_P256_ATTRIBUTES_PK => Ok(Self::EcDsaP256),
            ECDH_P384_ATTRIBUTES | ECDH_P384_ATTRIBUTES_PK => Ok(Self::EcDhP384),
            ECDSA_P384_ATTRIBUTES | ECDSA_P384_ATTRIBUTES_PK => Ok(Self::EcDsaP384),
            ECDH_P521_ATTRIBUTES | ECDH_P521_ATTRIBUTES_PK => Ok(Self::EcDhP521),
            ECDSA_P521_ATTRIBUTES | ECDSA_P521_ATTRIBUTES_PK => Ok(Self::EcDsaP521),
            ECDSA_SECP256K1_ATTRIBUTES | ECDSA_SECP256K1_ATTRIBUTES_PK => Ok(Self::EcDsaSecp256k1),
            ECDH_SECP256K1_ATTRIBUTES | ECDH_SECP256K1_ATTRIBUTES_PK => Ok(Self::EcDhSecp256k1),
            ECDH_BRAINPOOL_P256R1_ATTRIBUTES | ECDH_BRAINPOOL_P256R1_ATTRIBUTES_PK => {
                Ok(Self::EcDhBrainpoolP256R1)
            }
            ECDSA_BRAINPOOL_P256R1_ATTRIBUTES | ECDSA_BRAINPOOL_P256R1_ATTRIBUTES_PK => {
                Ok(Self::EcDsaBrainpoolP256R1)
            }
            ECDH_BRAINPOOL_P384R1_ATTRIBUTES | ECDH_BRAINPOOL_P384R1_ATTRIBUTES_PK => {
                Ok(Self::EcDhBrainpoolP384R1)
            }
            ECDSA_BRAINPOOL_P384R1_ATTRIBUTES | ECDSA_BRAINPOOL_P384R1_ATTRIBUTES_PK => {
                Ok(Self::EcDsaBrainpoolP384R1)
            }
            ECDH_BRAINPOOL_P512R1_ATTRIBUTES | ECDH_BRAINPOOL_P512R1_ATTRIBUTES_PK => {
                Ok(Self::EcDhBrainpoolP512R1)
            }
            ECDSA_BRAINPOOL_P512R1_ATTRIBUTES | ECDSA_BRAINPOOL_P512R1_ATTRIBUTES_PK => {
                Ok(Self::EcDsaBrainpoolP512R1)
            }
            RSA_2K_ATTRIBUTES | RSA_2K_ATTRIBUTES_CRT => Ok(Self::Rsa2048),
            RSA_3K_ATTRIBUTES | RSA_3K_ATTRIBUTES_CRT => Ok(Self::Rsa3072),
            RSA_4K_ATTRIBUTES | RSA_4K_ATTRIBUTES_CRT => Ok(Self::Rsa4096),
            _ => Err(AlgorithmFromAttributesError),
        }
    }
}

impl Algorithm {
    pub fn id(&self) -> u8 {
        self.attributes()[0]
    }

    pub fn is_rsa(&self) -> bool {
        matches!(self, Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096)
    }

    pub fn attributes(&self) -> &'static [u8] {
        match self {
            Self::X255 => X255_ATTRIBUTES_PK,
            Self::Ed255 => ED255_ATTRIBUTES_PK,
            Self::EcDhP256 => ECDH_P256_ATTRIBUTES_PK,
            Self::EcDsaP256 => ECDSA_P256_ATTRIBUTES_PK,
            Self::EcDhP384 => ECDH_P384_ATTRIBUTES_PK,
            Self::EcDsaP384 => ECDSA_P384_ATTRIBUTES_PK,
            Self::EcDhP521 => ECDH_P521_ATTRIBUTES_PK,
            Self::EcDsaP521 => ECDSA_P521_ATTRIBUTES_PK,
            Self::EcDhSecp256k1 => ECDH_SECP256K1_ATTRIBUTES_PK,
            Self::EcDsaSecp256k1 => ECDSA_SECP256K1_ATTRIBUTES_PK,
            Self::EcDhBrainpoolP256R1 => ECDH_BRAINPOOL_P256R1_ATTRIBUTES_PK,
            Self::EcDsaBrainpoolP256R1 => ECDSA_BRAINPOOL_P256R1_ATTRIBUTES_PK,
            Self::EcDhBrainpoolP384R1 => ECDH_BRAINPOOL_P384R1_ATTRIBUTES_PK,
            Self::EcDsaBrainpoolP384R1 => ECDSA_BRAINPOOL_P384R1_ATTRIBUTES_PK,
            Self::EcDhBrainpoolP512R1 => ECDH_BRAINPOOL_P512R1_ATTRIBUTES_PK,
            Self::EcDsaBrainpoolP512R1 => ECDSA_BRAINPOOL_P512R1_ATTRIBUTES_PK,
            Self::Rsa2048 => RSA_2K_ATTRIBUTES,
            Self::Rsa3072 => RSA_3K_ATTRIBUTES,
            Self::Rsa4096 => RSA_4K_ATTRIBUTES,
        }
    }

    pub fn oid(&self) -> &'static [u8] {
        &self.attributes()[1..]
    }

    pub fn is_allowed(&self, allowed: AllowedAlgorithms) -> bool {
        match self {
            Self::X255 => allowed.contains(AllowedAlgorithms::X_25519),
            Self::Ed255 => allowed.contains(AllowedAlgorithms::ED_25519),
            Self::EcDhP256 => allowed.contains(AllowedAlgorithms::P_256),
            Self::EcDsaP256 => allowed.contains(AllowedAlgorithms::P_256),
            Self::EcDhP384 => allowed.contains(AllowedAlgorithms::P_384),
            Self::EcDsaP384 => allowed.contains(AllowedAlgorithms::P_384),
            Self::EcDhP521 => allowed.contains(AllowedAlgorithms::P_521),
            Self::EcDsaP521 => allowed.contains(AllowedAlgorithms::P_521),
            Self::EcDsaSecp256k1 => allowed.contains(AllowedAlgorithms::SECP256K1),
            Self::EcDhSecp256k1 => allowed.contains(AllowedAlgorithms::SECP256K1),
            Self::EcDhBrainpoolP256R1 => allowed.contains(AllowedAlgorithms::BRAINPOOL_P256R1),
            Self::EcDsaBrainpoolP256R1 => allowed.contains(AllowedAlgorithms::BRAINPOOL_P256R1),
            Self::EcDhBrainpoolP384R1 => allowed.contains(AllowedAlgorithms::BRAINPOOL_P384R1),
            Self::EcDsaBrainpoolP384R1 => allowed.contains(AllowedAlgorithms::BRAINPOOL_P384R1),
            Self::EcDhBrainpoolP512R1 => allowed.contains(AllowedAlgorithms::BRAINPOOL_P512R1),
            Self::EcDsaBrainpoolP512R1 => allowed.contains(AllowedAlgorithms::BRAINPOOL_P512R1),
            Self::Rsa2048 => allowed.contains(AllowedAlgorithms::RSA_2048),
            Self::Rsa3072 => allowed.contains(AllowedAlgorithms::RSA_3072),
            Self::Rsa4096 => allowed.contains(AllowedAlgorithms::RSA_4096),
        }
    }
}

iterable_sub_enum! {
    #[derive(Serialize_repr, Deserialize_repr, Clone, Copy, PartialEq, Eq, Debug)]
    #[repr(u8)]
    pub enum SignatureAlgorithm(Algorithm) {
        // Part of draft https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/
        Ed255 = 0,
        EcDsaP256 = 1,
        Rsa2048 = 2,
        Rsa3072 = 3,
        Rsa4096 = 4,
        EcDsaP384 = 5,
        EcDsaP521 = 6,
        EcDsaBrainpoolP256R1 = 7,
        EcDsaBrainpoolP384R1 = 8,
        EcDsaBrainpoolP512R1 = 9,
        EcDsaSecp256k1 = 10,
    }
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::Rsa2048
    }
}

impl SignatureAlgorithm {
    pub fn as_algorithm(self) -> Algorithm {
        self.into()
    }
    #[allow(unused)]
    pub fn id(&self) -> u8 {
        self.as_algorithm().id()
    }

    pub fn is_rsa(&self) -> bool {
        self.as_algorithm().is_rsa()
    }

    pub fn attributes(&self) -> &'static [u8] {
        self.as_algorithm().attributes()
    }

    #[allow(unused)]
    pub fn oid(&self) -> &'static [u8] {
        self.as_algorithm().oid()
    }

    pub fn is_allowed(&self, allowed: AllowedAlgorithms) -> bool {
        self.as_algorithm().is_allowed(allowed)
    }
}

impl TryFrom<&[u8]> for SignatureAlgorithm {
    type Error = AlgorithmFromAttributesError;

    fn try_from(v: &[u8]) -> Result<SignatureAlgorithm, AlgorithmFromAttributesError> {
        Algorithm::try_from(v)?.try_into()
    }
}

iterable_sub_enum! {
    #[derive(Serialize_repr, Deserialize_repr, Clone, Copy, PartialEq, Eq, Debug)]
    #[repr(u8)]
    pub enum DecryptionAlgorithm(Algorithm) {
        // Part of draft https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/
        X255 = 0,
        EcDhP256 = 1,
        Rsa2048 = 2,
        Rsa3072 = 3,
        Rsa4096 = 4,
        EcDhP384 = 5,
        EcDhP521 = 6,
        EcDhBrainpoolP256R1 = 7,
        EcDhBrainpoolP384R1 = 8,
        EcDhBrainpoolP512R1 = 9,
        EcDhSecp256k1 = 10,
    }
}

impl Default for DecryptionAlgorithm {
    fn default() -> Self {
        Self::Rsa2048
    }
}

impl DecryptionAlgorithm {
    pub fn as_algorithm(self) -> Algorithm {
        self.into()
    }
    #[allow(unused)]
    pub fn id(&self) -> u8 {
        self.as_algorithm().id()
    }

    pub fn is_rsa(&self) -> bool {
        self.as_algorithm().is_rsa()
    }

    pub fn attributes(&self) -> &'static [u8] {
        self.as_algorithm().attributes()
    }

    #[allow(unused)]
    pub fn oid(&self) -> &'static [u8] {
        self.as_algorithm().oid()
    }

    pub fn is_allowed(&self, allowed: AllowedAlgorithms) -> bool {
        self.as_algorithm().is_allowed(allowed)
    }
}

impl TryFrom<&[u8]> for DecryptionAlgorithm {
    type Error = AlgorithmFromAttributesError;

    fn try_from(v: &[u8]) -> Result<DecryptionAlgorithm, AlgorithmFromAttributesError> {
        Algorithm::try_from(v)?.try_into()
    }
}

iterable_sub_enum! {
    #[derive(Serialize_repr, Deserialize_repr, Clone, Copy, PartialEq, Eq, Debug)]
    #[repr(u8)]
    pub enum AuthenticationAlgorithm(Algorithm) {
        // Part of draft https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/
        Ed255 = 0,
        EcDsaP256 = 1,
        Rsa2048 = 2,
        Rsa3072 = 3,
        Rsa4096 = 4,
        EcDsaP384 = 5,
        EcDsaP521 = 6,
        EcDsaBrainpoolP256R1 = 7,
        EcDsaBrainpoolP384R1 = 8,
        EcDsaBrainpoolP512R1 = 9,
        EcDsaSecp256k1,
    }
}

impl Default for AuthenticationAlgorithm {
    fn default() -> Self {
        Self::Rsa2048
    }
}

impl AuthenticationAlgorithm {
    pub fn as_algorithm(self) -> Algorithm {
        self.into()
    }
    #[allow(unused)]
    pub fn id(&self) -> u8 {
        self.as_algorithm().id()
    }

    pub fn is_rsa(&self) -> bool {
        self.as_algorithm().is_rsa()
    }

    pub fn attributes(&self) -> &'static [u8] {
        self.as_algorithm().attributes()
    }

    #[allow(unused)]
    pub fn oid(&self) -> &'static [u8] {
        self.as_algorithm().oid()
    }

    pub fn is_allowed(&self, allowed: AllowedAlgorithms) -> bool {
        self.as_algorithm().is_allowed(allowed)
    }
}

impl TryFrom<&[u8]> for AuthenticationAlgorithm {
    type Error = AlgorithmFromAttributesError;

    fn try_from(v: &[u8]) -> Result<AuthenticationAlgorithm, AlgorithmFromAttributesError> {
        Algorithm::try_from(v)?.try_into()
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
        const SIGN: &[u8] = &hex!("84 01 01");
        const DEC: &[u8] = &hex!("84 01 02");
        const AUT: &[u8] = &hex!("84 01 03");
        if let Some(d) = get_do(&[0xB6], data) {
            if !matches!(d, [] | SIGN) {
                warn!("Incorrect CRT for Sign key");
                return Err(Status::IncorrectDataParameter);
            }
            Ok(KeyType::Sign)
        } else if let Some(d) = get_do(&[0xB8], data) {
            if !matches!(d, [] | DEC) {
                warn!("Incorrect CRT for DEC key");
                return Err(Status::IncorrectDataParameter);
            }
            Ok(KeyType::Dec)
        } else if let Some(d) = get_do(&[0xA4], data) {
            if !matches!(d, [] | AUT) {
                warn!("Incorrect CRT for AUT key");
                return Err(Status::IncorrectDataParameter);
            }
            Ok(KeyType::Aut)
        } else {
            Err(Status::IncorrectDataParameter)
        }
    }

    pub fn path(&self) -> &'static Path {
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

impl From<iso7816::command::CommandView<'_>> for Tag {
    fn from(command: iso7816::command::CommandView<'_>) -> Self {
        Self::from((command.p1, command.p2))
    }
}

#[derive(Debug, Copy, Clone)]
pub enum CurveAlgo {
    EcDhP256,
    EcDsaP256,
    EcDhP384,
    EcDsaP384,
    EcDhP521,
    EcDsaP521,
    EcDhBrainpoolP256R1,
    EcDsaBrainpoolP256R1,
    EcDhBrainpoolP384R1,
    EcDsaBrainpoolP384R1,
    EcDhBrainpoolP512R1,
    EcDsaBrainpoolP512R1,
    EcDsaSecp256k1,
    EcDhSecp256k1,
    X255,
    Ed255,
}

impl CurveAlgo {
    pub fn mechanism(self) -> Mechanism {
        match self {
            Self::EcDsaP256 | Self::EcDhP256 => Mechanism::P256,
            Self::EcDsaP384 | Self::EcDhP384 => Mechanism::P384,
            Self::EcDsaP521 | Self::EcDhP521 => Mechanism::P521,
            Self::EcDsaBrainpoolP256R1 | Self::EcDhBrainpoolP256R1 => Mechanism::BrainpoolP256R1,
            Self::EcDsaBrainpoolP384R1 | Self::EcDhBrainpoolP384R1 => Mechanism::BrainpoolP384R1,
            Self::EcDsaBrainpoolP512R1 | Self::EcDhBrainpoolP512R1 => Mechanism::BrainpoolP512R1,
            Self::X255 => Mechanism::X255,
            Self::Ed255 => Mechanism::Ed255,
            Self::EcDsaSecp256k1 | Self::EcDhSecp256k1 => Mechanism::Secp256k1,
        }
    }

    pub fn public_key_header(self) -> u8 {
        match self {
            Self::EcDsaP256 | Self::EcDhP256 => 0x04,
            Self::EcDsaP384 | Self::EcDhP384 => 0x04,
            Self::EcDsaP521 | Self::EcDhP521 => 0x04,
            Self::EcDsaBrainpoolP256R1 | Self::EcDhBrainpoolP256R1 => 0x04,
            Self::EcDsaBrainpoolP384R1 | Self::EcDhBrainpoolP384R1 => 0x04,
            Self::EcDsaBrainpoolP512R1 | Self::EcDhBrainpoolP512R1 => 0x04,
            Self::EcDsaSecp256k1 | Self::EcDhSecp256k1 => 0x04,
            Self::X255 | Self::Ed255 => 0x40,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_test::{assert_tokens, Token};

    #[test]
    fn asssert_alg_values() {
        assert_eq!(Algorithm::X255 as u8, 0);
        assert_eq!(Algorithm::Ed255 as u8, 1);
        assert_eq!(Algorithm::EcDhP256 as u8, 2);
        assert_eq!(Algorithm::EcDsaP256 as u8, 3);
        assert_eq!(Algorithm::Rsa2048 as u8, 4);
        assert_eq!(Algorithm::Rsa3072 as u8, 5);
        assert_eq!(Algorithm::Rsa4096 as u8, 6);
        assert_eq!(Algorithm::EcDhP384 as u8, 7);
        assert_eq!(Algorithm::EcDsaP384 as u8, 8);
        assert_eq!(Algorithm::EcDhP521 as u8, 9);
        assert_eq!(Algorithm::EcDsaP521 as u8, 10);
        assert_eq!(Algorithm::EcDhBrainpoolP256R1 as u8, 11);
        assert_eq!(Algorithm::EcDsaBrainpoolP256R1 as u8, 12);
        assert_eq!(Algorithm::EcDhBrainpoolP384R1 as u8, 13);
        assert_eq!(Algorithm::EcDsaBrainpoolP384R1 as u8, 14);
        assert_eq!(Algorithm::EcDhBrainpoolP512R1 as u8, 15);
        assert_eq!(Algorithm::EcDsaBrainpoolP512R1 as u8, 16);
        assert_eq!(Algorithm::EcDhSecp256k1 as u8, 17);
        assert_eq!(Algorithm::EcDsaSecp256k1 as u8, 18);

        assert_tokens(&Algorithm::X255, &[Token::U8(0)]);
        assert_tokens(&Algorithm::Ed255, &[Token::U8(1)]);
        assert_tokens(&Algorithm::EcDhP256, &[Token::U8(2)]);
        assert_tokens(&Algorithm::EcDsaP256, &[Token::U8(3)]);
        assert_tokens(&Algorithm::Rsa2048, &[Token::U8(4)]);
        assert_tokens(&Algorithm::Rsa3072, &[Token::U8(5)]);
        assert_tokens(&Algorithm::Rsa4096, &[Token::U8(6)]);
        assert_tokens(&Algorithm::EcDhP384, &[Token::U8(7)]);
        assert_tokens(&Algorithm::EcDsaP384, &[Token::U8(8)]);
        assert_tokens(&Algorithm::EcDhP521, &[Token::U8(9)]);
        assert_tokens(&Algorithm::EcDsaP521, &[Token::U8(10)]);
        assert_tokens(&Algorithm::EcDhBrainpoolP256R1, &[Token::U8(11)]);
        assert_tokens(&Algorithm::EcDsaBrainpoolP256R1, &[Token::U8(12)]);
        assert_tokens(&Algorithm::EcDhBrainpoolP384R1, &[Token::U8(13)]);
        assert_tokens(&Algorithm::EcDsaBrainpoolP384R1, &[Token::U8(14)]);
        assert_tokens(&Algorithm::EcDhBrainpoolP512R1, &[Token::U8(15)]);
        assert_tokens(&Algorithm::EcDsaBrainpoolP512R1, &[Token::U8(16)]);
        assert_tokens(&Algorithm::EcDhSecp256k1, &[Token::U8(17)]);
        assert_tokens(&Algorithm::EcDsaSecp256k1, &[Token::U8(18)]);
    }

    #[test]
    fn asssert_sign_values() {
        assert_eq!(SignatureAlgorithm::Ed255 as u8, 0);
        assert_eq!(SignatureAlgorithm::EcDsaP256 as u8, 1);
        assert_eq!(SignatureAlgorithm::Rsa2048 as u8, 2);
        assert_eq!(SignatureAlgorithm::Rsa3072 as u8, 3);
        assert_eq!(SignatureAlgorithm::Rsa4096 as u8, 4);
        assert_eq!(SignatureAlgorithm::EcDsaP384 as u8, 5);
        assert_eq!(SignatureAlgorithm::EcDsaP521 as u8, 6);
        assert_eq!(SignatureAlgorithm::EcDsaBrainpoolP256R1 as u8, 7);
        assert_eq!(SignatureAlgorithm::EcDsaBrainpoolP384R1 as u8, 8);
        assert_eq!(SignatureAlgorithm::EcDsaBrainpoolP512R1 as u8, 9);
        assert_eq!(SignatureAlgorithm::EcDsaSecp256k1 as u8, 10);

        assert_tokens(&SignatureAlgorithm::Ed255, &[Token::U8(0)]);
        assert_tokens(&SignatureAlgorithm::EcDsaP256, &[Token::U8(1)]);
        assert_tokens(&SignatureAlgorithm::Rsa2048, &[Token::U8(2)]);
        assert_tokens(&SignatureAlgorithm::Rsa3072, &[Token::U8(3)]);
        assert_tokens(&SignatureAlgorithm::Rsa4096, &[Token::U8(4)]);
        assert_tokens(&SignatureAlgorithm::EcDsaP384, &[Token::U8(5)]);
        assert_tokens(&SignatureAlgorithm::EcDsaP521, &[Token::U8(6)]);
        assert_tokens(&SignatureAlgorithm::EcDsaBrainpoolP256R1, &[Token::U8(7)]);
        assert_tokens(&SignatureAlgorithm::EcDsaBrainpoolP384R1, &[Token::U8(8)]);
        assert_tokens(&SignatureAlgorithm::EcDsaBrainpoolP512R1, &[Token::U8(9)]);
        assert_tokens(&SignatureAlgorithm::EcDsaSecp256k1, &[Token::U8(10)]);
    }
    #[test]
    fn asssert_dec_values() {
        assert_eq!(DecryptionAlgorithm::X255 as u8, 0);
        assert_eq!(DecryptionAlgorithm::EcDhP256 as u8, 1);
        assert_eq!(DecryptionAlgorithm::Rsa2048 as u8, 2);
        assert_eq!(DecryptionAlgorithm::Rsa3072 as u8, 3);
        assert_eq!(DecryptionAlgorithm::Rsa4096 as u8, 4);
        assert_eq!(DecryptionAlgorithm::EcDhP384 as u8, 5);
        assert_eq!(DecryptionAlgorithm::EcDhP521 as u8, 6);
        assert_eq!(DecryptionAlgorithm::EcDhBrainpoolP256R1 as u8, 7);
        assert_eq!(DecryptionAlgorithm::EcDhBrainpoolP384R1 as u8, 8);
        assert_eq!(DecryptionAlgorithm::EcDhBrainpoolP512R1 as u8, 9);
        assert_eq!(DecryptionAlgorithm::EcDhSecp256k1 as u8, 10);

        assert_tokens(&DecryptionAlgorithm::X255, &[Token::U8(0)]);
        assert_tokens(&DecryptionAlgorithm::EcDhP256, &[Token::U8(1)]);
        assert_tokens(&DecryptionAlgorithm::Rsa2048, &[Token::U8(2)]);
        assert_tokens(&DecryptionAlgorithm::Rsa3072, &[Token::U8(3)]);
        assert_tokens(&DecryptionAlgorithm::Rsa4096, &[Token::U8(4)]);
        assert_tokens(&DecryptionAlgorithm::EcDhP384, &[Token::U8(5)]);
        assert_tokens(&DecryptionAlgorithm::EcDhP521, &[Token::U8(6)]);
        assert_tokens(&DecryptionAlgorithm::EcDhBrainpoolP256R1, &[Token::U8(7)]);
        assert_tokens(&DecryptionAlgorithm::EcDhBrainpoolP384R1, &[Token::U8(8)]);
        assert_tokens(&DecryptionAlgorithm::EcDhBrainpoolP512R1, &[Token::U8(9)]);
        assert_tokens(&DecryptionAlgorithm::EcDhSecp256k1, &[Token::U8(10)]);
    }
    #[test]
    fn asssert_aut_values() {
        assert_eq!(AuthenticationAlgorithm::Ed255 as u8, 0);
        assert_eq!(AuthenticationAlgorithm::EcDsaP256 as u8, 1);
        assert_eq!(AuthenticationAlgorithm::Rsa2048 as u8, 2);
        assert_eq!(AuthenticationAlgorithm::Rsa3072 as u8, 3);
        assert_eq!(AuthenticationAlgorithm::Rsa4096 as u8, 4);
        assert_eq!(AuthenticationAlgorithm::EcDsaP384 as u8, 5);
        assert_eq!(AuthenticationAlgorithm::EcDsaP521 as u8, 6);
        assert_eq!(AuthenticationAlgorithm::EcDsaBrainpoolP256R1 as u8, 7);
        assert_eq!(AuthenticationAlgorithm::EcDsaBrainpoolP384R1 as u8, 8);
        assert_eq!(AuthenticationAlgorithm::EcDsaBrainpoolP512R1 as u8, 9);
        assert_eq!(AuthenticationAlgorithm::EcDsaSecp256k1 as u8, 10);

        assert_tokens(&AuthenticationAlgorithm::Ed255, &[Token::U8(0)]);
        assert_tokens(&AuthenticationAlgorithm::EcDsaP256, &[Token::U8(1)]);
        assert_tokens(&AuthenticationAlgorithm::Rsa2048, &[Token::U8(2)]);
        assert_tokens(&AuthenticationAlgorithm::Rsa3072, &[Token::U8(3)]);
        assert_tokens(&AuthenticationAlgorithm::Rsa4096, &[Token::U8(4)]);
        assert_tokens(&AuthenticationAlgorithm::EcDsaP384, &[Token::U8(5)]);
        assert_tokens(&AuthenticationAlgorithm::EcDsaP521, &[Token::U8(6)]);
        assert_tokens(
            &AuthenticationAlgorithm::EcDsaBrainpoolP256R1,
            &[Token::U8(7)],
        );
        assert_tokens(
            &AuthenticationAlgorithm::EcDsaBrainpoolP384R1,
            &[Token::U8(8)],
        );
        assert_tokens(
            &AuthenticationAlgorithm::EcDsaBrainpoolP512R1,
            &[Token::U8(9)],
        );
        assert_tokens(&AuthenticationAlgorithm::EcDsaSecp256k1, &[Token::U8(10)]);
    }
}
