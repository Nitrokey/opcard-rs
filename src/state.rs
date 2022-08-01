// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use heapless::String;
use heapless_bytes::Bytes;
use hex_literal::hex;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use subtle::ConstantTimeEq;

use trussed::api::reply::Metadata;
use trussed::config::MAX_MESSAGE_LENGTH;
use trussed::try_syscall;
use trussed::types::{KeyId, Location, PathBuf};

use crate::command::Password;
use crate::error::Error;
use crate::types::*;
use crate::utils::serde_bytes;

/// Maximum supported length for PW1 and PW3
pub const MAX_PIN_LENGTH: usize = 127;

/// Default value for PW1
pub const DEFAULT_USER_PIN: &[u8] = b"123456";
/// Default value for PW3
pub const DEFAULT_ADMIN_PIN: &[u8] = b"12345678";

/// Maximum length for generic DOs, limited by the length in trussed `read_file` command.
pub const MAX_GENERIC_LENGTH: usize = 1024;
/// Big endian encoding of [MAX_GENERIC_LENGTH](MAX_GENERIC_LENGTH)
pub const MAX_GENERIC_LENGTH_BE: [u8; 2] = (MAX_GENERIC_LENGTH as u16).to_be_bytes();

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    // Internal state may not be loaded, or may error when loaded
    pub internal: Option<Internal>,
    pub runtime: Runtime,
}

impl State {
    /// Loads the internal state from flash
    pub fn load<'s, T: trussed::Client>(
        &'s mut self,
        client: &mut T,
    ) -> Result<LoadedState<'s>, Error> {
        // This would be the correct way but it doesn't compile because of
        // https://github.com/rust-lang/rust/issues/47680 (I think)
        //if let Some(internal) = self.internal.as_mut() {
        //    Ok(LoadedState {
        //        internal,
        //        runtime: &mut self.runtime,
        //    })
        //} else {
        //    Ok(LoadedState {
        //        internal: self.internal.insert(Internal::load(client)?),
        //        runtime: &mut self.runtime,
        //    })
        //}

        if self.internal.is_none() {
            self.internal = Some(Internal::load(client)?);
        }

        #[allow(clippy::unwrap_used)]
        Ok(LoadedState {
            internal: self.internal.as_mut().unwrap(),
            runtime: &mut self.runtime,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct LoadedState<'s> {
    pub internal: &'s mut Internal,
    pub runtime: &'s mut Runtime,
}

#[derive(Clone, Debug, Eq, PartialEq, Copy, Deserialize_repr, Serialize_repr)]
#[repr(u8)]
pub enum Sex {
    NotKnown = 0x30,
    Male = 0x31,
    Female = 0x32,
    NotApplicable = 0x39,
}

impl Default for Sex {
    fn default() -> Sex {
        Sex::NotKnown
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Internal {
    user_pin_tries: u8,
    admin_pin_tries: u8,
    verify_valid_mutltiple: bool,
    user_pin: Bytes<MAX_PIN_LENGTH>,
    admin_pin: Bytes<MAX_PIN_LENGTH>,
    signing_key: Option<KeyId>,
    confidentiality_key: Option<KeyId>,
    aut_key: Option<KeyId>,
    sign_alg: SignatureAlgorithms,
    dec_alg: DecryptionAlgorithms,
    aut_alg: AuthenticationAlgorithms,
    /// sig, dec, aut
    #[serde(with = "serde_bytes")]
    fingerprints: [u8; 60],
    #[serde(with = "serde_bytes")]
    keygen_dates: [u8; 12],

    cardholder_name: Bytes<39>,
    cardholder_sex: Sex,
    language_preferences: Bytes<8>,
    sign_count: usize,
    uif_sign: Uif,
    uif_dec: Uif,
    uif_aut: Uif,
}

impl Internal {
    const FILENAME: &'static str = "persistent-state.cbor";
    // § 4.3
    const MAX_RETRIES: u8 = 3;

    #[allow(clippy::unwrap_used)]
    fn default() -> Self {
        // § 4.3.1
        let admin_pin = Bytes::from_slice(DEFAULT_ADMIN_PIN).unwrap();
        let user_pin = Bytes::from_slice(DEFAULT_USER_PIN).unwrap();
        Self {
            user_pin_tries: 0,
            admin_pin_tries: 0,
            verify_valid_mutltiple: true,
            admin_pin,
            user_pin,
            cardholder_name: Bytes::new(),
            cardholder_sex: Sex::default(),
            language_preferences: Bytes::new(),
            sign_count: 0,
            signing_key: None,
            confidentiality_key: None,
            sign_alg: SignatureAlgorithms::default(),
            dec_alg: DecryptionAlgorithms::default(),
            aut_alg: AuthenticationAlgorithms::default(),
            aut_key: None,
            fingerprints: [0; 60],
            keygen_dates: [0; 12],
            uif_sign: Uif::Disabled,
            uif_dec: Uif::Disabled,
            uif_aut: Uif::Disabled,
        }
    }

    fn path() -> PathBuf {
        PathBuf::from(Self::FILENAME)
    }

    pub fn load<T: trussed::Client>(client: &mut T) -> Result<Self, Error> {
        if let Some(data) = load_if_exists(client, Location::Internal, &Self::path())? {
            trussed::cbor_deserialize(&data).map_err(|_err| {
                error!("failed to deserialize internal state: {_err}");
                Error::Loading
            })
        } else {
            Ok(Self::default())
        }
    }

    pub fn save<T: trussed::Client>(&self, client: &mut T) -> Result<(), Error> {
        let msg = trussed::cbor_serialize_bytes(&self).map_err(|_err| {
            error!("Failed to serialize: {_err}");
            Error::Saving
        })?;
        try_syscall!(client.write_file(Location::Internal, Self::path(), msg, None)).map_err(
            |_err| {
                error!("Failed to store data: {_err:?}");
                Error::Saving
            },
        )?;
        Ok(())
    }

    pub fn remaining_tries(&self, password: Password) -> u8 {
        match password {
            Password::Pw1 => Self::MAX_RETRIES.saturating_sub(self.user_pin_tries),
            Password::Pw3 => Self::MAX_RETRIES.saturating_sub(self.admin_pin_tries),
        }
    }

    pub fn is_locked(&self, password: Password) -> bool {
        match password {
            Password::Pw1 => self.user_pin_tries >= Self::MAX_RETRIES,
            Password::Pw3 => self.admin_pin_tries >= Self::MAX_RETRIES,
        }
    }

    pub fn decrement_counter<T: trussed::Client>(
        &mut self,
        client: &mut T,
        password: Password,
    ) -> Result<(), Error> {
        if !self.is_locked(password) {
            match password {
                Password::Pw1 => self.user_pin_tries += 1,
                Password::Pw3 => self.admin_pin_tries += 1,
            }
            self.save(client)
        } else {
            Ok(())
        }
    }

    pub fn reset_counter<T: trussed::Client>(
        &mut self,
        client: &mut T,
        password: Password,
    ) -> Result<(), Error> {
        match password {
            Password::Pw1 => self.user_pin_tries = 0,
            Password::Pw3 => self.admin_pin_tries = 0,
        }
        self.save(client)
    }

    fn pin(&self, password: Password) -> &[u8] {
        match password {
            Password::Pw1 => &self.user_pin,
            Password::Pw3 => &self.admin_pin,
        }
    }

    pub fn verify_pin<T: trussed::Client>(
        &mut self,
        client: &mut T,
        value: &[u8],
        password: Password,
    ) -> Result<(), Error> {
        if self.is_locked(password) {
            return Err(Error::TooManyTries);
        }

        self.decrement_counter(client, password)?;
        if (!value.ct_eq(self.pin(password))).into() {
            return Err(Error::InvalidPin);
        }

        self.reset_counter(client, password)?;
        Ok(())
    }

    pub fn pin_len(&self, password: Password) -> usize {
        match password {
            Password::Pw1 => self.user_pin.len(),
            Password::Pw3 => self.admin_pin.len(),
        }
    }

    pub fn change_pin<T: trussed::Client>(
        &mut self,
        client: &mut T,
        value: &[u8],
        password: Password,
    ) -> Result<(), Error> {
        let (pin, tries) = match password {
            Password::Pw1 => (&mut self.user_pin, &mut self.user_pin_tries),
            Password::Pw3 => (&mut self.admin_pin, &mut self.admin_pin_tries),
        };
        *pin = Bytes::from_slice(value).map_err(|_| Error::RequestTooLarge)?;
        *tries = 0;
        self.save(client)
    }

    pub fn sign_alg(&self) -> SignatureAlgorithms {
        self.sign_alg
    }
    pub fn set_sign_alg(
        &mut self,
        client: &mut impl trussed::Client,
        alg: SignatureAlgorithms,
    ) -> Result<(), Error> {
        self.sign_alg = alg;
        self.save(client)
    }

    pub fn dec_alg(&self) -> DecryptionAlgorithms {
        self.dec_alg
    }
    pub fn set_dec_alg(
        &mut self,
        client: &mut impl trussed::Client,
        alg: DecryptionAlgorithms,
    ) -> Result<(), Error> {
        self.dec_alg = alg;
        self.save(client)
    }

    pub fn aut_alg(&self) -> AuthenticationAlgorithms {
        self.aut_alg
    }

    pub fn set_aut_alg(
        &mut self,
        client: &mut impl trussed::Client,
        alg: AuthenticationAlgorithms,
    ) -> Result<(), Error> {
        self.aut_alg = alg;
        self.save(client)
    }

    pub fn fingerprints(&self) -> [u8; 60] {
        self.fingerprints
    }

    pub fn set_fingerprints(
        &mut self,
        client: &mut impl trussed::Client,
        data: [u8; 60],
    ) -> Result<(), Error> {
        self.fingerprints = data;
        self.save(client)
    }

    pub fn keygen_dates(&self) -> [u8; 12] {
        self.keygen_dates
    }

    pub fn set_keygen_dates(
        &mut self,
        client: &mut impl trussed::Client,
        data: [u8; 12],
    ) -> Result<(), Error> {
        self.keygen_dates = data;
        self.save(client)
    }

    pub fn uif(&self, key: KeyType) -> Uif {
        match key {
            KeyType::Sign => self.uif_sign,
            KeyType::Confidentiality => self.uif_dec,
            KeyType::Aut => self.uif_aut,
        }
    }

    pub fn set_uif(
        &mut self,
        client: &mut impl trussed::Client,
        uif: Uif,
        key: KeyType,
    ) -> Result<(), Error> {
        match key {
            KeyType::Sign => self.uif_sign = uif,
            KeyType::Confidentiality => self.uif_dec = uif,
            KeyType::Aut => self.uif_aut = uif,
        }
        self.save(client)
    }

    pub fn verify_valid_multiple(&self) -> bool {
        self.verify_valid_mutltiple
    }

    pub fn set_verify_valid_multiple(
        &mut self,
        value: bool,
        client: &mut impl trussed::Client,
    ) -> Result<(), Error> {
        self.verify_valid_mutltiple = value;
        self.save(client)
    }

    pub fn cardholder_name(&self) -> &[u8] {
        &self.cardholder_name
    }

    pub fn cardholder_sex(&self) -> Sex {
        self.cardholder_sex
    }

    pub fn language_preferences(&self) -> &[u8] {
        &self.language_preferences
    }

    pub fn sign_count(&self) -> usize {
        self.sign_count
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Runtime {
    pub sign_verified: bool,
    pub other_verified: bool,
    pub admin_verified: bool,
}

/// DOs that can store arbitrary data from the user
///
/// They are stored each in their own files and are loaded only
/// when necessary to prevent the state from getting too big.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum ArbitraryDO {
    Url,
    KdfDo,
    PrivateUse1,
    PrivateUse2,
    PrivateUse3,
    PrivateUse4,
    LoginData,
    CardHolderCertAut,
    #[allow(unused)]
    CardHolderCertDec,
    #[allow(unused)]
    CardHolderCertSig,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum PermissionRequirement {
    None,
    User,
    Admin,
}

impl ArbitraryDO {
    fn path(self) -> PathBuf {
        PathBuf::from(match self {
            Self::Url => "url",
            Self::KdfDo => "kdf_do",
            Self::PrivateUse1 => "private_use_1",
            Self::PrivateUse2 => "private_use_2",
            Self::PrivateUse3 => "private_use_3",
            Self::PrivateUse4 => "private_use_4",
            Self::LoginData => "login_data",
            Self::CardHolderCertAut => "cardholder_cert_aut",
            Self::CardHolderCertDec => "cardholder_cert_dec",
            Self::CardHolderCertSig => "cardholder_cert_sig",
        })
    }

    fn default(self) -> Bytes<MAX_GENERIC_LENGTH> {
        #[allow(clippy::unwrap_used)]
        match self {
            // KDF-DO initialized to NONE
            Self::KdfDo => Bytes::from_slice(&hex!("81 01 00")).unwrap(),
            _ => Bytes::new(),
        }
    }

    pub fn read_permission(self) -> PermissionRequirement {
        match self {
            Self::PrivateUse3 => PermissionRequirement::User,
            Self::PrivateUse4 => PermissionRequirement::Admin,
            _ => PermissionRequirement::None,
        }
    }

    pub fn load(
        self,
        client: &mut impl trussed::Client,
    ) -> Result<Bytes<MAX_GENERIC_LENGTH>, Error> {
        load_if_exists(client, Location::Internal, &self.path())
            .map(|data| data.unwrap_or_else(|| self.default()))
    }

    pub fn save(self, client: &mut impl trussed::Client, bytes: &[u8]) -> Result<(), Error> {
        let msg = Bytes::from(heapless::Vec::try_from(bytes).map_err(|_| {
            error!("Buffer full");
            Error::Saving
        })?);
        try_syscall!(client.write_file(Location::Internal, self.path(), msg, None)).map_err(
            |_err| {
                error!("Failed to store data: {_err:?}");
                Error::Saving
            },
        )?;
        Ok(())
    }
}

fn load_if_exists(
    client: &mut impl trussed::Client,
    location: Location,
    path: &PathBuf,
) -> Result<Option<Bytes<MAX_MESSAGE_LENGTH>>, Error> {
    match try_syscall!(client.read_file(location, path.clone())) {
        Ok(r) => Ok(Some(r.data)),
        Err(_) => match try_syscall!(client.entry_metadata(location, path.clone())) {
            Ok(Metadata { metadata: None }) => Ok(None),
            Ok(Metadata {
                metadata: Some(_metadata),
            }) => {
                error!("File {path} exists but couldn't be read: {_metadata:?}");
                Err(Error::Loading)
            }
            Err(_err) => {
                error!("File {path} couldn't be read: {_err:?}");
                Err(Error::Loading)
            }
        },
    }
}
