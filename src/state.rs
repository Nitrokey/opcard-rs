// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use heapless::String;
use heapless_bytes::Bytes;
use hex_literal::hex;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use subtle::ConstantTimeEq;

use trussed::api::reply::Metadata;
use trussed::try_syscall;
use trussed::types::{Location, PathBuf};

use crate::command::Password;
use crate::error::Error;

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

#[derive(Clone, Debug, Eq, PartialEq, Copy, Deserialize_repr, Serialize_repr)]
#[repr(u8)]
pub enum Uif {
    Disabled = 0,
    Enable = 1,
}

impl Default for Uif {
    fn default() -> Self {
        Uif::Disabled
    }
}

impl Uif {
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Internal {
    user_pin_tries: u8,
    admin_pin_tries: u8,
    user_pin: Bytes<MAX_PIN_LENGTH>,
    admin_pin: Bytes<MAX_PIN_LENGTH>,
    pub cardholder_name: String<39>,
    pub cardholder_sex: Sex,
    pub language_preferences: String<8>,
    pub sign_count: usize,
    pub uif_sign: Uif,
    pub uif_dec: Uif,
    pub uif_aut: Uif,
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
            admin_pin,
            user_pin,
            cardholder_name: String::new(),
            cardholder_sex: Sex::default(),
            language_preferences: String::from("en"),
            sign_count: 0,
            uif_sign: Uif::Disabled,
            uif_dec: Uif::Disabled,
            uif_aut: Uif::Disabled,
        }
    }

    fn path() -> PathBuf {
        PathBuf::from(Self::FILENAME)
    }

    pub fn load<T: trussed::Client>(client: &mut T) -> Result<Self, Error> {
        let data = match try_syscall!(client.read_file(Location::Internal, Self::path())) {
            Ok(r) => r.data,
            Err(_) => match try_syscall!(client.entry_metadata(Location::Internal, Self::path())) {
                Ok(Metadata { metadata: None }) => return Ok(Self::default()),
                Ok(Metadata {
                    metadata: Some(metadata),
                }) => {
                    log::error!("File exists but couldn't be read: {metadata:?}");
                    return Err(Error::Loading);
                }
                Err(err) => {
                    log::error!("File couldn't be read: {err:?}");
                    return Err(Error::Loading);
                }
            },
        };
        trussed::cbor_deserialize(&data).map_err(|err| {
            log::error!("failed to deserialize internal state: {err}");
            Error::Loading
        })
    }

    pub fn save<T: trussed::Client>(&self, client: &mut T) -> Result<(), Error> {
        let msg = trussed::cbor_serialize_bytes(&self).map_err(|err| {
            log::error!("Failed to serialize: {err}");
            Error::Saving
        })?;
        try_syscall!(client.write_file(Location::Internal, Self::path(), msg, None)).map_err(
            |err| {
                log::error!("Failed to store data: {err:?}");
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
        match try_syscall!(client.read_file(Location::Internal, self.path())) {
            Ok(r) => Ok(r.data),
            Err(_) => match try_syscall!(client.entry_metadata(Location::Internal, self.path())) {
                Ok(Metadata { metadata: None }) => Ok(self.default()),
                Ok(Metadata {
                    metadata: Some(metadata),
                }) => {
                    log::error!("File exists but couldn't be read: {metadata:?}");
                    Err(Error::Loading)
                }
                Err(err) => {
                    log::error!("File couldn't be read: {err:?}");
                    Err(Error::Loading)
                }
            },
        }
    }
}
