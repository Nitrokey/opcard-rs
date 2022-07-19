// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use crate::utils::serde_bytes_heapless;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use trussed::error::Error as TrussedError;
use trussed::try_syscall;
use trussed::types::{Location, PathBuf};

use crate::error::Error;

// TODO support more?
/// Maximum supported length for PW1 and PW3
pub const MAX_PIN_LENGTH: usize = 8;

/// Default value for PW1
pub const DEFAULT_USER_PIN: &[u8] = b"123456";
/// Default value for PW3
pub const DEFAULT_ADMIN_PIN: &[u8] = b"12345678";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    // Internal state may not be loaded, or may error when loaded
    pub internal: Option<Internal>,
    pub runtime: Runtime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Internal {
    user_pin_tries: u8,
    admin_pin_tries: u8,
    #[serde(with = "serde_bytes_heapless")]
    user_pin: heapless::Vec<u8, MAX_PIN_LENGTH>,
    #[serde(with = "serde_bytes_heapless")]
    admin_pin: heapless::Vec<u8, MAX_PIN_LENGTH>,
}

impl Internal {
    const FILENAME: &'static str = "persistent-state.cbor";
    // § 4.3
    const MAX_RETRIES: u8 = 3;

    fn default() -> Self {
        #[allow(clippy::unwrap_used)]
        let admin_pin = heapless::Vec::from_slice(DEFAULT_ADMIN_PIN).unwrap();
        #[allow(clippy::unwrap_used)]
        let user_pin = heapless::Vec::from_slice(DEFAULT_USER_PIN).unwrap();
        Self {
            user_pin_tries: 0,
            admin_pin_tries: 0,

            // § 4.3.1
            admin_pin,
            user_pin,
        }
    }

    fn path() -> PathBuf {
        PathBuf::from(Self::FILENAME)
    }

    fn file_exists<T: trussed::Client>(client: &mut T) -> Result<bool, TrussedError> {
        let maybe_entry = try_syscall!(client.read_dir_first(
            Location::Internal,
            PathBuf::new(),
            Some(Self::path())
        ))?
        .entry;
        if let Some(entry) = maybe_entry {
            if entry.file_name() == Self::FILENAME {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    pub fn load<T: trussed::Client>(client: &mut T) -> Result<Self, Error> {
        let data = match try_syscall!(client.read_file(Location::Internal, Self::path())) {
            Ok(r) => r.data,
            Err(_) => match Self::file_exists(client) {
                Ok(false) => return Ok(Self::default()),
                Ok(true) => {
                    log::error!("File exists but couldn't be read");
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

    pub fn remaining_user_tries(&self) -> u8 {
        Self::MAX_RETRIES.saturating_sub(self.user_pin_tries)
    }

    pub fn remaining_admin_tries(&self) -> u8 {
        Self::MAX_RETRIES.saturating_sub(self.admin_pin_tries)
    }

    pub fn is_user_locked(&self) -> bool {
        self.user_pin_tries >= Self::MAX_RETRIES
    }

    pub fn is_admin_locked(&self) -> bool {
        self.admin_pin_tries >= Self::MAX_RETRIES
    }

    pub fn decrement_user_counter<T: trussed::Client>(
        &mut self,
        client: &mut T,
    ) -> Result<(), Error> {
        if !self.is_user_locked() {
            self.user_pin_tries += 1;
            self.save(client)
        } else {
            Ok(())
        }
    }

    pub fn decrement_admin_counter<T: trussed::Client>(
        &mut self,
        client: &mut T,
    ) -> Result<(), Error> {
        if !self.is_admin_locked() {
            self.admin_pin_tries += 1;
            self.save(client)
        } else {
            Ok(())
        }
    }

    pub fn reset_user_counter<T: trussed::Client>(&mut self, client: &mut T) -> Result<(), Error> {
        self.user_pin_tries = 0;
        self.save(client)
    }

    pub fn reset_admin_counter<T: trussed::Client>(&mut self, client: &mut T) -> Result<(), Error> {
        self.admin_pin_tries = 0;
        self.save(client)
    }
    pub fn verify_user_pin<T: trussed::Client>(
        &mut self,
        client: &mut T,
        value: &[u8],
    ) -> Result<(), Error> {
        if self.is_user_locked() {
            return Err(Error::TooManyTries);
        }

        self.decrement_user_counter(client)?;
        if (!value.ct_eq(&self.user_pin)).into() {
            return Err(Error::InvalidPin);
        }

        self.reset_user_counter(client)?;
        Ok(())
    }

    pub fn verify_admin_pin<T: trussed::Client>(
        &mut self,
        client: &mut T,
        value: &[u8],
    ) -> Result<(), Error> {
        if self.is_admin_locked() {
            return Err(Error::TooManyTries);
        }

        self.decrement_admin_counter(client)?;
        if (!value.ct_eq(&self.admin_pin)).into() {
            return Err(Error::InvalidPin);
        }

        self.reset_admin_counter(client)?;
        Ok(())
    }

    pub fn user_pin_len(&self) -> usize {
        self.user_pin.len()
    }

    pub fn admin_pin_len(&self) -> usize {
        self.admin_pin.len()
    }

    pub fn change_admin_pin<T: trussed::Client>(
        &mut self,
        client: &mut T,
        value: &[u8],
    ) -> Result<(), Error> {
        self.admin_pin = heapless::Vec::from_slice(value).map_err(|_| Error::RequestTooLarge)?;
        self.admin_pin_tries = 0;
        self.save(client)
    }

    pub fn change_user_pin<T: trussed::Client>(
        &mut self,
        client: &mut T,
        value: &[u8],
    ) -> Result<(), Error> {
        self.user_pin = heapless::Vec::from_slice(value).map_err(|_| Error::RequestTooLarge)?;
        self.user_pin_tries = 0;
        self.save(client)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Runtime {
    pub sign_verified: bool,
    pub other_verified: bool,
    pub admin_verified: bool,
}
