// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use heapless_bytes::Bytes;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use trussed::api::reply::Metadata;
use trussed::try_syscall;
use trussed::types::{Location, PathBuf};

use crate::command::Password;
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
    user_pin: Bytes<MAX_PIN_LENGTH>,
    admin_pin: Bytes<MAX_PIN_LENGTH>,
}

impl Internal {
    const FILENAME: &'static str = "persistent-state.cbor";
    // § 4.3
    const MAX_RETRIES: u8 = 3;

    fn default() -> Self {
        #[allow(clippy::unwrap_used)]
        let admin_pin = Bytes::from_slice(DEFAULT_ADMIN_PIN).unwrap();
        #[allow(clippy::unwrap_used)]
        let user_pin = Bytes::from_slice(DEFAULT_USER_PIN).unwrap();
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