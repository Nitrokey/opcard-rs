// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use trussed::try_syscall;
use trussed::types::{Location, PathBuf};

use crate::error::Error;

// TODO support more?
const MAX_PIN_LENGTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Internal {
    #[serde(skip)]
    initialized: bool,
    user_pin_tries: u8,
    admin_pin_tries: u8,
    user_pin: heapless::Vec<u8, MAX_PIN_LENGTH>,
    admin_pin: heapless::Vec<u8, MAX_PIN_LENGTH>,
}

impl Default for Internal {
    fn default() -> Self {
        #[allow(clippy::unwrap_used)]
        let admin_pin = heapless::Vec::from_slice(b"123456".as_slice()).unwrap();
        #[allow(clippy::unwrap_used)]
        let user_pin = heapless::Vec::from_slice(b"12345678".as_slice()).unwrap();
        Self {
            initialized: Default::default(),
            user_pin_tries: Default::default(),
            admin_pin_tries: Default::default(),

            // § 4.3.1
            admin_pin,
            user_pin,
        }
    }
}

impl Internal {
    const FILENAME: &'static [u8] = b"persistent-state.cbor";
    // § 4.3
    const MAX_RETRIES: u8 = 3;
    fn path() -> PathBuf {
        PathBuf::from(Self::FILENAME)
    }

    pub fn load<T: trussed::Client>(client: &mut T) -> Result<Self, Error> {
        let data = try_syscall!(client.read_file(Location::Internal, Self::path()))
            .map_err(|_| Error::Loading)?
            .data;
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

    pub fn load_if_not_init<T: trussed::Client>(&mut self, client: &mut T) {
        if !self.initialized {
            match Self::load(client) {
                Ok(state) => *self = state,
                // Only info since it will happen if the state doesn't already exists
                Err(err) => log::info!("Failed to load state {err}"),
            }
        }
        self.initialized = true;
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
        self.load_if_not_init(client);
        if self.is_user_locked() {
            return Err(Error::TooManyTries);
        }

        self.decrement_user_counter(client)?;
        if value.ct_eq(&self.user_pin).into() {
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
        self.load_if_not_init(client);
        if self.is_admin_locked() {
            return Err(Error::TooManyTries);
        }

        self.decrement_admin_counter(client)?;
        if value.ct_eq(&self.admin_pin).into() {
            return Err(Error::InvalidPin);
        }

        self.reset_admin_counter(client)?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Runtime {
    // TODO verification of Pw1Sign can also be verified for multiple commands depending on DO C4
    other_verified: bool,
}

impl Runtime {
    pub fn is_other_verified(&self) -> bool {
        self.other_verified
    }

    pub fn verify_other(&mut self) {
        self.other_verified = true;
    }
}
