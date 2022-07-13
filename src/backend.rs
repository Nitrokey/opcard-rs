// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

//! Backend providing platform-specific low-level functionality.
//!
//! As this crate is designed to be usable on any platform, it cannot rely on a specific data
//! storage and cryptography implementation.  Instead, a [`Card`][`crate::Card`] has to be provided
//! with a Backend wrapping a [`trussed::Client`][trussed::Client]

use core::fmt::Debug;

/// The available PIN types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pin {
    /// The user PIN.
    UserPin,
    /// The admin PIN.
    AdminPin,
}

#[derive(Clone)]
pub struct Backend<T: trussed::Client> {
    client: T,
}

impl<T: trussed::Client> Debug for Backend<T> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self { client: _client } = self;
        fmt.debug_struct("Backend").finish()
    }
}

impl<T: trussed::Client> Backend<T> {
    pub fn new(client: T) -> Self {
        Self { client }
    }

    pub fn verify_pin(&self, _pin: Pin, _value: &[u8]) -> bool {
        todo!()
    }
}
