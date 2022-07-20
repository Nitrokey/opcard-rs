// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

//! Backend providing platform-specific low-level functionality.
//!
//! As this crate is designed to be usable on any platform, it cannot rely on a specific data
//! storage and cryptography implementation.  Instead, a [`Card`][`crate::Card`] has to be provided
//! with a Backend wrapping a [`trussed::Client`][trussed::Client]

use core::fmt::Debug;

use crate::command::Password;
use crate::error::Error;
use crate::state;

/// Backend that provides data storage and cryptography operations.
/// Mostly a wrapper around a trussed client
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
    /// Create new backend from a trussed client
    pub fn new(client: T) -> Self {
        Self { client }
    }

    /// If the state is already loaded, returns it, otherwise try to load it
    pub fn load_internal<'s, 'i>(
        &'s mut self,
        internal: &'i mut Option<state::Internal>,
    ) -> Result<&'i mut state::Internal, Error> {
        if let Some(state) = internal {
            return Ok(state);
        }
        let to_ret = internal.insert(state::Internal::load(&mut self.client)?);
        Ok(to_ret)
    }

    /// Return a mutable reference to the trussed client
    pub fn client_mut(&mut self) -> &mut T {
        &mut self.client
    }

    /// Checks whether the given value matches the pin of the given type.
    pub fn verify_pin(&mut self, pin: Password, value: &[u8], state: &mut state::Internal) -> bool {
        state.verify_pin(&mut self.client, value, pin).is_ok()
    }
}
