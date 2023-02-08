// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

//! Backend providing platform-specific low-level functionality.
//!
//! As this crate is designed to be usable on any platform, it cannot rely on a specific data
//! storage and cryptography implementation.  Instead, a [`Card`][`crate::Card`] has to be provided
//! with a Backend wrapping a [`trussed::Client`][trussed::Client]

use core::fmt::Debug;

use trussed::try_syscall;

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

    /// Return a mutable reference to the trussed client
    pub fn client_mut(&mut self) -> &mut T {
        &mut self.client
    }

    /// Checks whether the given value matches the pin of the given type.
    pub fn verify_pin(
        &mut self,
        pin: Password,
        value: &[u8],
        state: &mut state::Persistent,
    ) -> bool {
        state.verify_pin(&mut self.client, value, pin).is_ok()
    }

    /// Ask for confirmation of presence from the user with a default timeout of 15 seconds
    pub fn confirm_user_present(&mut self) -> Result<bool, Error> {
        try_syscall!(self.client_mut().confirm_user_present(15_000))
            .map_err(|_err| {
                error!("Failed to confirm user presence {_err:?}");
                Error::UserInteraction
            })
            .map(|r| r.result.is_ok())
    }
}
