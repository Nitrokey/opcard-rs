// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use core::fmt::Debug;

use super::{Backend, Pin};

/// Backend using Trussed mechanisms.
#[derive(Debug)]
pub struct TrussedBackend<T: trussed::Client + Debug> {
    _client: T,
}

impl<T: trussed::Client + Debug> TrussedBackend<T> {
    /// Creates a new Trussed backend using the given client.
    pub fn new(client: T) -> Self {
        Self { _client: client }
    }
}

impl<T: trussed::Client + Debug> Backend for TrussedBackend<T> {
    fn verify_pin(&self, _pin: Pin, _value: &[u8]) -> bool {
        unimplemented!();
    }
}
