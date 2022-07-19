// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#[derive(Debug, Clone, Copy)]
pub enum Error {
    Loading,
    Saving,
    InvalidPin,
    TooManyTries,
    RequestTooLarge,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let to_write = match self {
            Error::Loading => "Failed to load or deserialize from filesystem",
            Error::Saving => "Failed to save to filesystem",
            Error::InvalidPin => "Failed PIN authentication",
            Error::TooManyTries => "PIN is locked",
            Error::RequestTooLarge => "Request data is larger than supported",
        };
        f.write_str(to_write)
    }
}
