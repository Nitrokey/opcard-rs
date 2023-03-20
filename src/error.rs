// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#[derive(Debug, Clone, Copy)]
pub enum Error {
    Loading,
    Saving,
    InvalidPin,
    BadRequest,
    UserInteraction,
    Internal,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let to_write = match self {
            Error::Loading => "Failed to load or deserialize from filesystem",
            Error::Saving => "Failed to save to filesystem",
            Error::InvalidPin => "Failed PIN authentication",
            Error::BadRequest => "Request data invalid",
            Error::UserInteraction => "Failed to get user presence",
            Error::Internal => "Internal error",
        };
        f.write_str(to_write)
    }
}
