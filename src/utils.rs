// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use trussed::error::Error as TrussedError;
use trussed::try_syscall;
use trussed::types::{Location, PathBuf};

pub fn file_exists<T: trussed::Client>(
    client: &mut T,
    location: Location,
    path: &str,
) -> Result<bool, TrussedError> {
    let maybe_entry =
        try_syscall!(client.read_dir_first(location, PathBuf::new(), Some(PathBuf::from(path))))?
            .entry;
    if let Some(entry) = maybe_entry {
        if entry.file_name() == path {
            Ok(true)
        } else {
            Ok(false)
        }
    } else {
        Ok(false)
    }
}
