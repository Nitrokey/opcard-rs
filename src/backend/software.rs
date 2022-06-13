// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use std::{fs, io, path};

use super::{Backend, Pin};

/// Backend using the filesystem to store data.
#[derive(Debug)]
pub struct SoftwareBackend {
    root: path::PathBuf,
}

impl SoftwareBackend {
    /// Creates a new software backend using the given root directory.
    pub fn new(root: impl Into<path::PathBuf>) -> Self {
        let root = root.into();
        Self { root }
    }

    fn pin(&self, pin: Pin) -> io::Result<Vec<u8>> {
        let path = self.root.join("pin").join(match pin {
            Pin::UserPin => "user",
            Pin::AdminPin => "admin",
        });
        if path.exists() {
            fs::read(path)
        } else {
            Ok(match pin {
                Pin::UserPin => b"123456".to_owned().into(),
                Pin::AdminPin => b"12345678".to_owned().into(),
            })
        }
    }
}

impl Backend for SoftwareBackend {
    fn verify_pin(&self, pin: Pin, value: &[u8]) -> bool {
        if let Ok(pin) = self.pin(pin) {
            pin == value
        } else {
            false
        }
    }
}
