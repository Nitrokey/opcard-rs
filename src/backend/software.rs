// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use std::{collections, fs, io, path};

use super::{Backend, Pin};

/// Backend using the filesystem or memory to store data.
#[derive(Debug, Default)]
pub struct SoftwareBackend {
    storage: Storage,
}

impl SoftwareBackend {
    /// Creates a new software backend using the given data storage.
    pub fn new(storage: impl Into<Storage>) -> Self {
        let storage = storage.into();
        Self { storage }
    }

    fn pin(&self, pin: Pin) -> io::Result<Vec<u8>> {
        let path = path::Path::new("pin").join(match pin {
            Pin::UserPin => "user",
            Pin::AdminPin => "admin",
        });
        if self.storage.exists(&path) {
            self.storage.read(&path)
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

/// A storage provider for the software backend.
#[derive(Debug)]
pub enum Storage {
    /// Files under a path.
    Filesystem(path::PathBuf),
    /// In-memory storage.
    Memory(collections::BTreeMap<path::PathBuf, Vec<u8>>),
}

impl Storage {
    /// Checks whether the given path exists in this storage provider.
    pub fn exists(&self, path: &path::Path) -> bool {
        match self {
            Self::Filesystem(root) => root.join(path).exists(),
            Self::Memory(map) => map.contains_key(path),
        }
    }

    /// Reads the file at the given path in this storage provider.
    pub fn read(&self, path: &path::Path) -> io::Result<Vec<u8>> {
        match self {
            Self::Filesystem(root) => fs::read(root.join(path)),
            Self::Memory(map) => map
                .get(path)
                .map(ToOwned::to_owned)
                .ok_or_else(|| io::ErrorKind::NotFound.into()),
        }
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self::Memory(Default::default())
    }
}

impl<P: Into<path::PathBuf>> From<P> for Storage {
    fn from(path: P) -> Self {
        Self::Filesystem(path.into())
    }
}
