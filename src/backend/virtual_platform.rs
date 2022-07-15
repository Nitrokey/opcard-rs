// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
//! Virtual trussed client implementation used for testing
use trussed::client::ClientImplementation;
use trussed::pipe::TrussedInterchange;
use trussed::platform::{Platform, Syscall, UserInterface};
use trussed::service::Service;
use trussed::types::ClientId;

use std::sync::Mutex;

#[allow(missing_docs, clippy::too_many_arguments)]
mod macros_gen {
    use littlefs2::const_ram_storage;
    use trussed::types::{LfsResult, LfsStorage};
    const_ram_storage!(VolatileStorage, 1024);
    const_ram_storage!(ExternalStorage, 1024);
    const_ram_storage!(InternalStorage, 1024);

    trussed::platform! {VirtualPlatform,
        R: rand_chacha::ChaCha20Rng,
        S: VirtualStore,
        UI: super::VirtualUI,
    }

    trussed::store! {VirtualStore,
        Internal: InternalStorage,
        External: ExternalStorage,
        Volatile: VolatileStorage
    }
}
pub use macros_gen::*;

impl Default for VirtualStore {
    fn default() -> VirtualStore {
        VirtualStore::attach_else_format(
            InternalStorage::new(),
            ExternalStorage::new(),
            VolatileStorage::new(),
        )
    }
}

/// Dummy UI, used for testing
#[allow(missing_copy_implementations)]
#[derive(Default, Debug)]
pub struct VirtualUI {}

impl UserInterface for VirtualUI {}

/// Wrapper around a trussed service, providing a [into_client][ServiceWrapper::into_client] method that is `'static`, unlike [try_as_new_client][trussed::service::Service::try_as_new_client].
#[allow(missing_debug_implementations)]
pub struct ServiceWrapper<P: Platform>(Service<P>);

impl<P: Platform> Syscall for ServiceWrapper<P> {
    fn syscall(&mut self) {
        (&mut self.0).syscall();
    }
}

impl<P: Platform> ServiceWrapper<P> {
    /// Create a new [ClientImplementation][trussed::client::ClientImplementation] containing an
    /// owned service providing syscalls
    pub fn into_client(mut self, client_id: &str) -> ClientImplementation<ServiceWrapper<P>> {
        use interchange::Interchange;
        // This module is only used for testing, unwrap is OK
        #[allow(clippy::unwrap_used)]
        let (requester, responder) = TrussedInterchange::claim().ok_or(()).unwrap();
        let client_id = ClientId::from(client_id.as_bytes());

        #[allow(clippy::unwrap_used)]
        self.0
            .add_endpoint(responder, client_id)
            .map_err(|_service_endpoint| ())
            .unwrap();

        ClientImplementation::new(requester, self)
    }
}

fn virtual_platform() -> VirtualPlatform {
    use rand::SeedableRng;

    #[allow(clippy::unwrap_used)]
    let rng = rand_chacha::ChaChaRng::from_rng(rand::rngs::OsRng).unwrap();
    let store = VirtualStore::default();
    let ui = VirtualUI::default();
    VirtualPlatform::new(rng, store, ui)
}

/// Create a virtual trussed client for testing
fn virtual_client() -> ClientImplementation<ServiceWrapper<VirtualPlatform>> {
    let service = ServiceWrapper(Service::new(virtual_platform()));
    service.into_client("virtual_openpgp")
}

/// Type alias for a Card using a pure software trussed client
pub type SoftwareCard = crate::Card<ClientImplementation<ServiceWrapper<VirtualPlatform>>>;

/// Type alias for a vpicc card using a pure software trussed client
pub type SoftwareVirtualCard =
    crate::VirtualCard<ClientImplementation<ServiceWrapper<VirtualPlatform>>>;

lazy_static::lazy_static! {
    static ref ONE_CARD: Mutex<Option<SoftwareCard>> =
    {
        #[allow(clippy::unwrap_used, clippy::expect_used)]
        Mutex::new(
            Some(SoftwareCard::new(
                super::Backend::new(virtual_client()), crate::Options::default()
            ))
        )
    };

    /// Reference to a unique card
    /// Multiple card cannot be created because they use static storage, so using it when
    /// [`VIRTUAL_CARD`][VIRTUAL_CARD] is already used will cause a panic
    pub static ref CARD: Mutex<SoftwareCard> = {
#[allow(clippy::unwrap_used, clippy::expect_used)]
        Mutex::new(ONE_CARD.lock().unwrap().take().expect("SoftwareCard cannot be used if SoftwareVirtualCard is used"))
    };

    /// Reference to a unique card
    /// Multiple card cannot be created because they use static storage, so using it when
    /// [`CARD`][CARD] is already used will cause a panic
    pub static ref VIRTUAL_CARD: Mutex<SoftwareVirtualCard> = {
#[allow(clippy::unwrap_used, clippy::expect_used)]
        Mutex::new(crate::VirtualCard::new(ONE_CARD.lock().unwrap().take().expect("SoftwareCard cannot be used if SoftwareVirtualCard is used")))
    };
}
