// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

//! USB/IP runner for opcard.
//! Run with cargo run --example --features apdu-dispatch (and optionally rsa4096-gen)

use littlefs2_core::path;
use trussed::virt::{self, Platform, StoreProvider, UserInterface};
use trussed::{client::ClientBuilder, ClientImplementation, Platform as _, Service};
use trussed_usbip::Syscall;

use opcard::virt::dispatch::{self, Dispatch};

type VirtClient = ClientImplementation<Syscall, dispatch::Dispatch>;

const MANUFACTURER: &str = "Nitrokey";
const PRODUCT: &str = "Nitrokey 3";
const VID: u16 = 0x20a0;
const PID: u16 = 0x42b2;

struct OpcardApp {
    opcard: opcard::Card<VirtClient>,
}

impl<S: StoreProvider> trussed_usbip::Apps<'_, S, Dispatch> for OpcardApp {
    type Data = ();
    fn new(service: &mut Service<Platform<S>, Dispatch>, syscall: Syscall, _data: ()) -> Self {
        let client = ClientBuilder::new(path!("opcard"))
            .backends(dispatch::BACKENDS)
            .prepare(service)
            .expect("failed to create client")
            .build(syscall);
        OpcardApp {
            opcard: opcard::Card::new(client, opcard::Options::default()),
        }
    }

    fn with_ccid_apps<T>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn apdu_dispatch::App<7609>]) -> T,
    ) -> T {
        f(&mut [&mut self.opcard])
    }
}

fn main() {
    env_logger::init();

    let options = trussed_usbip::Options {
        manufacturer: Some(MANUFACTURER.to_owned()),
        product: Some(PRODUCT.to_owned()),
        serial_number: Some("TEST".into()),
        vid: VID,
        pid: PID,
    };
    trussed_usbip::Builder::new(virt::Ram::default(), options)
        .dispatch(Dispatch::new())
        .init_platform(move |platform| {
            let ui: Box<dyn trussed::platform::UserInterface + Send + Sync> =
                Box::new(UserInterface::new());
            platform.user_interface().set_inner(ui);
        })
        .build::<OpcardApp>()
        .exec(|_platform| {});
}
