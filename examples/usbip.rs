// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

//! USB/IP runner for opcard.
//! Run with cargo run --example --features apdu-dispatch (and optionally rsa4096-gen)

use trussed::virt::{self, Ram, UserInterface};
use trussed::{ClientImplementation, Platform};
use trussed_usbip::ClientBuilder;

use opcard::virt::dispatch::{self, Dispatch};

type VirtClient =
    ClientImplementation<trussed_usbip::Service<Ram, dispatch::Dispatch>, dispatch::Dispatch>;

const MANUFACTURER: &str = "Nitrokey";
const PRODUCT: &str = "Nitrokey 3";
const VID: u16 = 0x20a0;
const PID: u16 = 0x42b2;

struct OpcardApp {
    opcard: opcard::Card<VirtClient>,
}

impl trussed_usbip::Apps<VirtClient, Dispatch> for OpcardApp {
    type Data = ();
    fn new<B: ClientBuilder<VirtClient, Dispatch>>(builder: &B, _data: ()) -> Self {
        OpcardApp {
            opcard: opcard::Card::new(
                builder.build("opcard", dispatch::BACKENDS),
                opcard::Options::default(),
            ),
        }
    }

    fn with_ccid_apps<T>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn apdu_dispatch::App<7609, 7609>]) -> T,
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
