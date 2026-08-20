// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

//! USB/IP runner for opcard.
//! Run with cargo run --example --features apdu-dispatch (and optionally rsa4096-gen)

use littlefs2::{
    const_ram_storage,
    fs::{Allocation, Filesystem},
};
use littlefs2_core::{path, DynFilesystem};
use trussed::{
    pipe::{ServiceEndpoint, TrussedChannel},
    types::CoreContext,
    virt::UserInterface,
    Platform as _, Service,
};
use trussed_usbip::{Client, Platform, Store, Syscall};

use dev_vpicc::virt::dispatch::{self, Backend, Dispatch, DispatchContext};

type VirtClient = Client<Dispatch>;

const MANUFACTURER: &str = "Nitrokey";
const PRODUCT: &str = "Nitrokey 3";
const VID: u16 = 0x20a0;
const PID: u16 = 0x42b2;

struct OpcardApp {
    opcard: opcard::Card<VirtClient>,
}

impl trussed_usbip::Apps<'_, Dispatch> for OpcardApp {
    type Data = ();
    fn new(
        _service: &mut Service<Platform, Dispatch>,
        endpoints: &mut Vec<ServiceEndpoint<'static, Backend, DispatchContext>>,
        syscall: Syscall,
        _data: (),
    ) -> Self {
        static CHANNEL: TrussedChannel = TrussedChannel::new();
        let (requester, responder) = CHANNEL.split().unwrap();
        let context = CoreContext::new(path!("opcard").into());
        endpoints.push(ServiceEndpoint::new(responder, context, dispatch::BACKENDS));
        let client = VirtClient::new(requester, syscall, None);
        OpcardApp {
            opcard: opcard::Card::new(client, opcard::Options::default()),
        }
    }

    fn with_ccid_apps<T>(&mut self, f: impl FnOnce(&mut [&mut dyn apdu_dispatch::App]) -> T) -> T {
        f(&mut [&mut self.opcard])
    }
}

const_ram_storage!(RamStorage, 512 * 128);

fn ram_filesystem() -> &'static dyn DynFilesystem {
    let storage = Box::leak(Box::new(RamStorage::new()));
    Filesystem::format(storage).expect("failed to format RAM filesystem");
    let alloc = Box::leak(Box::new(Allocation::new()));
    let fs = Filesystem::mount(alloc, storage).expect("failed to mount RAM filesystem");
    Box::leak(Box::new(fs))
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
    let store = Store {
        ifs: ram_filesystem(),
        efs: ram_filesystem(),
        vfs: ram_filesystem(),
    };
    let mut platform = Platform::new(store);
    let ui: Box<dyn trussed::platform::UserInterface + Send + Sync> =
        Box::new(UserInterface::new());
    platform.user_interface().set_inner(ui);
    trussed_usbip::Builder::new(options)
        .dispatch(Dispatch::new())
        .build::<OpcardApp>()
        .exec(platform, ());
}
