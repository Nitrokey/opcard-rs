// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

#![no_main]
use libfuzzer_sys::fuzz_target;

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    data: Vec<Vec<u8>>,
    manufacturer: [u8; 2],
    serial: [u8; 4],
    historical_bytes: Vec<u8>,
    button_available: bool,
}

fuzz_target!(|input: Input| {
    trussed::virt::with_ram_client("opcard", move |client| {
        let Input {
            data,
            manufacturer,
            serial,
            mut historical_bytes,
            button_available,
        } = input;
        historical_bytes.truncate(15);
        let mut options = opcard::Options::default();
        options.manufacturer = manufacturer;
        options.serial = serial;
        options.historical_bytes = heapless::Vec::from_slice(&historical_bytes).unwrap();
        options.button_available = button_available;
        let mut card = opcard::Card::new(client, options);
        let mut reply = heapless::Vec::<u8, { 3 * 1024 }>::new();

        for d in data {
            if let Ok(command) = iso7816::Command::<{ 10 * 1024 }>::try_from(&d) {
                card.handle(&command, &mut reply).ok();
            }
        }
    })
});
