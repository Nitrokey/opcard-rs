// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

#![no_main]
use libfuzzer_sys::fuzz_target;
use opcard_fuzz::Input;

fuzz_target!(|input: Input| {
    // Logger is deactivated by default to reduce output.
    // The "log" feature is expected to be used for debugging crashes
    // Initialization errors are ignored because they would always happen
    // at the second run of the fuzz target
    #[cfg(feature = "log")]
    env_logger::builder().is_test(true).try_init().ok();

    opcard::virt::with_ram_client("opcard", move |client| {
        let Input {
            commands,
            manufacturer,
            serial,
            // mut historical_bytes,
            //button_available,
        } = input;
        //historical_bytes.truncate(15);
        let mut options = opcard::Options::default();
        options.manufacturer = manufacturer;
        options.serial = serial;
        //options.historical_bytes = heapless::Vec::from_slice(&historical_bytes).unwrap();
        //options.button_available = button_available;
        let mut card = opcard::Card::new(client, options);
        let mut reply = heapless::Vec::<u8, { 3 * 1024 }>::new();

        for data in commands {
            if let Ok(command) = iso7816::Command::<{ 10 * 1024 }>::try_from(&data) {
                reply.clear();
                card.handle(&command, &mut reply).ok();
            }
        }
    })
});
