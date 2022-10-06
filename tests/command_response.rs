// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "virtual")]

use hex_literal::hex;

#[test_log::test]
fn command_response() {
    trussed::virt::with_ram_client("opcard", |client| {
        let mut card = opcard::Card::new(client, opcard::Options::default());
        let reset_command: iso7816::Command<4> =
            iso7816::Command::try_from(&hex!("00 44 0000")).unwrap();
        let mut rep: heapless::Vec<u8, 0> = heapless::Vec::new();
        card.handle(&reset_command, &mut rep).unwrap();

        let get_challenge: iso7816::Command<5> =
            iso7816::Command::try_from(&hex!("00 84 0000 0A")).unwrap();
        let mut rep: heapless::Vec<u8, 16> = heapless::Vec::new();
        card.handle(&get_challenge, &mut rep).unwrap();
        assert_eq!(rep.len(), 10);
        // Sanity check that it's not uninitialized or something
        assert_ne!(rep, [0; 10]);

        let get_challenge: iso7816::Command<5> =
            iso7816::Command::try_from(&hex!("00 84 0000 00 0400")).unwrap();
        let mut rep: heapless::Vec<u8, 1024> = heapless::Vec::new();
        card.handle(&get_challenge, &mut rep).unwrap();
        assert_eq!(rep.len(), 1024);
        // Sanity check that it's not uninitialized or something
        assert_ne!(rep, [0; 1024]);
    })
}
