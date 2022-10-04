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
        rep.clear();

        let admin_pin_cmd: iso7816::Command<32> =
            iso7816::Command::try_from(hex!("00200083 08 3132333435363738").as_slice()).unwrap();
        card.handle(&admin_pin_cmd, &mut rep).unwrap();
        rep.clear();

        let user_pin_cmd: iso7816::Command<32> =
            iso7816::Command::try_from(hex!("00200082 06 313233343536").as_slice()).unwrap();
        card.handle(&user_pin_cmd, &mut rep).unwrap();

        let mut set_aes_key = Vec::from(hex!("0C DA 00D5 20 "));
        set_aes_key.extend_from_slice(&[0; 32]);
        let import_cmd: iso7816::Command<32> = iso7816::Command::try_from(&set_aes_key).unwrap();
        card.handle(&import_cmd, &mut rep).unwrap();

        let encrypt_aes = Vec::from(hex!("00 2A 86 80 10 00112233445566778899AABBCCDDEEFF 00"));
        let encrypt_cmd: iso7816::Command<16> = iso7816::Command::try_from(&encrypt_aes).unwrap();
        let mut rep: heapless::Vec<u8, 17> = heapless::Vec::new();
        card.handle(&encrypt_cmd, &mut rep).unwrap();
        assert_eq!(rep, hex!("02 1c060f4c9e7ea8d6ca961a2d64c05c18"));

        let mut decrypt_aes = Vec::from(hex!("00 2A 80 86 11"));
        decrypt_aes.extend_from_slice(&rep);
        decrypt_aes.push(0x00);

        let decrypt_cmd: iso7816::Command<17> = iso7816::Command::try_from(&decrypt_aes).unwrap();
        let mut rep: heapless::Vec<u8, 16> = heapless::Vec::new();
        card.handle(&decrypt_cmd, &mut rep).unwrap();
        assert_eq!(rep, hex!("00112233445566778899AABBCCDDEEFF"));
    })
}
