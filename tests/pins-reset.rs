// Copyright (C) 2023 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(all(feature = "virt", not(feature = "dangerous-test-real-card")))]

mod card;
use card::Card;
use heapless_bytes::Bytes;
use hex_literal::hex;
use trussed::{
    client::*,
    syscall,
    types::{Message, PathBuf},
};
use trussed_auth::AuthClient;

use test_log::test;

#[test]
// Fails because of https://gitlab.com/openpgp-card/openpgp-card/-/issues/70
// Tested with the VPICC example that it works with gpg
#[ignore]
fn factory_reset_pins_no_data() {
    opcard::virt::with_ram_client("opcard", |mut client| {
        #[allow(clippy::unwrap_used)]
        let default_user_pin = Bytes::from_slice(b"123456").unwrap();
        #[allow(clippy::unwrap_used)]
        let default_admin_pin = Bytes::from_slice(b"12345678").unwrap();
        syscall!(client.set_pin(0, default_user_pin, Some(3), true,));
        syscall!(client.set_pin(1, default_admin_pin, Some(3), true,));
        // Here we create an invalid (empty state) but with Pins set

        let mut card = Card::from_opcard(opcard::Card::new(client, opcard::Options::default()));
        card.with_tx(|mut tx| {
            let _appdata = tx.application_related_data().unwrap();
            let cardholder_related_data = tx.cardholder_related_data().unwrap();
            assert_eq!(
                cardholder_related_data.name(),
                Some(b"Card state corrupted.".as_slice())
            );
            tx.factory_reset().unwrap();
            let cardholder_related_data = tx.cardholder_related_data().unwrap();
            assert_eq!(cardholder_related_data.name(), Some([].as_slice()));
        });
    });
}

// Fails because of https://gitlab.com/openpgp-card/openpgp-card/-/issues/70
// Tested with the VPICC example that it works with gpg
#[test]
#[ignore]
fn factory_reset_pins_bad_data() {
    opcard::virt::with_ram_client("opcard", |mut client| {
        let options = opcard::Options::default();
        #[allow(clippy::unwrap_used)]
        let default_user_pin = Bytes::from_slice(b"123456").unwrap();
        #[allow(clippy::unwrap_used)]
        let default_admin_pin = Bytes::from_slice(b"12345678").unwrap();
        syscall!(client.set_pin(0, default_user_pin, Some(3), true,));
        syscall!(client.set_pin(1, default_admin_pin, Some(3), true,));
        syscall!(client.write_file(
            options.storage,
            PathBuf::from("persistent-state.cbor"),
            Message::from_slice(&hex!("AAAAAAAAAAAAAAAAAA")).unwrap(),
            None
        ));
        // Here we create an invalid (empty state) but with Pins set

        let mut card = Card::from_opcard(opcard::Card::new(client, options));
        card.with_tx(|mut tx| {
            let _appdata = tx.application_related_data().unwrap();
            let cardholder_related_data = tx.cardholder_related_data().unwrap();
            assert_eq!(
                cardholder_related_data.name(),
                Some(b"Card state corrupted.".as_slice())
            );
            tx.factory_reset().unwrap();
            let cardholder_related_data = tx.cardholder_related_data().unwrap();
            assert_eq!(cardholder_related_data.name(), Some([].as_slice()));
        });
    });
}
