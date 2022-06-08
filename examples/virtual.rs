// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

// To use this, make sure that you have vpcd from vsmartcard installed and configured (e. g.
// install vsmartcard-vpcd on Debian).  You might have to restart your pcscd, e. g.
// `systemctl restart pcscd pcscd.socket`.
//
// Now you should be able to see the card in `pcsc_scan` and talk to it with `gpg --card-status` or
// with this code snippet using `openpgp-card-client`:
//
//    let context = pcsc::Context::establish(pcsc::Scope::User)
//        .expect("failed to establish context");
//    let readers = context.list_readers_owned()
//        .expect("failed to list readers");
//    assert!(readers.len() > 0);
//    let card = context.connect(&readers[0], pcsc::ShareMode::Shared, pcsc::Protocols::T1)
//        .expect("failed to connect card");
//    let mut client = openpgp_card_client::Client::new(card).expect("failed to create client");
//    assert!(client.verify(b"12345678").is_err());
//    assert!(client.verify(b"123456").is_ok());
//
// https://git.sr.ht/~ireas/openpgp-card-client
//
// Set `RUST_LOG=opcard::card=info` to see the executed commands.

// TODO: add CLI

fn main() {
    env_logger::init();

    let backend = opcard::backend::SoftwareBackend::new("/tmp/opcard");
    let card = opcard::Card::new(backend, opcard::Options::default());
    let virtual_card = opcard::VirtualCard::new(card);
    let mut vpicc = vpicc::SmartCard::with_card(virtual_card);
    vpicc.run();
}
