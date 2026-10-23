// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

mod card;

use card::{generate_key_simple_transaction, secret_pin, with_card};
use openpgp_card::ocard::{algorithm::AlgoSimple, crypto::SigningAlgo, KeyType};
use test_log::test;

#[test]
fn gen_key() {
    if card::dangerous_real_card_enabled() {
        return;
    }

    with_card(|mut card| {
        card.with_tx(|mut tx| {
            let tx = &mut tx;
            let appdata = tx.application_related_data().unwrap();
            assert!(appdata.fingerprints().unwrap().signature().is_none());
            assert!(appdata.fingerprints().unwrap().decryption().is_none());
            assert!(appdata.fingerprints().unwrap().authentication().is_none());

            assert!(
                generate_key_simple_transaction(tx, KeyType::Signing, AlgoSimple::Curve25519,)
                    .is_err()
            );

            assert!(tx.verify_pw3(secret_pin(b"12345678")).is_ok());
            generate_key_simple_transaction(tx, KeyType::Signing, AlgoSimple::Curve25519).unwrap();
            let appdata = tx.application_related_data().unwrap();
            assert!(appdata.fingerprints().unwrap().signature().is_some());

            generate_key_simple_transaction(tx, KeyType::Decryption, AlgoSimple::Curve25519)
                .unwrap();
            let appdata = tx.application_related_data().unwrap();
            assert!(appdata.fingerprints().unwrap().decryption().is_some());

            generate_key_simple_transaction(tx, KeyType::Authentication, AlgoSimple::Curve25519)
                .unwrap();
            let appdata = tx.application_related_data().unwrap();
            assert!(appdata.fingerprints().unwrap().authentication().is_some());

            generate_key_simple_transaction(tx, KeyType::Signing, AlgoSimple::NIST256).unwrap();
            generate_key_simple_transaction(tx, KeyType::Decryption, AlgoSimple::NIST256).unwrap();
            generate_key_simple_transaction(tx, KeyType::Authentication, AlgoSimple::NIST256)
                .unwrap();

            assert!(tx.verify_pw1_sign(secret_pin(b"123456")).is_ok());
            tx.signature_for_hash(SigningAlgo::ECC, &[3; 32]).unwrap();
        })
    })
}
