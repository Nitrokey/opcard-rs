// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

mod card;

use card::with_card;
use openpgp_card::{algorithm::AlgoSimple, KeyType};
use test_log::test;

#[test]
fn gen_key() {
    with_card(|mut card| {
        card.with_tx(|mut tx| {
            assert!(tx.verify_pw3(b"12345678").is_ok());
            tx.generate_key_simple(
                |_, _, _| Ok([1; 20].into()),
                KeyType::Signing,
                AlgoSimple::Curve25519,
            )
            .unwrap();

            let appdata = tx.application_related_data().unwrap();
            assert_eq!(
                appdata
                    .fingerprints()
                    .unwrap()
                    .signature()
                    .unwrap()
                    .as_bytes(),
                &[1; 20]
            );
        })
    })
}
