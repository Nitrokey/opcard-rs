// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

mod card;

use card::with_card;
use openpgp_card::{
    algorithm::AlgoSimple,
    card_do::{Fingerprint, KeyGenerationTime},
    crypto_data::PublicKeyMaterial,
    KeyType,
};
use openpgp_card_sequoia::util::public_key_material_to_key;
use test_log::test;

fn public_key_material_to_fp(
    mat: &PublicKeyMaterial,
    time: KeyGenerationTime,
    ty: KeyType,
) -> Result<Fingerprint, openpgp_card::Error> {
    let key = public_key_material_to_key(mat, ty, &time, None, None)?;

    // Get fingerprint from the Sequoia Key
    let fp = key.fingerprint();
    fp.as_bytes().try_into()
}

#[test]
fn gen_key() {
    with_card(|mut card| {
        card.with_tx(|mut tx| {
            let appdata = tx.application_related_data().unwrap();
            assert!(appdata.fingerprints().unwrap().signature().is_none());
            assert!(appdata.fingerprints().unwrap().decryption().is_none());
            assert!(appdata.fingerprints().unwrap().authentication().is_none());

            assert!(tx.verify_pw3(b"12345678").is_ok());
            tx.generate_key_simple(
                public_key_material_to_fp,
                KeyType::Signing,
                AlgoSimple::Curve25519,
            )
            .unwrap();
            let appdata = tx.application_related_data().unwrap();
            assert!(appdata.fingerprints().unwrap().signature().is_some());

            tx.generate_key_simple(
                public_key_material_to_fp,
                KeyType::Decryption,
                AlgoSimple::Curve25519,
            )
            .unwrap();
            let appdata = tx.application_related_data().unwrap();
            assert!(appdata.fingerprints().unwrap().decryption().is_some());

            tx.generate_key_simple(
                public_key_material_to_fp,
                KeyType::Authentication,
                AlgoSimple::Curve25519,
            )
            .unwrap();
            let appdata = tx.application_related_data().unwrap();
            assert!(appdata.fingerprints().unwrap().authentication().is_some());

            tx.generate_key_simple(
                public_key_material_to_fp,
                KeyType::Signing,
                AlgoSimple::NIST256,
            )
            .unwrap();
            tx.generate_key_simple(
                public_key_material_to_fp,
                KeyType::Decryption,
                AlgoSimple::NIST256,
            )
            .unwrap();
            tx.generate_key_simple(
                public_key_material_to_fp,
                KeyType::Authentication,
                AlgoSimple::NIST256,
            )
            .unwrap();
        })
    })
}
