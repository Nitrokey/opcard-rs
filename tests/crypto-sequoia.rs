// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "virtual")]

mod card;
mod virt;

use openpgp_card::{algorithm::AlgoSimple, KeyType, OpenPgp};
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::Open;
use openpgp_card_sequoia::util::public_key_material_to_key;
use sequoia_openpgp::crypto::Signer;
use sequoia_openpgp::types::HashAlgorithm;

use test_log::test;

#[test]
fn sign() {
    virt::with_vsc(|| {
        let mut cards = PcscBackend::cards(None).unwrap();
        let mut pgp = OpenPgp::new(&mut cards[0]);
        let mut open = Open::new(pgp.transaction().unwrap()).unwrap();
        open.verify_admin(b"12345678").unwrap();
        let mut admin = open.admin_card().unwrap();
        let (material, gendate) = admin
            .generate_key_simple(KeyType::Signing, Some(AlgoSimple::NIST256))
            .unwrap();
        let pubk =
            public_key_material_to_key(&material, KeyType::Signing, &gendate, None, None).unwrap();

        open.verify_user_for_signing(b"123456").unwrap();
        let mut sign_card = open.signing_card().unwrap();
        let mut signer = sign_card.signer_from_public(pubk.clone(), &|| {});
        let data = [1; 32];
        let signature = signer.sign(HashAlgorithm::SHA256, &data).unwrap();
        assert!(pubk
            .verify(&signature, HashAlgorithm::SHA256, &data)
            .is_ok());
    });

    virt::with_vsc(|| {
        let mut cards = PcscBackend::cards(None).unwrap();
        let mut pgp = OpenPgp::new(&mut cards[0]);
        let mut open = Open::new(pgp.transaction().unwrap()).unwrap();
        open.verify_admin(b"12345678").unwrap();
        let mut admin = open.admin_card().unwrap();
        let (material, gendate) = admin
            .generate_key_simple(KeyType::Signing, Some(AlgoSimple::Curve25519))
            .unwrap();
        let pubk =
            public_key_material_to_key(&material, KeyType::Signing, &gendate, None, None).unwrap();

        open.verify_user_for_signing(b"123456").unwrap();
        let mut sign_card = open.signing_card().unwrap();
        let mut signer = sign_card.signer_from_public(pubk.clone(), &|| {});
        let data = [1; 32];
        let signature = signer.sign(HashAlgorithm::SHA256, &data).unwrap();
        assert!(pubk
            .verify(&signature, HashAlgorithm::SHA256, &data)
            .is_ok());
    });
}
