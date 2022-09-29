// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "virtual")]

mod card;
mod virt;

use openpgp_card::{algorithm::AlgoSimple, KeyType, OpenPgp};
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::Open;
use openpgp_card_sequoia::util::public_key_material_to_key;
use sequoia_openpgp::crypto::Decryptor;
use sequoia_openpgp::crypto::SessionKey;
use sequoia_openpgp::crypto::Signer;
use sequoia_openpgp::types::HashAlgorithm;

use test_log::test;

#[test]
fn sequoia_gen_key() {
    virt::with_vsc(|| {
        let mut cards = PcscBackend::cards(None).unwrap();
        let mut pgp = OpenPgp::new(cards.pop().unwrap());
        let mut open = Open::new(pgp.transaction().unwrap()).unwrap();
        open.verify_admin(b"12345678").unwrap();
        let mut admin = open.admin_card().unwrap();
        let (material, gendate) = admin
            .generate_key_simple(KeyType::Decryption, Some(AlgoSimple::NIST256))
            .unwrap();
        let dec_pubk =
            public_key_material_to_key(&material, KeyType::Decryption, &gendate, None, None)
                .unwrap();
        let dec_pubk_aut =
            public_key_material_to_key(&material, KeyType::Authentication, &gendate, None, None)
                .unwrap();

        let (material, gendate) = admin
            .generate_key_simple(KeyType::Authentication, Some(AlgoSimple::NIST256))
            .unwrap();
        let aut_pubk =
            public_key_material_to_key(&material, KeyType::Authentication, &gendate, None, None)
                .unwrap();
        let aut_pubk_dec =
            public_key_material_to_key(&material, KeyType::Decryption, &gendate, None, None)
                .unwrap();

        let (material, gendate) = admin
            .generate_key_simple(KeyType::Signing, Some(AlgoSimple::NIST256))
            .unwrap();
        let sign_pubk =
            public_key_material_to_key(&material, KeyType::Signing, &gendate, None, None).unwrap();

        open.verify_user_for_signing(b"123456").unwrap();
        let mut sign_card = open.signing_card().unwrap();
        let mut signer = sign_card.signer_from_public(sign_pubk.clone(), &|| {});
        let data = [1; 32];
        let signature = signer.sign(HashAlgorithm::SHA256, &data).unwrap();
        assert!(sign_pubk
            .verify(&signature, HashAlgorithm::SHA256, &data)
            .is_ok());

        open.verify_user(b"123456").unwrap();
        let mut user_card = open.user_card().unwrap();
        let mut authenticator = user_card.authenticator_from_public(aut_pubk.clone(), &|| {});
        let data = [2; 32];
        let signature = authenticator.sign(HashAlgorithm::SHA256, &data).unwrap();
        assert!(dec_pubk_aut
            .verify(&signature, HashAlgorithm::SHA256, &data)
            .is_err());
        assert!(aut_pubk
            .verify(&signature, HashAlgorithm::SHA256, &data)
            .is_ok());

        let mut session = SessionKey::new(19);
        session[0] = 7;
        let ciphertext = dec_pubk.encrypt(&session).unwrap();
        let mut decryptor = user_card.decryptor_from_public(dec_pubk, &|| {});
        assert_eq!(session, decryptor.decrypt(&ciphertext, Some(32)).unwrap());

        open.manage_security_environment(KeyType::Authentication, KeyType::Decryption)
            .unwrap();
        let mut user_card = open.user_card().unwrap();
        let mut authenticator = user_card.authenticator_from_public(aut_pubk.clone(), &|| {});
        let data = [3; 32];
        let signature = authenticator.sign(HashAlgorithm::SHA256, &data).unwrap();
        assert!(aut_pubk
            .verify(&signature, HashAlgorithm::SHA256, &data)
            .is_err());
        dec_pubk_aut
            .verify(&signature, HashAlgorithm::SHA256, &data)
            .unwrap();

        open.manage_security_environment(KeyType::Decryption, KeyType::Authentication)
            .unwrap();
        let mut user_card = open.user_card().unwrap();
        let mut session = SessionKey::new(19);
        session[0] = 7;
        let ciphertext = aut_pubk_dec.encrypt(&session).unwrap();
        let mut decryptor = user_card.decryptor_from_public(aut_pubk_dec, &|| {});
        assert_eq!(session, decryptor.decrypt(&ciphertext, Some(32)).unwrap());
    });

    virt::with_vsc(|| {
        let mut cards = PcscBackend::cards(None).unwrap();
        let mut pgp = OpenPgp::new(cards.pop().unwrap());
        let mut open = Open::new(pgp.transaction().unwrap()).unwrap();
        open.verify_admin(b"12345678").unwrap();
        let mut admin = open.admin_card().unwrap();

        let (material, gendate) = admin
            .generate_key_simple(KeyType::Decryption, Some(AlgoSimple::Curve25519))
            .unwrap();
        let dec_pubk =
            public_key_material_to_key(&material, KeyType::Decryption, &gendate, None, None)
                .unwrap();

        let (material, gendate) = admin
            .generate_key_simple(KeyType::Authentication, Some(AlgoSimple::Curve25519))
            .unwrap();
        let aut_pubk =
            public_key_material_to_key(&material, KeyType::Authentication, &gendate, None, None)
                .unwrap();

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

        open.verify_user(b"123456").unwrap();
        let mut user_card = open.user_card().unwrap();
        let mut authenticator = user_card.authenticator_from_public(aut_pubk.clone(), &|| {});
        let data = [2; 32];
        let signature = authenticator.sign(HashAlgorithm::SHA256, &data).unwrap();
        assert!(aut_pubk
            .verify(&signature, HashAlgorithm::SHA256, &data)
            .is_ok());

        let mut session = SessionKey::new(19);
        session[0] = 7;
        let ciphertext = dec_pubk.encrypt(&session).unwrap();
        let mut decryptor = user_card.decryptor_from_public(dec_pubk.clone(), &|| {});
        assert_eq!(session, decryptor.decrypt(&ciphertext, None).unwrap());

        open.manage_security_environment(KeyType::Authentication, KeyType::Decryption)
            .unwrap();
        let mut user_card = open.user_card().unwrap();
        let mut authenticator = user_card.authenticator_from_public(aut_pubk, &|| {});
        let data = [3; 32];
        // Signature with X25519 key should fail
        let _ = authenticator
            .sign(HashAlgorithm::SHA256, &data)
            .unwrap_err();

        open.manage_security_environment(KeyType::Decryption, KeyType::Authentication)
            .unwrap();
        let mut user_card = open.user_card().unwrap();
        let mut session = SessionKey::new(19);
        session[0] = 7;
        let ciphertext = dec_pubk.encrypt(&session).unwrap();
        let mut decryptor = user_card.decryptor_from_public(dec_pubk, &|| {});

        // X25519 with and EdDSA key should fail
        decryptor.decrypt(&ciphertext, None).unwrap_err();
    });
}
