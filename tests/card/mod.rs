// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![allow(unused)]

use std::{
    io::BufReader,
    sync::{Arc, Mutex},
};

use card_backend::{CardBackend, CardCaps, CardTransaction, PinType, SmartcardError};
use dev_vpicc::virt::VirtClient;
use iso7816::{
    command::{CommandView, FromSliceError},
    Command, Status,
};
use opcard::Options;
use openpgp_card::{
    ocard::{
        algorithm::{AlgoSimple, AlgorithmAttributes, Curve, EccAttributes, RsaAttributes},
        crypto::{EccPub, EccType, PublicKeyMaterial},
        data::{Fingerprint, KeyGenerationTime},
        KeyType, OpenPGP, Transaction as OpenPgpTransaction,
    },
    state::{Admin, Open},
    Error,
};
use pgp::{
    composed::{Message, MessageBuilder, PlainSessionKey},
    crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::PublicKey,
    types::{EncryptionKey, EskType, Password, PkeskBytes},
};

use openpgp_card_rpgp::{public_key_material_to_key, CardSlot};
use pgp::types::KeyDetails;

use secrecy::SecretBox;
use trussed::virt::StoreConfig;
use trussed::{virt::Platform, Service};
use trussed_auth::AuthClient;

const REQUEST_LEN: usize = 7609;
const RESPONSE_LEN: usize = 7609;

pub fn dangerous_real_card_enabled() -> bool {
    option_env!("DANGEROUS_TEST_RUN_REAL_CARD") == Some("true")
}

#[derive(Debug)]
pub struct Card<T: opcard::Client + Send + Sync + 'static>(Arc<Mutex<opcard::Card<T>>>);

impl<T: opcard::Client + Send + Sync + 'static> Card<T> {
    pub fn new(client: T) -> Self {
        Self::with_options(client, Options::default())
    }

    pub fn with_options(client: T, options: Options) -> Self {
        let card = opcard::Card::new(client, options);
        Self::from_opcard(card)
    }

    pub fn from_opcard(card: opcard::Card<T>) -> Self {
        Self(Arc::new(Mutex::new(card)))
    }

    pub fn with_tx<F: FnOnce(OpenPgpTransaction<'_>) -> R, R>(&mut self, f: F) -> R {
        let dyn_b: Box<(dyn CardBackend + Send + Sync + 'static)> = Box::new(Self(self.0.clone()));
        let mut openpgp = OpenPGP::new(dyn_b).unwrap();
        let tx = openpgp.transaction().expect("failed to create transaction");
        f(tx)
    }

    pub fn with_card<F: FnOnce(openpgp_card::Card<openpgp_card::state::Transaction>) -> R, R>(
        &mut self,
        f: F,
    ) -> R {
        let dyn_b: Box<(dyn CardBackend + Send + Sync + 'static)> = Box::new(Self(self.0.clone()));
        let mut card = openpgp_card::Card::new(dyn_b).unwrap();

        f(card.transaction().unwrap())
    }

    pub fn with_many_tx(
        &mut self,
        fs: impl IntoIterator<Item = impl FnOnce(OpenPgpTransaction<'_>)>,
    ) {
        for f in fs {
            self.with_tx(f);
            self.0.lock().unwrap().reset();
        }
    }

    pub fn reset(&self) {
        self.0.lock().unwrap().reset();
    }
}

impl<T: opcard::Client + Send + Sync + 'static> CardBackend for Card<T> {
    fn limit_card_caps(&self, card_caps: CardCaps) -> CardCaps {
        card_caps
    }

    fn transaction(
        &mut self,
        _reselect_application: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + Sync>, SmartcardError> {
        let mut transaction = Transaction {
            card: self.0.clone(),
            caps: None,
            buffer: heapless::Vec::new(),
        };
        // CardTransaction::initialize(&mut transaction).unwrap();
        Ok(Box::new(transaction))
    }
}

#[derive(Debug)]
pub struct Transaction<T: opcard::Client + Send + Sync + 'static> {
    card: Arc<Mutex<opcard::Card<T>>>,
    caps: Option<CardCaps>,
    buffer: heapless::Vec<u8, RESPONSE_LEN>,
}

impl<T: opcard::Client + Send + Sync + 'static> Transaction<T> {
    fn handle(&mut self, command: &[u8]) -> Result<(), Status> {
        self.buffer.clear();
        let command = CommandView::try_from(command).map_err(|err| match err {
            FromSliceError::InvalidSliceLength
            | FromSliceError::TooShort
            | FromSliceError::TooLong => Status::WrongLength,
            FromSliceError::InvalidClass => Status::ClassNotSupported,
            FromSliceError::InvalidFirstBodyByteForExtended => Status::UnspecifiedCheckingError,
        })?;
        let mut card = self.card.lock().expect("failed to lock card");
        card.handle(command, &mut self.buffer)
    }
}

impl<T: opcard::Client + Send + Sync + 'static> CardTransaction for Transaction<T> {
    fn transmit(&mut self, command: &[u8], _buf_size: usize) -> Result<Vec<u8>, SmartcardError> {
        let status = self.handle(command).err().unwrap_or_default();
        let status: [u8; 2] = status.into();
        let mut response = Vec::with_capacity(self.buffer.len() + 2);
        response.extend_from_slice(&self.buffer);
        response.extend_from_slice(&status);
        Ok(response)
    }

    fn was_reset(&self) -> bool {
        false
    }

    fn feature_pinpad_verify(&self) -> bool {
        false
    }

    fn feature_pinpad_modify(&self) -> bool {
        false
    }

    fn pinpad_verify(
        &mut self,
        _pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        unimplemented!();
    }

    fn pinpad_modify(
        &mut self,
        _pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        unimplemented!();
    }
}

pub fn with_card_options<F: FnOnce(Card<VirtClient<'_>>) -> R, R>(options: Options, f: F) -> R {
    dev_vpicc::virt::with_leaking_client(StoreConfig::ram(), "opcard", |client| {
        f(Card::from_opcard(opcard::Card::new(client, options)))
    })
}

pub fn with_card<F: FnOnce(Card<VirtClient<'_>>) -> R, R>(f: F) -> R {
    with_card_options(Options::default(), f)
}

pub fn with_tx_options<F: FnOnce(OpenPgpTransaction<'_>) -> R, R>(options: Options, f: F) -> R {
    with_card_options(options, move |mut card| card.with_tx(f))
}

pub fn with_tx<F: FnOnce(OpenPgpTransaction<'_>) -> R, R>(f: F) -> R {
    with_card(move |mut card| card.with_tx(f))
}

pub fn with_many_tx(fs: impl IntoIterator<Item = impl FnOnce(OpenPgpTransaction<'_>)>) {
    with_card(move |mut card| card.with_many_tx(fs))
}

pub fn error_to_retries(err: Result<(), openpgp_card::Error>) -> Option<u8> {
    match err {
        Ok(()) => None,
        Err(openpgp_card::Error::CardStatus(
            openpgp_card::ocard::StatusBytes::PasswordNotChecked(c),
        )) => Some(c),
        Err(e) => panic!("Unexpected error {e}"),
    }
}
const IDENT: &str = concat!(
    env!("OPCARD_DANGEROUS_TEST_CARD_PGP_VENDOR"),
    ":",
    env!("OPCARD_DANGEROUS_TEST_CARD_PGP_SERIAL")
);

#[allow(unused)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgo {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Cv25519,
    P256,
    P384,
    P521,
}

impl From<KeyAlgo> for AlgoSimple {
    fn from(value: KeyAlgo) -> Self {
        match value {
            KeyAlgo::Rsa2048 => AlgoSimple::RSA2k,
            KeyAlgo::Rsa3072 => AlgoSimple::RSA3k,
            KeyAlgo::Rsa4096 => AlgoSimple::RSA4k,
            KeyAlgo::Cv25519 => AlgoSimple::Curve25519,
            KeyAlgo::P256 => AlgoSimple::NIST256,
            KeyAlgo::P384 => AlgoSimple::NIST384,
            KeyAlgo::P521 => AlgoSimple::NIST521,
        }
    }
}

impl KeyAlgo {
    fn hash_algo(self) -> HashAlgorithm {
        match self {
            KeyAlgo::Rsa2048 => HashAlgorithm::Sha256,
            KeyAlgo::Rsa3072 => HashAlgorithm::Sha384,
            KeyAlgo::Rsa4096 => HashAlgorithm::Sha512,
            KeyAlgo::Cv25519 => HashAlgorithm::Sha256,
            KeyAlgo::P256 => HashAlgorithm::Sha256,
            KeyAlgo::P384 => HashAlgorithm::Sha384,
            KeyAlgo::P521 => HashAlgorithm::Sha512,
        }
    }

    fn plaintext_len(self) -> usize {
        match self {
            KeyAlgo::Rsa2048 => 32,
            KeyAlgo::Rsa3072 => 48,
            KeyAlgo::Rsa4096 => 64,
            KeyAlgo::Cv25519 => 32,
            KeyAlgo::P256 => 32,
            KeyAlgo::P384 => 48,
            KeyAlgo::P521 => 64,
        }
    }

    fn can_work_with_mse(self) -> bool {
        match self {
            KeyAlgo::Cv25519 => false,
            KeyAlgo::Rsa2048
            | KeyAlgo::Rsa3072
            | KeyAlgo::Rsa4096
            | KeyAlgo::P256
            | KeyAlgo::P384
            | KeyAlgo::P521 => true,
        }
    }
}

fn change_ecc_type(material: PublicKeyMaterial, old: EccType, new: EccType) -> PublicKeyMaterial {
    let PublicKeyMaterial::E(e) = material else {
        return material;
    };
    let data = e.data();
    let AlgorithmAttributes::Ecc(attrs) = e.algo() else {
        unreachable!("ECC without ECC attributes")
    };

    assert_eq!(attrs.ecc_type(), old);
    PublicKeyMaterial::E(EccPub::new(
        data.into(),
        AlgorithmAttributes::Ecc(EccAttributes::new(
            new,
            attrs.curve().clone(),
            attrs.import_format(),
        )),
    ))
}

fn ecdh_to_ecdsa(material: PublicKeyMaterial) -> PublicKeyMaterial {
    change_ecc_type(material, EccType::ECDH, EccType::ECDSA)
}

fn ecdsa_to_ecdh(material: PublicKeyMaterial) -> PublicKeyMaterial {
    change_ecc_type(material, EccType::ECDSA, EccType::ECDH)
}

fn checksum_plaintext(plaintext: &[u8]) -> Vec<u8> {
    let mut tmp = vec![0; 1];
    tmp.extend_from_slice(plaintext);
    tmp.extend_from_slice(&pgp::crypto::checksum::calculate_simple(plaintext).to_be_bytes());
    tmp
}

fn encrypt_for_key(plaintext: &[u8], public_key: &PublicKey) -> PkeskBytes {
    let mut rng = rand::thread_rng();
    public_key
        .encrypt(
            rand::thread_rng(),
            &checksum_plaintext(plaintext),
            EskType::V3_4,
        )
        .unwrap()
}

pub fn rpgp_test(algo: KeyAlgo) {
    use openpgp_card::ocard::KeyType;
    use openpgp_card::{state::Open, Card};
    use openpgp_card_rpgp::public_key_material_to_key;
    use pgp::crypto::Decryptor;
    use pgp::crypto::Signer;
    use pgp::types::{DecryptionKey, EncryptionKey, SigningKey, VerifyingKey};

    let mut card: Card<Open> = Card::open_by_ident(
        card_backend_pcsc::PcscBackend::card_backends(None).unwrap(),
        IDENT,
    )
    .unwrap();
    let mut open = card.transaction().unwrap();
    open.verify_admin_pin(secret_str("12345678")).unwrap();
    let mut admin = open.as_admin_card(None).unwrap();
    let (material, gendate) =
        generate_key_simple(&mut admin, KeyType::Decryption, algo.into()).unwrap();

    let dec_pubk =
        public_key_material_to_key(&material, KeyType::Decryption, &gendate, None, None).unwrap();
    let dec_pubk_aut = algo.can_work_with_mse().then(|| {
        public_key_material_to_key(
            &ecdh_to_ecdsa(material),
            KeyType::Authentication,
            &gendate,
            None,
            None,
        )
        .unwrap()
    });

    println!("======== GENERATED {algo:?} Decryption key =======");

    let (material, gendate) =
        generate_key_simple(&mut admin, KeyType::Authentication, algo.into()).unwrap();
    let aut_pubk =
        public_key_material_to_key(&material, KeyType::Authentication, &gendate, None, None)
            .unwrap();
    let aut_pubk_dec = algo.can_work_with_mse().then(|| {
        public_key_material_to_key(
            &ecdsa_to_ecdh(material),
            KeyType::Decryption,
            &gendate,
            None,
            None,
        )
        .unwrap()
    });

    println!("======== GENERATED {algo:?} Authentication key =======");

    let (material, gendate) =
        generate_key_simple(&mut admin, KeyType::Signing, algo.into()).unwrap();
    let sign_pubk =
        public_key_material_to_key(&material, KeyType::Signing, &gendate, None, None).unwrap();

    println!("======== GENERATED {algo:?} Signing key =======");

    open.verify_user_signing_pin(secret_str("123456")).unwrap();
    let mut signer =
        CardSlot::with_public_key(&mut open, KeyType::Signing, sign_pubk.clone(), &|| {}).unwrap();
    let data = vec![1; algo.plaintext_len()];
    let signature = signer
        .sign(&Password::empty(), algo.hash_algo(), &data)
        .unwrap();
    assert!(sign_pubk
        .verify(algo.hash_algo(), &data, &signature)
        .is_ok());

    println!("======== Verified signature =======");

    open.verify_user_pin(secret_str("123456")).unwrap();
    let mut authenticator =
        CardSlot::with_public_key(&mut open, KeyType::Authentication, aut_pubk.clone(), &|| {})
            .unwrap();
    let data = vec![2; algo.plaintext_len()];
    let signature = authenticator
        .sign(&Password::empty(), algo.hash_algo(), &data)
        .unwrap();
    if let Some(dec_pubk_aut) = &dec_pubk_aut {
        assert!(dec_pubk_aut
            .verify(algo.hash_algo(), &data, &signature)
            .is_err());
    }
    assert!(aut_pubk.verify(algo.hash_algo(), &data, &signature).is_ok());

    println!("======== Verified authentication =======");

    let plaintext = b"plaintext";
    let ciphertext = encrypt_for_key(plaintext, &dec_pubk);
    let mut decryptor =
        CardSlot::with_public_key(&mut open, KeyType::Decryption, dec_pubk.clone(), &|| {})
            .unwrap();
    let PlainSessionKey::V3_4 { key: ref other, .. } = decryptor
        .decrypt(&Password::empty(), &ciphertext, EskType::V3_4)
        .unwrap()
        .unwrap()
    else {
        unreachable!()
    };
    assert_eq!(plaintext.as_slice(), other.as_ref());

    if algo.can_work_with_mse() {
        open.manage_security_environment(KeyType::Authentication, KeyType::Decryption)
            .unwrap();
        let mut user_card = open.as_user_card(None).unwrap();
        let mut authenticator = CardSlot::with_public_key(
            &mut open,
            KeyType::Authentication,
            dec_pubk_aut.clone().unwrap(),
            &|| {},
        )
        .unwrap();
        let data = vec![3; algo.plaintext_len()];
        if algo.can_work_with_mse() {
            let signature = authenticator
                .sign(&Password::empty(), algo.hash_algo(), &data)
                .unwrap();
            assert!(aut_pubk
                .verify(algo.hash_algo(), &data, &signature)
                .is_err());
            dec_pubk_aut
                .as_ref()
                .unwrap()
                .verify(algo.hash_algo(), &data, &signature)
                .unwrap();
        } else {
            assert!(authenticator
                .sign(&Password::empty(), algo.hash_algo(), &data)
                .is_err());
        }

        println!("======== Verified MSE 1 =======");

        open.manage_security_environment(KeyType::Decryption, KeyType::Authentication)
            .unwrap();
        let mut user_card = open.as_user_card(None).unwrap();
        let plaintext = b"plaintext";
        if algo.can_work_with_mse() {
            let plaintext = b"plaintext";
            let ciphertext = encrypt_for_key(plaintext, aut_pubk_dec.as_ref().unwrap());
            let mut decryptor = CardSlot::with_public_key(
                &mut open,
                KeyType::Decryption,
                aut_pubk_dec.clone().unwrap(),
                &|| {},
            )
            .unwrap();
            let PlainSessionKey::V3_4 { key: ref other, .. } = decryptor
                .decrypt(&Password::empty(), &ciphertext, EskType::V3_4)
                .unwrap()
                .unwrap()
            else {
                unreachable!()
            };
            assert_eq!(plaintext.as_slice(), other.as_ref());
        } else {
            let mut decryptor = CardSlot::with_public_key(
                &mut open,
                KeyType::Decryption,
                aut_pubk_dec.clone().unwrap(),
                &|| {},
            )
            .unwrap();
            let plaintext = b"plaintext";
            let ciphertext = encrypt_for_key(plaintext, aut_pubk_dec.as_ref().unwrap());
            assert!(decryptor
                .decrypt(&Password::empty(), &ciphertext, EskType::V3_4)
                .is_err());
        }

        println!("======== Verified MSE 2 =======");
    }

    open.factory_reset().unwrap();
}

pub fn secret_pin(data: &[u8]) -> SecretBox<[u8]> {
    SecretBox::new(data.into())
}

pub fn secret_str(data: &str) -> SecretBox<str> {
    SecretBox::new(data.into())
}

pub fn public_key_material_to_fp(
    mat: &PublicKeyMaterial,
    time: KeyGenerationTime,
    ty: KeyType,
) -> Result<Fingerprint, openpgp_card::Error> {
    let key = public_key_material_to_key(mat, ty, &time, None, None).unwrap();

    // Get fingerprint from the rpgp Key
    let fp = key.fingerprint();
    fp.as_bytes().try_into()
}

pub fn generate_key_simple(
    card: &mut openpgp_card::Card<Admin>,
    key_type: KeyType,
    algo: AlgoSimple,
) -> Result<(PublicKeyMaterial, KeyGenerationTime), openpgp_card::Error> {
    card.set_algorithm(key_type, algo)?;
    card.generate_key(public_key_material_to_fp, key_type)
}

pub fn generate_key_simple_transaction(
    card: &mut OpenPgpTransaction,
    key_type: KeyType,
    algo: AlgoSimple,
) -> Result<(PublicKeyMaterial, KeyGenerationTime), openpgp_card::Error> {
    let attributes =
        match (algo, key_type) {
            (AlgoSimple::RSA2k, _) => AlgorithmAttributes::Rsa(RsaAttributes::new(2048, 32, 0)),
            (AlgoSimple::RSA3k, _) => AlgorithmAttributes::Rsa(RsaAttributes::new(3072, 32, 0)),
            (AlgoSimple::RSA4k, _) => AlgorithmAttributes::Rsa(RsaAttributes::new(4096, 32, 0)),
            (AlgoSimple::NIST256, KeyType::Decryption) => AlgorithmAttributes::Ecc(
                EccAttributes::new(EccType::ECDH, Curve::NistP256r1, Some(0xFF)),
            ),
            (AlgoSimple::NIST256, _) => AlgorithmAttributes::Ecc(EccAttributes::new(
                EccType::ECDSA,
                Curve::NistP256r1,
                Some(0xFF),
            )),
            (AlgoSimple::Curve25519, KeyType::Decryption) => AlgorithmAttributes::Ecc(
                EccAttributes::new(EccType::ECDH, Curve::Curve25519, Some(0xFF)),
            ),
            (AlgoSimple::Curve25519, _) => AlgorithmAttributes::Ecc(EccAttributes::new(
                EccType::EdDSA,
                Curve::Ed25519,
                Some(0xFF),
            )),
            _ => todo!("Implement {algo:?} {key_type:?}"),
        };
    println!("Setting attributes: {attributes:?}");
    card.set_algorithm_attributes(key_type, &attributes)?;
    card.generate_key(public_key_material_to_fp, key_type)
}
