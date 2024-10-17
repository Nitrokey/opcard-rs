// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![allow(unused)]

use std::sync::{Arc, Mutex};

use iso7816::{
    command::{CommandView, FromSliceError},
    Command, Status,
};
#[cfg(not(feature = "dangerous-test-real-card"))]
use opcard::virt::VirtClient;
use opcard::Options;
use openpgp_card::{
    algorithm::AlgoSimple, CardBackend, CardCaps, CardTransaction, Error, OpenPgp,
    OpenPgpTransaction, PinType,
};
use sequoia_openpgp::types::HashAlgorithm;

use trussed::{
    virt::{Platform, Ram},
    Service,
};
use trussed_auth::AuthClient;

const REQUEST_LEN: usize = 7609;
const RESPONSE_LEN: usize = 7609;

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
        let mut openpgp = OpenPgp::new(dyn_b);
        let tx = openpgp.transaction().expect("failed to create transaction");
        f(tx)
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
    fn transaction(&mut self) -> Result<Box<dyn CardTransaction + Send + Sync + Sync>, Error> {
        let mut transaction = Transaction {
            card: self.0.clone(),
            caps: None,
            buffer: heapless::Vec::new(),
        };
        CardTransaction::initialize(&mut transaction).unwrap();
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
    fn transmit(&mut self, command: &[u8], _buf_size: usize) -> Result<Vec<u8>, Error> {
        let status = self.handle(command).err().unwrap_or_default();
        let status: [u8; 2] = status.into();
        let mut response = Vec::with_capacity(self.buffer.len() + 2);
        response.extend_from_slice(&self.buffer);
        response.extend_from_slice(&status);
        Ok(response)
    }

    fn init_card_caps(&mut self, caps: CardCaps) {
        self.caps = Some(caps);
    }

    fn card_caps(&self) -> Option<&CardCaps> {
        self.caps.as_ref()
    }

    fn feature_pinpad_verify(&self) -> bool {
        false
    }

    fn feature_pinpad_modify(&self) -> bool {
        false
    }

    fn pinpad_verify(&mut self, _pin: PinType) -> Result<Vec<u8>, Error> {
        unimplemented!();
    }

    fn pinpad_modify(&mut self, _pin: PinType) -> Result<Vec<u8>, Error> {
        unimplemented!();
    }
}

#[cfg(not(feature = "dangerous-test-real-card"))]
pub fn with_card_options<F: FnOnce(Card<VirtClient<Ram>>) -> R, R>(options: Options, f: F) -> R {
    opcard::virt::with_ram_client("opcard", |client| {
        f(Card::from_opcard(opcard::Card::new(client, options)))
    })
}

#[cfg(not(feature = "dangerous-test-real-card"))]
pub fn with_card<F: FnOnce(Card<VirtClient<Ram>>) -> R, R>(f: F) -> R {
    with_card_options(Options::default(), f)
}

#[cfg(not(feature = "dangerous-test-real-card"))]
pub fn with_tx_options<F: FnOnce(OpenPgpTransaction<'_>) -> R, R>(options: Options, f: F) -> R {
    with_card_options(options, move |mut card| card.with_tx(f))
}

#[cfg(not(feature = "dangerous-test-real-card"))]
pub fn with_tx<F: FnOnce(OpenPgpTransaction<'_>) -> R, R>(f: F) -> R {
    with_card(move |mut card| card.with_tx(f))
}

#[cfg(not(feature = "dangerous-test-real-card"))]
pub fn with_many_tx(fs: impl IntoIterator<Item = impl FnOnce(OpenPgpTransaction<'_>)>) {
    with_card(move |mut card| card.with_many_tx(fs))
}

#[cfg(not(feature = "dangerous-test-real-card"))]
pub fn error_to_retries(err: Result<(), openpgp_card::Error>) -> Option<u8> {
    match err {
        Ok(()) => None,
        Err(openpgp_card::Error::CardStatus(openpgp_card::StatusBytes::PasswordNotChecked(c))) => {
            Some(c)
        }
        Err(e) => panic!("Unexpected error {e}"),
    }
}
#[cfg(all(feature = "vpicc", not(feature = "dangerous-test-real-card")))]
const IDENT: &str = "0000:00000000";
#[cfg(feature = "dangerous-test-real-card")]
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
            KeyAlgo::Rsa2048 => HashAlgorithm::SHA256,
            KeyAlgo::Rsa3072 => HashAlgorithm::SHA384,
            KeyAlgo::Rsa4096 => HashAlgorithm::SHA512,
            KeyAlgo::Cv25519 => HashAlgorithm::SHA256,
            KeyAlgo::P256 => HashAlgorithm::SHA256,
            KeyAlgo::P384 => HashAlgorithm::SHA384,
            KeyAlgo::P521 => HashAlgorithm::SHA512,
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

pub fn sequoia_test(algo: KeyAlgo) {
    use openpgp_card::KeyType;
    use openpgp_card_pcsc::PcscBackend;
    use openpgp_card_sequoia::util::public_key_material_to_key;
    use openpgp_card_sequoia::{state::Open, Card};
    use sequoia_openpgp::crypto::Decryptor;
    use sequoia_openpgp::crypto::SessionKey;
    use sequoia_openpgp::crypto::Signer;

    let mut card: Card<Open> = PcscBackend::open_by_ident(IDENT, None).unwrap().into();
    let mut open = card.transaction().unwrap();
    open.verify_admin(b"12345678").unwrap();
    let mut admin = open.admin_card().unwrap();
    let (material, gendate) = admin
        .generate_key_simple(KeyType::Decryption, Some(algo.into()))
        .unwrap();

    let dec_pubk =
        public_key_material_to_key(&material, KeyType::Decryption, &gendate, None, None).unwrap();
    let dec_pubk_aut =
        public_key_material_to_key(&material, KeyType::Authentication, &gendate, None, None)
            .unwrap();

    println!("======== GENERATED {algo:?} Decryption key =======");

    let (material, gendate) = admin
        .generate_key_simple(KeyType::Authentication, Some(algo.into()))
        .unwrap();
    let aut_pubk =
        public_key_material_to_key(&material, KeyType::Authentication, &gendate, None, None)
            .unwrap();
    let aut_pubk_dec =
        public_key_material_to_key(&material, KeyType::Decryption, &gendate, None, None).unwrap();

    println!("======== GENERATED {algo:?} Authentication key =======");

    let (material, gendate) = admin
        .generate_key_simple(KeyType::Signing, Some(algo.into()))
        .unwrap();
    let sign_pubk =
        public_key_material_to_key(&material, KeyType::Signing, &gendate, None, None).unwrap();

    println!("======== GENERATED {algo:?} Signing key =======");

    open.verify_user_for_signing(b"123456").unwrap();
    let mut sign_card = open.signing_card().unwrap();
    let mut signer = sign_card.signer_from_public(sign_pubk.clone(), &|| {});
    let data = vec![1; algo.plaintext_len()];
    let signature = signer.sign(algo.hash_algo(), &data).unwrap();
    assert!(sign_pubk
        .verify(&signature, algo.hash_algo(), &data)
        .is_ok());

    println!("======== Verified signature =======");

    open.verify_user(b"123456").unwrap();
    let mut user_card = open.user_card().unwrap();
    let mut authenticator = user_card.authenticator_from_public(aut_pubk.clone(), &|| {});
    let data = vec![2; algo.plaintext_len()];
    let signature = authenticator.sign(algo.hash_algo(), &data).unwrap();
    assert!(dec_pubk_aut
        .verify(&signature, algo.hash_algo(), &data)
        .is_err());
    assert!(aut_pubk.verify(&signature, algo.hash_algo(), &data).is_ok());

    println!("======== Verified authentication =======");

    let mut session = SessionKey::new(19);
    session[0] = 7;
    let ciphertext = dec_pubk.encrypt(&session).unwrap();
    let mut decryptor = user_card.decryptor_from_public(dec_pubk, &|| {});
    assert_eq!(
        session,
        decryptor
            .decrypt(&ciphertext, Some(algo.plaintext_len()))
            .unwrap()
    );

    open.manage_security_environment(KeyType::Authentication, KeyType::Decryption)
        .unwrap();
    let mut user_card = open.user_card().unwrap();
    let mut authenticator = user_card.authenticator_from_public(aut_pubk.clone(), &|| {});
    let data = vec![3; algo.plaintext_len()];
    if algo.can_work_with_mse() {
        let signature = authenticator.sign(algo.hash_algo(), &data).unwrap();
        assert!(aut_pubk
            .verify(&signature, algo.hash_algo(), &data)
            .is_err());
        dec_pubk_aut
            .verify(&signature, algo.hash_algo(), &data)
            .unwrap();
    } else {
        _ = authenticator.sign(algo.hash_algo(), &data).unwrap_err();
    }

    println!("======== Verified MSE 1 =======");

    open.manage_security_environment(KeyType::Decryption, KeyType::Authentication)
        .unwrap();
    let mut user_card = open.user_card().unwrap();
    let mut session = SessionKey::new(19);
    session[0] = 7;
    if algo.can_work_with_mse() {
        let ciphertext = aut_pubk_dec.encrypt(&session).unwrap();
        let mut decryptor = user_card.decryptor_from_public(aut_pubk_dec, &|| {});
        assert_eq!(
            session,
            decryptor
                .decrypt(&ciphertext, Some(algo.plaintext_len()))
                .unwrap()
        );
    } else {
        let mut decryptor = user_card.decryptor_from_public(aut_pubk_dec, &|| {});
        assert!(decryptor
            .decrypt(&ciphertext, Some(algo.plaintext_len()))
            .is_err());
    }

    println!("======== Verified MSE 2 =======");

    open.factory_reset().unwrap();
}
