// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(feature = "backend-software")]

use std::sync::Mutex;

use iso7816::{command::FromSliceError, Command, Status};
use openpgp_card::{
    CardBackend, CardCaps, CardTransaction, Error, OpenPgp, OpenPgpTransaction, PinType,
};

use opcard::backend::virtual_platform::CARD;

const REQUEST_LEN: usize = 7609;
const RESPONSE_LEN: usize = 7609;

#[derive(Debug)]
struct Card<T: trussed::Client + Send + 'static>(&'static Mutex<opcard::Card<T>>);

impl<T: trussed::Client + Send + 'static> CardBackend for Card<T> {
    fn transaction(&mut self) -> Result<Box<dyn CardTransaction + Send + Sync>, Error> {
        Ok(Box::new(Transaction {
            card: self.0,
            buffer: heapless::Vec::new(),
        }))
    }
}

#[derive(Debug)]
struct Transaction<T: trussed::Client + Send + 'static> {
    card: &'static Mutex<opcard::Card<T>>,
    buffer: heapless::Vec<u8, RESPONSE_LEN>,
}

impl<T: trussed::Client + Send + 'static> Transaction<T> {
    fn handle(&mut self, command: &[u8]) -> Result<(), Status> {
        self.buffer.clear();
        let command = Command::<REQUEST_LEN>::try_from(command).map_err(|err| match err {
            FromSliceError::InvalidSliceLength
            | FromSliceError::TooShort
            | FromSliceError::TooLong => Status::WrongLength,
            FromSliceError::InvalidClass => Status::ClassNotSupported,
            FromSliceError::InvalidFirstBodyByteForExtended => Status::UnspecifiedCheckingError,
        })?;
        let mut card = self.card.try_lock().expect("failed to lock card");
        card.handle(&command, &mut self.buffer)
    }
}

impl<T: trussed::Client + Send + 'static> CardTransaction for Transaction<T> {
    fn transmit(&mut self, command: &[u8], _buf_size: usize) -> Result<Vec<u8>, Error> {
        let status = self.handle(command).err().unwrap_or_default();
        let status: [u8; 2] = status.into();
        let mut response = Vec::with_capacity(self.buffer.len() + 2);
        response.extend_from_slice(&self.buffer);
        response.extend_from_slice(&status);
        Ok(response)
    }

    fn init_card_caps(&mut self, _caps: CardCaps) {
        // TODO: implement
    }

    fn card_caps(&self) -> Option<&CardCaps> {
        None
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

fn with_tx<F: Fn(OpenPgpTransaction<'_>) -> R, R>(f: F) -> R {
    let mut handle = Card(&CARD);
    let mut openpgp = OpenPgp::new(&mut handle);
    let tx = openpgp.transaction().expect("failed to create transaction");
    f(tx)
}

#[test]
fn select() {
    with_tx(|_| ());
}

fn error_to_retries(err: Result<(), openpgp_card::Error>) -> Option<u8> {
    match err {
        Ok(()) => None,
        Err(openpgp_card::Error::CardStatus(openpgp_card::StatusBytes::PasswordNotChecked(c))) => {
            Some(c)
        }
        Err(e) => panic!("Unexpected error {e}"),
    }
}

macro_rules! assert_checks {
    ($tx:expr, $sign:expr, $user:expr, $admin:expr) => {{
        let sign_expected = $sign;
        let sign_retries = error_to_retries($tx.check_pw1_sign());
        assert_eq!(
            sign_retries, sign_expected,
            "Incorrect sign retries. Expected {:?},  got {:?}",
            sign_expected, sign_retries
        );
        let user_expected = $user;
        let user_retries = error_to_retries($tx.check_pw1_user());
        assert_eq!(
            user_retries, user_expected,
            "Incorrect user retries. Expected {:?},  got {:?}",
            user_expected, user_retries
        );
        let admin_expected = $admin;
        let admin_retries = error_to_retries($tx.check_pw3());
        assert_eq!(
            admin_retries, admin_expected,
            "Incorrect admin retries. Expected {:?},  got {:?}",
            admin_expected, admin_retries
        );
    }};
}

#[test]
fn verify() {
    with_tx(|mut tx| {
        assert_checks!(tx, Some(3), Some(3), Some(3));
        assert!(tx.verify_pw1_sign(b"12345678").is_err());
        assert_checks!(tx, Some(2), Some(2), Some(3));
        assert!(tx.verify_pw1_sign(b"123456").is_ok());
        assert_checks!(tx, Some(3), Some(3), Some(3));

        assert!(tx.verify_pw1_user(b"12345678").is_err());
        assert_checks!(tx, Some(2), Some(2), Some(3));
        assert!(tx.verify_pw1_user(b"123456").is_ok());
        assert_checks!(tx, Some(3), None, Some(3));

        assert!(tx.verify_pw3(b"123456").is_err());
        assert_checks!(tx, Some(3), None, Some(2));
        assert!(tx.verify_pw3(b"12345678").is_ok());
        assert_checks!(tx, Some(3), None, Some(3));
    });
    CARD.lock().unwrap().reset();
    with_tx(|mut tx| {
        assert_checks!(tx, Some(3), Some(3), Some(3));
        assert!(tx.verify_pw1_sign(b"12345678").is_err());
        assert!(tx.verify_pw1_sign(b"12345678").is_err());
        assert!(tx.verify_pw1_sign(b"12345678").is_err());
        assert_checks!(tx, Some(0), Some(0), Some(3));
        assert!(tx.verify_pw1_sign(b"12345678").is_err());
        assert_checks!(tx, Some(0), Some(0), Some(3));
        assert!(tx.verify_pw1_sign(b"123456").is_err());
        assert_checks!(tx, Some(0), Some(0), Some(3));
    });
    CARD.lock().unwrap().reset();
    with_tx(|mut tx| {
        assert_checks!(tx, Some(0), Some(0), Some(3));
        assert!(tx.verify_pw3(b"123456").is_err());
        assert!(tx.verify_pw3(b"123456").is_err());
        assert!(tx.verify_pw3(b"123456").is_err());
        assert_checks!(tx, Some(0), Some(0), Some(0));
        assert!(tx.verify_pw3(b"123456").is_err());
        assert_checks!(tx, Some(0), Some(0), Some(0));
        assert!(tx.verify_pw3(b"12345678").is_err());
        assert_checks!(tx, Some(0), Some(0), Some(0));
    });
    CARD.lock().unwrap().reset();
    with_tx(|mut tx| {
        assert_checks!(tx, Some(0), Some(0), Some(0));
    });
}
