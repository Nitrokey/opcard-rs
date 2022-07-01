// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(feature = "backend-software")]

use iso7816::{command::FromSliceError, Command, Status};
use openpgp_card::{
    CardBackend, CardCaps, CardTransaction, Error, OpenPgp, OpenPgpTransaction, PinType,
};

const REQUEST_LEN: usize = 7609;
const RESPONSE_LEN: usize = 7609;

#[derive(Debug)]
struct Card;

impl Card {
    pub fn new() -> Self {
        Self
    }
}

impl CardBackend for Card {
    fn transaction(&mut self) -> Result<Box<dyn CardTransaction + Send + Sync>, Error> {
        let backend = opcard::backend::SoftwareBackend::new("/tmp/opcard");
        let card = opcard::Card::new(backend, opcard::Options::default());
        Ok(Box::new(Transaction {
            card,
            buffer: heapless::Vec::new(),
        }))
    }
}

#[derive(Debug)]
struct Transaction {
    card: opcard::Card<opcard::backend::SoftwareBackend>,
    buffer: heapless::Vec<u8, RESPONSE_LEN>,
}

impl Transaction {
    fn handle(&mut self, command: &[u8]) -> Result<(), Status> {
        self.buffer.clear();
        let command = Command::<REQUEST_LEN>::try_from(command).map_err(|err| match err {
            FromSliceError::InvalidSliceLength
            | FromSliceError::TooShort
            | FromSliceError::TooLong => Status::WrongLength,
            FromSliceError::InvalidClass => Status::ClassNotSupported,
            FromSliceError::InvalidFirstBodyByteForExtended => Status::UnspecifiedCheckingError,
        })?;
        self.card.handle(&command, &mut self.buffer)
    }
}

impl CardTransaction for Transaction {
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
    let mut card = Card::new();
    let mut openpgp = OpenPgp::new(&mut card);
    let tx = openpgp.transaction().expect("failed to create transaction");
    f(tx)
}

#[test]
fn select() {
    with_tx(|_| ());
}

#[test]
fn verify() {
    with_tx(|mut tx| {
        assert!(tx.verify_pw1_sign(b"12345678").is_err());
        assert!(tx.verify_pw1_sign(b"123456").is_ok());

        assert!(tx.verify_pw1_user(b"12345678").is_err());
        assert!(tx.verify_pw1_user(b"123456").is_ok());

        assert!(tx.verify_pw3(b"123456").is_err());
        assert!(tx.verify_pw3(b"12345678").is_ok());
    });
}
