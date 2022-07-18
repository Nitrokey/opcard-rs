// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

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

pub fn with_tx<F: Fn(OpenPgpTransaction<'_>) -> R, R>(f: F) -> R {
    let mut handle = Card(&CARD);
    let mut openpgp = OpenPgp::new(&mut handle);
    let tx = openpgp.transaction().expect("failed to create transaction");
    f(tx)
}
