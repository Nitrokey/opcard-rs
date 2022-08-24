// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![allow(unused)]

use std::sync::{Arc, Mutex};

use hex_literal::hex;
use iso7816::{command::FromSliceError, Command, Status};
use opcard::Options;
use openpgp_card::{
    CardBackend, CardCaps, CardTransaction, Error, OpenPgp, OpenPgpTransaction, PinType,
};
use trussed::{
    virt::{Client, Platform, Ram},
    Service,
};

const REQUEST_LEN: usize = 7609;
const RESPONSE_LEN: usize = 7609;

#[derive(Debug)]
pub struct Card<T: trussed::Client + Send + 'static>(Arc<Mutex<opcard::Card<T>>>);

impl<T: trussed::Client + Send + 'static> Card<T> {
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
        let mut openpgp = OpenPgp::new(self);
        let tx = openpgp.transaction().expect("failed to create transaction");
        f(tx)
    }

    pub fn reset(&self) {
        self.0.lock().unwrap().reset();
    }
}

impl<T: trussed::Client + Send + 'static> CardBackend for Card<T> {
    fn transaction(&mut self) -> Result<Box<dyn CardTransaction + Send + Sync>, Error> {
        // TODO: use reference instead of cloning
        Ok(Box::new(Transaction {
            card: self.0.clone(),
            buffer: heapless::Vec::new(),
        }))
    }
}

#[derive(Debug)]
pub struct Transaction<T: trussed::Client + Send + 'static> {
    card: Arc<Mutex<opcard::Card<T>>>,
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
        let mut card = self.card.lock().expect("failed to lock card");
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

pub fn with_card_options<F: FnOnce(Card<Client<Ram>>) -> R, R>(options: Options, f: F) -> R {
    trussed::virt::with_ram_client("opcard", |client| {
        with_activated_card(opcard::Card::new(client, options), f)
    })
}

pub fn with_card<F: FnOnce(Card<Client<Ram>>) -> R, R>(f: F) -> R {
    with_card_options(Options::default(), f)
}

pub fn with_tx_options<F: FnOnce(OpenPgpTransaction<'_>) -> R, R>(options: Options, f: F) -> R {
    with_card_options(options, move |mut card| card.with_tx(f))
}

pub fn with_tx<F: FnOnce(OpenPgpTransaction<'_>) -> R, R>(f: F) -> R {
    with_card(move |mut card| card.with_tx(f))
}

pub fn error_to_retries(err: Result<(), openpgp_card::Error>) -> Option<u8> {
    match err {
        Ok(()) => None,
        Err(openpgp_card::Error::CardStatus(openpgp_card::StatusBytes::PasswordNotChecked(c))) => {
            Some(c)
        }
        Err(e) => panic!("Unexpected error {e}"),
    }
}

fn with_activated_card<F: FnOnce(Card<Client<Ram>>) -> R, R>(
    mut card: opcard::Card<Client<Ram>>,
    f: F,
) -> R {
    let command: iso7816::Command<4> = iso7816::Command::try_from(&hex!("00 44 0000")).unwrap();
    let mut rep: heapless::Vec<u8, 0> = heapless::Vec::new();
    card.handle(&command, &mut rep).unwrap();
    f(Card::from_opcard(card))
}
