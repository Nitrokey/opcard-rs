// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![allow(unused)]

use std::sync::{Arc, Mutex};

use iso7816::{command::FromSliceError, Command, Status};
#[cfg(not(feature = "dangerous-test-real-card"))]
use opcard::virt::VirtClient;
use opcard::Options;
use openpgp_card::{
    CardBackend, CardCaps, CardTransaction, Error, OpenPgp, OpenPgpTransaction, PinType,
};
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
