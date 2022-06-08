// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::{command::FromSliceError, Status};

use crate::{backend::Backend, card::Card};

const REQUEST_LEN: usize = 7609;
const RESPONSE_LEN: usize = 7609;

/// Virtual OpenPGP smart card implementation.
///
/// This struct provides a virtual OpenPGP smart card implementation that can be used with
/// `vpicc-rs` and [`vsmartcard`](https://frankmorgner.github.io/vsmartcard/) to emulate the card.
#[derive(Clone, Debug)]
pub struct VirtualCard<B: Backend> {
    buffer: heapless::Vec<u8, RESPONSE_LEN>,
    card: Card<B>,
}

impl<B: Backend> VirtualCard<B> {
    /// Creates a new virtual smart card from the given card.
    pub fn new(card: Card<B>) -> Self {
        Self {
            buffer: heapless::Vec::new(),
            card,
        }
    }

    fn handle(&mut self, request: &[u8]) -> Result<(), Status> {
        self.buffer.clear();
        let command =
            iso7816::Command::<REQUEST_LEN>::try_from(request).map_err(|err| match err {
                FromSliceError::InvalidSliceLength
                | FromSliceError::TooShort
                | FromSliceError::TooLong => Status::WrongLength,
                FromSliceError::InvalidClass => Status::ClassNotSupported,
                FromSliceError::InvalidFirstBodyByteForExtended => Status::UnspecifiedCheckingError,
            })?;
        self.card.handle(&command, &mut self.buffer)
    }
}

impl<B: Backend> vpicc::VSmartCard for VirtualCard<B> {
    fn power_on(&mut self) {}

    fn power_off(&mut self) {
        self.card.reset();
    }

    fn reset(&mut self) {
        self.card.reset();
    }

    fn execute(&mut self, request: &[u8]) -> Vec<u8> {
        log::trace!("Received request {:x?}", request);
        // TODO: consider using apdu_dispatch to combine APDUs
        let status = self.handle(request).err().unwrap_or_default();
        let status: [u8; 2] = status.into();
        let mut response = Vec::new();
        response.extend_from_slice(&self.buffer);
        response.extend_from_slice(&status);
        log::trace!("Sending response {:x?}", response);
        response
    }
}
