// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::{command::FromSliceError, Status};

use crate::card::Card;

const REQUEST_LEN: usize = 7609;
const RESPONSE_LEN: usize = 7609;

/// Virtual OpenPGP smart card implementation.
///
/// This struct provides a virtual OpenPGP smart card implementation that can be used with
/// `vpicc-rs` and [`vsmartcard`](https://frankmorgner.github.io/vsmartcard/) to emulate the card.
#[derive(Clone, Debug)]
pub struct VirtualCard<T: trussed::Client> {
    response_buffer: ResponseBuffer<RESPONSE_LEN>,
    card: Card<T>,
}

impl<T: trussed::Client> VirtualCard<T> {
    /// Creates a new virtual smart card from the given card.
    pub fn new(card: Card<T>) -> Self {
        Self {
            response_buffer: Default::default(),
            card,
        }
    }

    fn handle(&mut self, request: &[u8]) -> (&[u8], Status) {
        // TODO: consider using apdu_dispatch to combine APDUs
        parse_command(request)
            .map(|command| {
                self.response_buffer
                    .handle(&command, |c, b| self.card.handle(c, b))
            })
            .unwrap_or_else(|status| (&[], status))
    }
}

impl<T: trussed::Client> vpicc::VSmartCard for VirtualCard<T> {
    fn power_on(&mut self) {}

    fn power_off(&mut self) {
        self.card.reset();
    }

    fn reset(&mut self) {
        self.card.reset();
    }

    fn execute(&mut self, request: &[u8]) -> Vec<u8> {
        trace!("Received request {:x?}", request);
        let (data, status) = self.handle(request);
        let response = make_response(data, status);
        trace!("Sending response {:x?}", response);
        response
    }
}

fn parse_command(data: &[u8]) -> Result<iso7816::Command<REQUEST_LEN>, Status> {
    data.try_into().map_err(|err| {
        warn!("Failed to parse command: {err:?}");
        match err {
            FromSliceError::InvalidSliceLength
            | FromSliceError::TooShort
            | FromSliceError::TooLong => Status::WrongLength,
            FromSliceError::InvalidClass => Status::ClassNotSupported,
            FromSliceError::InvalidFirstBodyByteForExtended => Status::UnspecifiedCheckingError,
        }
    })
}

fn make_response(data: &[u8], status: Status) -> Vec<u8> {
    let status: [u8; 2] = status.into();
    let mut response = Vec::with_capacity(data.len() + 2);
    response.extend_from_slice(data);
    response.extend_from_slice(&status);
    response
}

#[derive(Clone, Debug, Default)]
struct ResponseBuffer<const N: usize> {
    buffer: heapless::Vec<u8, N>,
    offset: usize,
}

impl<const N: usize> ResponseBuffer<N> {
    pub fn handle<
        const C: usize,
        F: FnOnce(&iso7816::Command<C>, &mut heapless::Vec<u8, N>) -> Result<(), Status>,
    >(
        &mut self,
        command: &iso7816::Command<C>,
        exec: F,
    ) -> (&[u8], Status) {
        if command.instruction() != iso7816::Instruction::GetResponse {
            self.buffer.clear();
            self.offset = 0;
            if let Err(status) = exec(command, &mut self.buffer) {
                return (&[], status);
            }
        }
        self.response(command.expected())
    }

    fn response(&mut self, n: usize) -> (&[u8], Status) {
        let n = n.min(self.buffer.len() - self.offset);
        let data = &self.buffer[self.offset..][..n];
        self.offset += n;
        let status = if self.offset >= self.buffer.len() {
            Status::Success
        } else {
            let rest = self.buffer.len() - self.offset;
            Status::MoreAvailable(u8::try_from(rest).unwrap_or(u8::MAX))
        };
        (data, status)
    }
}
