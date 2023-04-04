// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::{command::FromSliceError, Command, Status};
use trussed_auth::AuthClient;

use crate::card::Card;

const REQUEST_LEN: usize = 7609;
const RESPONSE_LEN: usize = 7609;

/// Virtual OpenPGP smart card implementation.
///
/// This struct provides a virtual OpenPGP smart card implementation that can be used with
/// `vpicc-rs` and [`vsmartcard`](https://frankmorgner.github.io/vsmartcard/) to emulate the card.
#[derive(Clone, Debug)]
pub struct VirtualCard<T: trussed::Client + AuthClient> {
    request_buffer: RequestBuffer<REQUEST_LEN>,
    response_buffer: ResponseBuffer<RESPONSE_LEN>,
    card: Card<T>,
}

impl<T: trussed::Client + AuthClient> VirtualCard<T> {
    /// Creates a new virtual smart card from the given card.
    pub fn new(card: Card<T>) -> Self {
        Self {
            request_buffer: Default::default(),
            response_buffer: Default::default(),
            card,
        }
    }

    fn handle(&mut self, request: &[u8]) -> (&[u8], Status) {
        parse_command(request)
            .and_then(|command| self.request_buffer.handle(command))
            .map(|command| {
                command
                    .map(|command| {
                        self.response_buffer
                            .handle(&command, |c, b| self.card.handle(c, b))
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_else(|status| (&[], status))
    }
}

impl<T: trussed::Client + AuthClient> vpicc::VSmartCard for VirtualCard<T> {
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

fn parse_command(data: &[u8]) -> Result<Command<REQUEST_LEN>, Status> {
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
struct RequestBuffer<const N: usize> {
    command: Option<Command<N>>,
}

impl<const N: usize> RequestBuffer<N> {
    pub fn handle(&mut self, command: Command<N>) -> Result<Option<Command<N>>, Status> {
        if let Some(buffer) = &mut self.command {
            buffer
                .extend_from_command(&command)
                .map_err(|_| Status::WrongLength)?;
        }
        if command.class().chain().last_or_only() {
            if let Some(buffer) = self.command.take() {
                Ok(Some(buffer))
            } else {
                Ok(Some(command))
            }
        } else {
            if self.command.is_none() {
                self.command = Some(command);
            }
            Ok(None)
        }
    }
}

#[derive(Clone, Debug, Default)]
struct ResponseBuffer<const N: usize> {
    buffer: heapless::Vec<u8, N>,
    offset: usize,
}

impl<const N: usize> ResponseBuffer<N> {
    pub fn handle<
        const C: usize,
        F: FnOnce(&Command<C>, &mut heapless::Vec<u8, N>) -> Result<(), Status>,
    >(
        &mut self,
        command: &Command<C>,
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
