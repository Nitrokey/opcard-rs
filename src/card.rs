// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;

use crate::{backend::Backend, command::Command};

use crate::state::State;

// § 4.2.1
pub const RID: [u8; 5] = [0xD2, 0x76, 0x00, 0x01, 0x24];
pub const PIX_APPLICATION: [u8; 1] = [0x01];
pub const PIX_RFU: [u8; 2] = [0x00, 0x00];

// TODO: use generic iso7816 implementation, see https://github.com/ycrypto/iso7816/pull/3

/// OpenPGP card implementation.
///
/// This is the main entry point for this crate.  It takes care of the command handling and state
/// management.
#[derive(Clone, Debug)]
pub struct Card<T: trussed::Client> {
    backend: Backend<T>,
    options: Options,
    state: State,
}

impl<T: trussed::Client> Card<T> {
    /// Creates a new OpenPGP card with the given backend and options.
    pub fn new(backend: Backend<T>, options: Options) -> Self {
        Self {
            backend,
            options,
            state: Default::default(),
        }
    }

    /// Handles an APDU command and writes the response to the given buffer.
    ///
    /// The APDU command must be complete, i. e. chained commands must be resolved by the caller.
    pub fn handle<const C: usize, const R: usize>(
        &mut self,
        command: &iso7816::Command<C>,
        reply: &mut heapless::Vec<u8, R>,
    ) -> Result<(), Status> {
        log::trace!("Received APDU {:?}", command);
        let card_command = Command::try_from(command)?;
        log::info!("Executing command {:?}", card_command);

        let context = Context {
            backend: &mut self.backend,
            state: &mut self.state,
            data: command.data().as_ref(),
            reply,
        };
        card_command.exec(context)
    }

    /// Resets the state of the card.
    pub fn reset(&mut self) {
        self.state = Default::default();
    }
}

impl<T: trussed::Client> iso7816::App for Card<T> {
    fn aid(&self) -> iso7816::Aid {
        self.options.aid()
    }
}

#[cfg(feature = "apdu-dispatch")]
impl<T: trussed::Client, const C: usize, const R: usize> apdu_dispatch::App<C, R> for Card<T> {
    fn select(
        &mut self,
        command: &iso7816::Command<C>,
        reply: &mut heapless::Vec<u8, R>,
    ) -> Result<(), Status> {
        self.handle(command, reply)
    }

    fn call(
        &mut self,
        _interface: apdu_dispatch::dispatch::Interface,
        command: &iso7816::Command<C>,
        reply: &mut heapless::Vec<u8, R>,
    ) -> Result<(), Status> {
        self.handle(command, reply)
    }

    fn deselect(&mut self) {
        self.reset()
    }
}

/// Options for the OpenPGP card.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Options {
    /// The version number returned in the AID, see § 4.2.1 of the spec.
    pub version: [u8; 2],
    /// The manufacturer ID returned in the AID, see § 4.2.1 of the spec.
    pub manufacturer: [u8; 2],
    /// The serial number returned in the AID, see § 4.2.1 of the spec.
    pub serial: [u8; 4],
}

fn copy_remainder<'b>(buf: &'b mut [u8], data: &[u8]) -> &'b mut [u8] {
    let (left, right) = buf.split_at_mut(data.len());
    left.copy_from_slice(data);
    right
}

impl Options {
    fn aid(&self) -> iso7816::Aid {
        // § 4.2.1
        let mut aid = [0u8; 16];
        let rem = &mut aid;
        let rem = copy_remainder(rem, &RID);
        let rem = copy_remainder(rem, &PIX_APPLICATION);
        let rem = copy_remainder(rem, &self.version);
        let rem = copy_remainder(rem, &self.manufacturer);
        let rem = copy_remainder(rem, &self.serial);
        let rem = copy_remainder(rem, &PIX_RFU);
        assert!(rem.is_empty());
        // TODO: check truncation length
        iso7816::Aid::new_truncatable(&aid, RID.len())
    }
}

/// Returns an instance with the version number derived from the crate version and all-zero values
/// otherwise.
impl Default for Options {
    fn default() -> Self {
        // TODO: consider setting a default manufacturer
        let version_major = env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or_default();
        let version_minor = env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or_default();
        Self {
            version: [version_major, version_minor],
            manufacturer: Default::default(),
            serial: Default::default(),
        }
    }
}

#[derive(Debug)]
pub struct Context<'a, const R: usize, T: trussed::Client> {
    pub backend: &'a mut Backend<T>,
    pub state: &'a mut State,
    pub data: &'a [u8],
    pub reply: &'a mut heapless::Vec<u8, R>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Testing the concatenation of arrays used in aid
    #[test]
    fn aid() {
        assert_eq!(
            Options::default().aid(),
            iso7816::Aid::new_truncatable(
                &[
                    0xD2,
                    0x76,
                    0x00,
                    0x01,
                    0x24,
                    0x1,
                    env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or_default(),
                    env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or_default(),
                    0x0,
                    0x0,
                    0x0,
                    0x0,
                    0x0,
                    0x0,
                    0x0,
                    0x0
                ],
                5
            )
        )
    }
}
