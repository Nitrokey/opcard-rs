// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(feature = "admin-app")]
use admin_app::{ResetSignal, ResetSignalAllocation};
use bitflags::bitflags;
use hex_literal::hex;
use iso7816::Status;
use trussed::types::Location;
use trussed_auth::AuthClient;
use trussed_chunked::ChunkedClient;

pub(crate) mod reply;

use crate::state::{LoadedState, State};
use crate::utils::InspectErr;
use crate::{backend::Backend, command::Command};
use reply::Reply;

// § 4.2.1
pub const RID: [u8; 5] = [0xD2, 0x76, 0x00, 0x01, 0x24];
pub const PIX_APPLICATION: [u8; 1] = [0x01];
pub const PIX_RFU: [u8; 2] = [0x00, 0x00];
/// Version of the spec implemented by opcard-rs
pub const PGP_SMARTCARD_VERSION: [u8; 2] = [3, 4];

/// OpenPGP card implementation.
///
/// This is the main entry point for this crate.  It takes care of the command handling and state
/// management.
#[derive(Clone, Debug)]
pub struct Card<T: Client> {
    backend: Backend<T>,
    options: Options,
    state: State,
}

impl<T: Client> Card<T> {
    /// Creates a new OpenPGP card with the given backend and options.
    pub fn new(client: T, options: Options) -> Self {
        let state = State::default();
        Self {
            backend: Backend::new(client),
            options,
            state,
        }
    }

    #[cfg(feature = "admin-app")]
    fn ack_factory_reset(&mut self, reset_signal: &ResetSignalAllocation) -> bool {
        self.state = State::default();
        reset_signal.ack_factory_reset()
    }

    /// Handles an APDU command and writes the response to the given buffer.
    ///
    /// The APDU command must be complete, i. e. chained commands must be resolved by the caller.
    pub fn handle<const C: usize, const R: usize>(
        &mut self,
        command: &iso7816::Command<C>,
        reply: &mut heapless::Vec<u8, R>,
    ) -> Result<(), Status> {
        #[cfg(feature = "admin-app")]
        if let Some(reset_signal) = self.options.reset_signal {
            match reset_signal.load() {
                ResetSignal::None => {}
                ResetSignal::ConfigChanged => {
                    return Err(Status::SelectedFileInTerminationState);
                }
                ResetSignal::FactoryReset => {
                    if !self.ack_factory_reset(reset_signal) {
                        return Err(Status::SelectedFileInTerminationState);
                    }
                }
            }
        }

        trace!("Received APDU {:?}", command);
        let card_command = Command::try_from(command).inspect_err_stable(|_err| {
            warn!("Failed to parse command: {command:x?} {_err:?}");
        })?;
        info!("Executing command {:x?}", card_command);
        let context = Context {
            backend: &mut self.backend,
            state: &mut self.state,
            options: &self.options,
            data: command.data().as_ref(),
            reply: Reply(reply),
        };
        card_command.exec(context)
    }

    /// Resets the state of the card.
    pub fn reset(&mut self) {
        #[cfg(feature = "admin-app")]
        if let Some(reset_signal) = self.options.reset_signal {
            match reset_signal.load() {
                ResetSignal::None => {}
                ResetSignal::ConfigChanged => {
                    debug!("Attempt to reset opcard with reset signal active");
                    return;
                }
                ResetSignal::FactoryReset => {
                    self.ack_factory_reset(reset_signal);
                    return;
                }
            }
        }

        self.state.volatile.clear(self.backend.client_mut());
        let state = State::default();
        self.state = state;
    }
}

impl<T: Client> Drop for Card<T> {
    fn drop(&mut self) {
        self.reset()
    }
}

impl<T: Client> iso7816::App for Card<T> {
    fn aid(&self) -> iso7816::Aid {
        // TODO: check truncation length
        iso7816::Aid::new_truncatable(&self.options.aid(), RID.len())
    }
}

#[cfg(feature = "apdu-dispatch")]
impl<T: Client, const C: usize, const R: usize> apdu_dispatch::App<C, R> for Card<T> {
    fn select(
        &mut self,
        interface: apdu_dispatch::dispatch::Interface,
        command: &iso7816::Command<C>,
        reply: &mut heapless::Vec<u8, R>,
    ) -> Result<(), Status> {
        use apdu_dispatch::dispatch::Interface;
        if interface != Interface::Contact {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        self.handle(command, reply)
    }

    fn call(
        &mut self,
        interface: apdu_dispatch::dispatch::Interface,
        command: &iso7816::Command<C>,
        reply: &mut heapless::Vec<u8, R>,
    ) -> Result<(), Status> {
        use apdu_dispatch::dispatch::Interface;
        if interface != Interface::Contact {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        self.handle(command, reply)
    }

    fn deselect(&mut self) {
        self.reset()
    }
}

bitflags! {
    /// The algorithms that are allowed to be generated or imported.
    ///
    /// Used in [`Options`](allowed_generation) and [`Options`](allowed_imports)
    #[derive(Clone, Copy, Debug)]
    pub struct AllowedAlgorithms: u32 {
        /// P256 NIST curve
        const P_256 = 1;
        /// P384 NIST curve
        const P_384 = 1 << 1;
        /// P521 NIST curve
        const P_521 = 1 << 2;
        /// RSA 2048
        const RSA_2048 = 1 << 3;
        /// RSA 3072
        const RSA_3072 = 1 << 4;
        /// RSA 4096
        const RSA_4096 = 1 << 5;
        /// X25519
        const X_25519 = 1 << 6;
        /// EdDsa25519
        const ED_25519 = 1 << 7;
        /// BRAINPOOL_P256R1 Brainpool curve
        const BRAINPOOL_P256R1 = 1 << 8;
        /// BRAINPOOL_P384R1 Brainpool curve
        const BRAINPOOL_P384R1 = 1 << 9;
        /// BRAINPOOL_P521R1 Brainpool curve
        const BRAINPOOL_P512R1 = 1 << 10;
    }
}

impl AllowedAlgorithms {
    fn default_gen() -> Self {
        [
            Self::P_256,
            Self::P_384,
            Self::P_521,
            #[cfg(feature = "rsa2048-gen")]
            Self::RSA_2048,
            #[cfg(feature = "rsa3072-gen")]
            Self::RSA_3072,
            #[cfg(feature = "rsa4096-gen")]
            Self::RSA_4096,
            Self::X_25519,
            Self::ED_25519,
        ]
        .into_iter()
        .fold(Self::empty(), |acc, value| acc | value)
    }
    fn default_import() -> Self {
        [
            Self::P_256,
            Self::P_384,
            Self::P_521,
            #[cfg(feature = "rsa2048")]
            Self::RSA_2048,
            #[cfg(feature = "rsa3072")]
            Self::RSA_3072,
            #[cfg(feature = "rsa4096")]
            Self::RSA_4096,
            Self::X_25519,
            Self::ED_25519,
        ]
        .into_iter()
        .fold(Self::empty(), |acc, value| acc | value)
    }
}

/// Options for the OpenPGP card.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Options {
    /// The manufacturer ID returned in the AID, see § 4.2.1 of the spec.
    pub manufacturer: [u8; 2],
    /// The serial number returned in the AID, see § 4.2.1 of the spec.
    pub serial: [u8; 4],

    // FIXME: Make historical bytes configurable
    /// Historical bytes, see  § 6
    pub(crate) historical_bytes: heapless::Vec<u8, 15>,

    /// Does the card have a button for user input?
    pub button_available: bool,
    /// Which trussed storage to use
    pub storage: Location,

    /// Bitflags of algorithms allowed to be imported
    pub allowed_imports: AllowedAlgorithms,

    /// Bitflags of algorithms allowed to be generated
    pub allowed_generation: AllowedAlgorithms,

    /// Flag to signal that the application has had its configuration changed or was factory-resetted by the admin application
    ///
    /// Requires the feature-flag admin-app
    #[cfg(feature = "admin-app")]
    pub reset_signal: Option<&'static ResetSignalAllocation>,
}

impl Options {
    /// Returns the AID based on these options, see § 4.2.1 of the spec.
    pub fn aid(&self) -> [u8; 16] {
        [
            RID[0],
            RID[1],
            RID[2],
            RID[3],
            RID[4],
            PIX_APPLICATION[0],
            PGP_SMARTCARD_VERSION[0],
            PGP_SMARTCARD_VERSION[1],
            self.manufacturer[0],
            self.manufacturer[1],
            self.serial[0],
            self.serial[1],
            self.serial[2],
            self.serial[3],
            PIX_RFU[0],
            PIX_RFU[1],
        ]
    }
}

/// Returns an instance with the version number derived from the crate version
impl Default for Options {
    fn default() -> Self {
        // TODO: consider setting a default manufacturer
        #[allow(clippy::unwrap_used)]
        Self {
            manufacturer: Default::default(),
            serial: Default::default(),
            // TODO: Copied from Nitrokey Pro
            historical_bytes: heapless::Vec::from_slice(&hex!("0031F573C00160009000")).unwrap(),
            button_available: true,
            storage: Location::External,
            allowed_imports: AllowedAlgorithms::default_import(),
            allowed_generation: AllowedAlgorithms::default_gen(),
            #[cfg(feature = "admin-app")]
            reset_signal: None,
        }
    }
}

#[derive(Debug)]
pub struct Context<'a, const R: usize, T: Client> {
    pub backend: &'a mut Backend<T>,
    pub options: &'a Options,
    pub state: &'a mut State,
    pub data: &'a [u8],
    pub reply: Reply<'a, R>,
}

impl<'a, const R: usize, T: Client> Context<'a, R, T> {
    pub fn load_state(&mut self) -> Result<LoadedContext<'_, R, T>, Status> {
        Ok(LoadedContext {
            state: self
                .state
                .load(self.backend.client_mut(), self.options.storage)
                .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?,
            options: self.options,
            backend: self.backend,
            data: self.data,
            reply: self.reply.lend(),
        })
    }

    /// Lend the context
    ///
    /// The resulting `Context` has a shorter lifetime than the original one, meaning that it
    /// can be passed by value to other functions and the original context can then be used again
    pub fn lend(&mut self) -> Context<'_, R, T> {
        Context {
            reply: Reply(self.reply.0),
            backend: self.backend,
            options: self.options,
            state: self.state,
            data: self.data,
        }
    }
}

#[derive(Debug)]
/// Context with the persistent state loaded from flash
pub struct LoadedContext<'a, const R: usize, T: Client> {
    pub backend: &'a mut Backend<T>,
    pub options: &'a Options,
    pub state: LoadedState<'a>,
    pub data: &'a [u8],
    pub reply: Reply<'a, R>,
}

impl<'a, const R: usize, T: Client> LoadedContext<'a, R, T> {
    /// Lend the context
    ///
    /// The resulting `LoadedContext` has a shorter lifetime than the original one, meaning that it
    /// can be passed by value to other functions and the original context can then be used again
    pub fn lend(&mut self) -> LoadedContext<'_, R, T> {
        LoadedContext {
            reply: Reply(self.reply.0),
            backend: self.backend,
            options: self.options,
            state: self.state.lend(),
            data: self.data,
        }
    }
}

use trussed_wrap_key_to_file::WrapKeyToFileClient;

/// Super trait with all trussed extensions required by opcard
pub trait Client: trussed::Client + AuthClient + WrapKeyToFileClient + ChunkedClient {}
impl<C: trussed::Client + WrapKeyToFileClient + AuthClient + ChunkedClient> Client for C {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Testing the concatenation of arrays used in aid
    #[test]
    fn aid() {
        assert_eq!(
            Options::default().aid(),
            hex!("D2 76 00 01 24 01 03 04 00 00 00 00 00 00 00 00"),
        )
    }
}
