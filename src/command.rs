// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

mod data;
mod gen;
mod pso;

use iso7816::Status;

use crate::card::{Context, LoadedContext, RID};
use crate::state::{LifeCycle, State};
use crate::tlv;
use crate::types::*;
use trussed::try_syscall;
use trussed::types::{Location, PathBuf};

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Select,
    SelectData(Occurrence),
    GetData(GetDataMode, Tag),
    GetNextData(Tag),
    Verify(VerifyMode, PasswordMode),
    ChangeReferenceData(Password),
    ResetRetryCounter(ResetRetryCounterMode),
    PutData(PutDataMode, Tag),
    GenerateAsymmetricKeyPair(GenerateAsymmetricKeyPairMode),
    ComputeDigitalSignature,
    Decipher,
    Encipher,
    InternalAuthenticate,
    GetResponse,
    GetChallenge,
    TerminateDf,
    ActivateFile,
    ManageSecurityEnvironment(ManageSecurityEnvironmentMode),
}

impl Command {
    fn can_lifecycle_run(&self, lifecycle: LifeCycle) -> bool {
        match (self, lifecycle) {
            (Self::Select | Self::ActivateFile | Self::TerminateDf, LifeCycle::Initialization) => {
                true
            }
            (_, LifeCycle::Initialization) => false,
            (_, LifeCycle::Operational) => true,
        }
    }

    pub fn exec<const R: usize, T: trussed::Client>(
        &self,
        mut context: Context<'_, R, T>,
    ) -> Result<(), Status> {
        if !self.can_lifecycle_run(State::lifecycle(context.backend.client_mut())) {
            warn!(
                "Command {self:?} called in lifecycle {:?}",
                State::lifecycle(context.backend.client_mut())
            );
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        match self {
            Self::Select => select(context),
            Self::GetData(mode, tag) => data::get_data(context, *mode, *tag),
            Self::GetNextData(tag) => data::get_next_data(context, *tag),
            Self::PutData(mode, tag) => data::put_data(context, *mode, *tag),
            Self::Verify(mode, password) => verify(context.load_state()?, *mode, *password),
            Self::ChangeReferenceData(password) => {
                change_reference_data(context.load_state()?, *password)
            }
            Self::ComputeDigitalSignature => pso::sign(context.load_state()?),
            Self::InternalAuthenticate => pso::internal_authenticate(context.load_state()?),
            Self::Decipher => pso::decipher(context.load_state()?),
            Self::GenerateAsymmetricKeyPair(mode) => gen_keypair(context.load_state()?, *mode),
            Self::TerminateDf => terminate_df(context),
            Self::ActivateFile => activate_file(context),
            Self::SelectData(occurrence) => select_data(context, *occurrence),
            _ => {
                error!("Command not yet implemented: {:x?}", self);
                Err(Status::FunctionNotSupported)
            }
        }
    }
}

impl<const C: usize> TryFrom<&iso7816::Command<C>> for Command {
    type Error = Status;

    fn try_from(command: &iso7816::Command<C>) -> Result<Self, Self::Error> {
        fn require(left: u8, right: u8) -> Result<(), Status> {
            if left == right {
                Ok(())
            } else {
                Err(Status::IncorrectP1OrP2Parameter)
            }
        }

        fn require_p1_p2<const D: usize>(
            command: &iso7816::Command<D>,
            p1: u8,
            p2: u8,
        ) -> Result<(), Status> {
            require(command.p1, p1)?;
            require(command.p2, p2)?;
            Ok(())
        }

        // TODO: check CLA
        // See § 7.1
        match u8::from(command.instruction()) {
            0xA4 => {
                require_p1_p2(command, 0x04, 0x00)?;
                Ok(Self::Select)
            }
            0x20 => {
                let verify_mode = VerifyMode::try_from(command.p1)?;
                let password_mode = PasswordMode::try_from(command.p2)?;
                Ok(Self::Verify(verify_mode, password_mode))
            }
            0x24 => {
                require(command.p1, 0x00)?;
                let password = Password::try_from(command.p2)?;
                Ok(Self::ChangeReferenceData(password))
            }
            0x2C => {
                let mode = ResetRetryCounterMode::try_from(command.p1)?;
                require(command.p2, 0x81)?;
                Ok(Self::ResetRetryCounter(mode))
            }
            0xA5 => {
                let occurrence = Occurrence::try_from(command.p1)?;
                require(command.p2, 0x04)?;
                Ok(Self::SelectData(occurrence))
            }
            0xCA => Ok(Self::GetData(GetDataMode::Even, Tag::from(command))),
            0xCB => Ok(Self::GetData(GetDataMode::Odd, Tag::from(command))),
            0xCC => Ok(Self::GetNextData(Tag::from(command))),
            0xDA => Ok(Self::PutData(PutDataMode::Even, Tag::from(command))),
            0xDB => Ok(Self::PutData(PutDataMode::Odd, Tag::from(command))),
            0xC0 => {
                require_p1_p2(command, 0x00, 0x00)?;
                Ok(Self::GetResponse)
            }
            0x2A => match (command.p1, command.p2) {
                (0x9E, 0x9A) => Ok(Self::ComputeDigitalSignature),
                (0x80, 0x86) => Ok(Self::Decipher),
                (0x86, 0x80) => Ok(Self::Encipher),
                _ => Err(Status::IncorrectP1OrP2Parameter),
            },
            0x88 => {
                require_p1_p2(command, 0x00, 0x00)?;
                Ok(Self::InternalAuthenticate)
            }
            0x47 => {
                let mode = GenerateAsymmetricKeyPairMode::try_from(command.p1)?;
                require(command.p2, 0x00)?;
                Ok(Self::GenerateAsymmetricKeyPair(mode))
            }
            0x84 => {
                require_p1_p2(command, 0x00, 0x00)?;
                Ok(Self::GetChallenge)
            }
            0xE6 => {
                require_p1_p2(command, 0x00, 0x00)?;
                Ok(Self::TerminateDf)
            }
            0x44 => {
                require_p1_p2(command, 0x00, 0x00)?;
                Ok(Self::ActivateFile)
            }
            0x22 => {
                require(command.p1, 0x41)?;
                let mode = ManageSecurityEnvironmentMode::try_from(command.p2)?;
                Ok(Self::ManageSecurityEnvironment(mode))
            }
            _ => Err(Status::InstructionNotSupportedOrInvalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Password {
    Pw1,
    Pw3,
}

impl From<PasswordMode> for Password {
    fn from(value: PasswordMode) -> Password {
        match value {
            PasswordMode::Pw1Sign | PasswordMode::Pw1Other => Password::Pw1,
            PasswordMode::Pw3 => Password::Pw3,
        }
    }
}

impl TryFrom<u8> for Password {
    type Error = Status;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x81 => Ok(Self::Pw1),
            0x83 => Ok(Self::Pw3),
            _ => Err(Status::IncorrectP1OrP2Parameter),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordMode {
    Pw1Sign,
    Pw1Other,
    Pw3,
}

impl TryFrom<u8> for PasswordMode {
    type Error = Status;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x81 => Ok(Self::Pw1Sign),
            0x82 => Ok(Self::Pw1Other),
            0x83 => Ok(Self::Pw3),
            _ => Err(Status::IncorrectP1OrP2Parameter),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyMode {
    SetOrCheck,
    Reset,
}

impl TryFrom<u8> for VerifyMode {
    type Error = Status;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::SetOrCheck),
            0xFF => Ok(Self::Reset),
            _ => Err(Status::IncorrectP1OrP2Parameter),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ResetRetryCounterMode {
    ResettingCode,
    Verify,
}

impl TryFrom<u8> for ResetRetryCounterMode {
    type Error = Status;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::ResettingCode),
            0x02 => Ok(Self::Verify),
            _ => Err(Status::IncorrectP1OrP2Parameter),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GetDataMode {
    Even,
    Odd,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum PutDataMode {
    Even,
    Odd,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum GenerateAsymmetricKeyPairMode {
    GenerateKey,
    ReadTemplate,
}

impl TryFrom<u8> for GenerateAsymmetricKeyPairMode {
    type Error = Status;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x80 => Ok(Self::GenerateKey),
            0x81 => Ok(Self::ReadTemplate),
            _ => Err(Status::IncorrectP1OrP2Parameter),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ManageSecurityEnvironmentMode {
    Authentication,
    Dec,
}

impl TryFrom<u8> for ManageSecurityEnvironmentMode {
    type Error = Status;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0xA4 => Ok(Self::Authentication),
            0xB8 => Ok(Self::Dec),
            _ => Err(Status::IncorrectP1OrP2Parameter),
        }
    }
}

// § 7.2.1
fn select<const R: usize, T: trussed::Client>(context: Context<'_, R, T>) -> Result<(), Status> {
    if context.data.starts_with(&RID) {
        context.state.runtime.cur_do = None;
        Ok(())
    } else {
        info!("Selected application {:x?} not found", context.data);
        Err(Status::NotFound)
    }
}

// § 7.2.2
fn verify<const R: usize, T: trussed::Client>(
    context: LoadedContext<'_, R, T>,
    mode: VerifyMode,
    password: PasswordMode,
) -> Result<(), Status> {
    match mode {
        VerifyMode::SetOrCheck => {
            if context.data.is_empty() {
                let already_validated = match password {
                    PasswordMode::Pw1Sign => context.state.runtime.sign_verified,
                    PasswordMode::Pw1Other => context.state.runtime.other_verified,
                    PasswordMode::Pw3 => context.state.runtime.admin_verified,
                };
                if already_validated {
                    Ok(())
                } else {
                    Err(Status::RemainingRetries(
                        context.state.internal.remaining_tries(password.into()),
                    ))
                }
            } else {
                let pin = password.into();
                if context
                    .backend
                    .verify_pin(pin, context.data, context.state.internal)
                {
                    match password {
                        PasswordMode::Pw1Sign => context.state.runtime.sign_verified = true,
                        PasswordMode::Pw1Other => context.state.runtime.other_verified = true,
                        PasswordMode::Pw3 => context.state.runtime.admin_verified = true,
                    }
                    Ok(())
                } else {
                    Err(Status::RemainingRetries(
                        context.state.internal.remaining_tries(password.into()),
                    ))
                }
            }
        }
        VerifyMode::Reset => {
            match password {
                PasswordMode::Pw1Sign => context.state.runtime.sign_verified = false,
                PasswordMode::Pw1Other => context.state.runtime.other_verified = false,
                PasswordMode::Pw3 => context.state.runtime.admin_verified = false,
            }
            Ok(())
        }
    }
}

// § 7.2.3
fn change_reference_data<const R: usize, T: trussed::Client>(
    context: LoadedContext<'_, R, T>,
    password: Password,
) -> Result<(), Status> {
    const MIN_LENGTH_ADMIN_PIN: usize = 8;
    const MIN_LENGTH_USER_PIN: usize = 6;
    let min_len = match password {
        Password::Pw1 => MIN_LENGTH_USER_PIN,
        Password::Pw3 => MIN_LENGTH_ADMIN_PIN,
    };

    if context.data.len() < 2 * min_len {
        return Err(Status::WrongLength);
    }

    let current_len = context.state.internal.pin_len(password);
    let (old, new) = if context.data.len() < current_len {
        (context.data, [].as_slice())
    } else {
        context.data.split_at(current_len)
    };
    let client_mut = context.backend.client_mut();
    // Verify the old pin before returning for wrong length to avoid leaking information about the
    // length of the PIN
    context
        .state
        .internal
        .verify_pin(client_mut, old, password)
        .map_err(|_| Status::VerificationFailed)?;

    if current_len + min_len > context.data.len() {
        return Err(Status::WrongLength);
    }
    context
        .state
        .internal
        .change_pin(client_mut, new, password)
        .map_err(|_| Status::WrongLength)
}

// § 7.2.14
fn gen_keypair<const R: usize, T: trussed::Client>(
    context: LoadedContext<'_, R, T>,
    mode: GenerateAsymmetricKeyPairMode,
) -> Result<(), Status> {
    let key = KeyType::try_from_crt(context.data)?;

    if mode == GenerateAsymmetricKeyPairMode::ReadTemplate {
        return match key {
            KeyType::Sign => gen::read_sign(context),
            KeyType::Dec => gen::read_dec(context),
            KeyType::Aut => gen::read_aut(context),
        };
    }

    if !context.state.runtime.admin_verified {
        return Err(Status::SecurityStatusNotSatisfied);
    }

    match key {
        KeyType::Sign => gen::sign(context),
        KeyType::Dec => gen::dec(context),
        KeyType::Aut => gen::aut(context),
    }
}

// § 7.2.16
fn terminate_df<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
) -> Result<(), Status> {
    if let Ok(ctx) = context.load_state() {
        if ctx.state.runtime.admin_verified || ctx.state.internal.is_locked(Password::Pw3) {
            State::terminate_df(context.backend.client_mut())?;
        } else {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
    } else {
        State::terminate_df(context.backend.client_mut())?;
    }

    Ok(())
}

fn unspecified_delete_error<E: core::fmt::Debug>(_err: E) -> Status {
    error!("Failed to delete data {_err:?}");
    Status::UnspecifiedPersistentExecutionError
}

fn factory_reset<const R: usize, T: trussed::Client>(ctx: Context<'_, R, T>) -> Result<(), Status> {
    *ctx.state = Default::default();
    try_syscall!(ctx
        .backend
        .client_mut()
        .remove_dir_all(Location::Internal, PathBuf::new()))
    .map_err(unspecified_delete_error)?;
    try_syscall!(ctx.backend.client_mut().delete_all(Location::Internal))
        .map_err(unspecified_delete_error)?;
    try_syscall!(ctx
        .backend
        .client_mut()
        .remove_dir_all(Location::Volatile, PathBuf::new()))
    .map_err(unspecified_delete_error)?;
    try_syscall!(ctx.backend.client_mut().delete_all(Location::Volatile))
        .map_err(unspecified_delete_error)?;
    Ok(())
}

// § 7.2.17
fn activate_file<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
) -> Result<(), Status> {
    if State::lifecycle(context.backend.client_mut()) == LifeCycle::Operational {
        return Ok(());
    }

    factory_reset(context.lend())?;
    *context.state = Default::default();
    let context = context.load_state()?;
    context
        .state
        .internal
        .save(context.backend.client_mut())
        .map_err(|_err| {
            error!("Failed to store data {_err:?}");
            Status::UnspecifiedPersistentExecutionError
        })?;
    State::activate_file(context.backend.client_mut())?;
    Ok(())
}

// § 7.2.5
fn select_data<const R: usize, T: trussed::Client>(
    ctx: Context<'_, R, T>,
    occurrence: Occurrence,
) -> Result<(), Status> {
    let tag: Tag = match tlv::get_do(&[0x60, 0x5C], ctx.data) {
        Some([b1, b2]) => (*b1, *b2).into(),
        Some([b1]) => (*b1).into(),
        _ => {
            warn!("Select Data with incorrect data path");
            return Err(Status::IncorrectDataParameter);
        }
    };
    ctx.state.runtime.cur_do = Some((tag, occurrence));
    Ok(())
}
