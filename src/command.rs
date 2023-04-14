// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

mod data;
mod gen;
mod private_key_template;
mod pso;

use hex_literal::hex;
use iso7816::Status;
use trussed_auth::PinId;

use crate::card::{Context, LoadedContext, RID};
use crate::error::Error;
use crate::state::{
    KeyRef, LifeCycle, State, MAX_GENERIC_LENGTH, MAX_PIN_LENGTH, MIN_LENGTH_ADMIN_PIN,
    MIN_LENGTH_RESET_CODE, MIN_LENGTH_USER_PIN,
};
use crate::tlv;
use crate::types::*;
use trussed::config::MAX_MESSAGE_LENGTH;
use trussed::types::{Location, PathBuf};
use trussed::{syscall, try_syscall};

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
    GetChallenge(usize),
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

    pub fn exec<const R: usize, T: crate::card::Client>(
        &self,
        mut ctx: Context<'_, R, T>,
    ) -> Result<(), Status> {
        let lifecycle = State::lifecycle(ctx.backend.client_mut(), ctx.options.storage);
        if !self.can_lifecycle_run(lifecycle) {
            warn!(
                "Command {self:?} called in lifecycle {:?}",
                State::lifecycle(ctx.backend.client_mut(), ctx.options.storage)
            );
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        match self {
            Self::Select => select(ctx, lifecycle),
            Self::GetData(mode, tag) => data::get_data(ctx, *mode, *tag),
            Self::GetNextData(tag) => data::get_next_data(ctx, *tag),
            Self::PutData(mode, tag) => data::put_data(ctx, *mode, *tag),
            Self::Verify(mode, password) => verify(ctx.load_state()?, *mode, *password),
            Self::ChangeReferenceData(password) => {
                change_reference_data(ctx.load_state()?, *password)
            }
            Self::ComputeDigitalSignature => pso::sign(ctx.load_state()?),
            Self::InternalAuthenticate => pso::internal_authenticate(ctx.load_state()?),
            Self::Decipher => pso::decipher(ctx.load_state()?),
            Self::Encipher => pso::encipher(ctx.load_state()?),
            Self::GenerateAsymmetricKeyPair(mode) => gen_keypair(ctx.load_state()?, *mode),
            Self::TerminateDf => terminate_df(ctx),
            Self::ActivateFile => activate_file(ctx),
            Self::SelectData(occurrence) => select_data(ctx, *occurrence),
            Self::GetChallenge(length) => get_challenge(ctx, *length),
            Self::ResetRetryCounter(mode) => reset_retry_conter(ctx.load_state()?, *mode),
            Self::ManageSecurityEnvironment(mode) => manage_security_environment(ctx, *mode),
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
                Ok(Self::GetChallenge(command.expected()))
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
    ResetCode,
}

impl From<Password> for PinId {
    fn from(v: Password) -> Self {
        match v {
            Password::Pw1 => 0,
            Password::Pw3 => 1,
            Password::ResetCode => 2,
        }
        .into()
    }
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

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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
fn select<const R: usize, T: crate::card::Client>(
    context: Context<'_, R, T>,
    lifecycle: LifeCycle,
) -> Result<(), Status> {
    if context.data.starts_with(&RID) {
        context.state.volatile.cur_do = None;
        context.state.volatile.keyrefs = Default::default();
        match lifecycle {
            LifeCycle::Operational => Ok(()),
            LifeCycle::Initialization => Err(Status::SelectedFileInTerminationState),
        }
    } else {
        info!("Selected application {:x?} not found", context.data);
        Err(Status::NotFound)
    }
}

// § 7.2.2
fn verify<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    mode: VerifyMode,
    password: PasswordMode,
) -> Result<(), Status> {
    match mode {
        VerifyMode::SetOrCheck => {
            if ctx.data.is_empty() {
                let already_validated = match password {
                    PasswordMode::Pw1Sign => ctx.state.volatile.sign_verified(),
                    PasswordMode::Pw1Other => ctx.state.volatile.other_verified(),
                    PasswordMode::Pw3 => ctx.state.volatile.admin_verified(),
                };
                if already_validated {
                    Ok(())
                } else {
                    Err(Status::RemainingRetries(
                        ctx.state
                            .persistent
                            .remaining_tries(ctx.backend.client_mut(), password.into()),
                    ))
                }
            } else {
                ctx.state
                    .verify_pin(
                        ctx.backend.client_mut(),
                        ctx.options.storage,
                        ctx.data,
                        password,
                    )
                    .map_err(|_| {
                        Status::RemainingRetries(
                            ctx.state
                                .persistent
                                .remaining_tries(ctx.backend.client_mut(), password.into()),
                        )
                    })
            }
        }
        VerifyMode::Reset => {
            match password {
                PasswordMode::Pw1Sign => ctx.state.volatile.clear_sign(ctx.backend.client_mut()),
                PasswordMode::Pw1Other => ctx.state.volatile.clear_other(ctx.backend.client_mut()),
                PasswordMode::Pw3 => ctx.state.volatile.clear_admin(ctx.backend.client_mut()),
            }
            Ok(())
        }
    }
}

// § 7.2.3
fn change_reference_data<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    password: Password,
) -> Result<(), Status> {
    let min_len = match password {
        Password::Pw1 => MIN_LENGTH_USER_PIN,
        Password::Pw3 => MIN_LENGTH_ADMIN_PIN,
        Password::ResetCode => unreachable!(),
    };

    if ctx.data.len() < 2 * min_len {
        return Err(Status::WrongLength);
    }

    let current_len = ctx.state.persistent.pin_len(password);
    let (old, new) = if ctx.data.len() < current_len {
        (ctx.data, [].as_slice())
    } else {
        ctx.data.split_at(current_len)
    };
    let client_mut = ctx.backend.client_mut();
    // Verify the old pin before returning for wrong length to avoid leaking information about the
    // length of the PIN
    ctx.state
        .check_pin(client_mut, old, password)
        .map_err(|_| Status::VerificationFailed)?;

    if current_len + min_len > ctx.data.len() {
        return Err(Status::WrongLength);
    }
    ctx.state
        .persistent
        .change_pin(client_mut, ctx.options.storage, old, new, password)
        .map_err(|_| Status::WrongLength)
}

// § 7.2.14
fn gen_keypair<const R: usize, T: crate::card::Client>(
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

    if !context.state.volatile.admin_verified() {
        return Err(Status::SecurityStatusNotSatisfied);
    }

    match key {
        KeyType::Sign => gen::sign(context),
        KeyType::Dec => gen::dec(context),
        KeyType::Aut => gen::aut(context),
    }
}

// § 7.2.16
fn terminate_df<const R: usize, T: crate::card::Client>(
    mut ctx: Context<'_, R, T>,
) -> Result<(), Status> {
    if let Ok(ctx) = ctx.load_state() {
        if ctx.state.volatile.admin_verified()
            || ctx
                .state
                .persistent
                .is_locked(ctx.backend.client_mut(), Password::Pw3)
        {
            State::terminate_df(ctx.backend.client_mut(), ctx.options.storage)?;
        } else {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
    } else {
        State::terminate_df(ctx.backend.client_mut(), ctx.options.storage)?;
    }

    Ok(())
}

fn unspecified_delete_error<E: core::fmt::Debug>(_err: E) -> Status {
    error!("Failed to delete data {_err:?}");
    Status::UnspecifiedPersistentExecutionError
}

fn factory_reset<const R: usize, T: crate::card::Client>(
    ctx: Context<'_, R, T>,
) -> Result<(), Status> {
    ctx.state.volatile.clear(ctx.backend.client_mut());
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
        .remove_dir_all(Location::External, PathBuf::new()))
    .map_err(unspecified_delete_error)?;
    try_syscall!(ctx.backend.client_mut().delete_all(Location::External))
        .map_err(unspecified_delete_error)?;
    try_syscall!(ctx
        .backend
        .client_mut()
        .remove_dir_all(Location::Volatile, PathBuf::new()))
    .map_err(unspecified_delete_error)?;
    try_syscall!(ctx.backend.client_mut().delete_all(Location::Volatile))
        .map_err(unspecified_delete_error)?;
    try_syscall!(ctx.backend.client_mut().delete_all_pins()).map_err(unspecified_delete_error)?;
    Ok(())
}

// § 7.2.17
fn activate_file<const R: usize, T: crate::card::Client>(
    mut ctx: Context<'_, R, T>,
) -> Result<(), Status> {
    if State::lifecycle(ctx.backend.client_mut(), ctx.options.storage) == LifeCycle::Operational {
        return Ok(());
    }

    factory_reset(ctx.lend())?;
    let ctx = ctx.load_state()?;
    ctx.state
        .persistent
        .save(ctx.backend.client_mut(), ctx.options.storage)
        .map_err(|_err| {
            error!("Failed to store data {_err:?}");
            Status::UnspecifiedPersistentExecutionError
        })?;
    State::activate_file(ctx.backend.client_mut(), ctx.options.storage)?;
    Ok(())
}

// § 7.2.4
fn reset_retry_conter<const R: usize, T: crate::card::Client>(
    ctx: LoadedContext<'_, R, T>,
    mode: ResetRetryCounterMode,
) -> Result<(), Status> {
    match mode {
        ResetRetryCounterMode::Verify => reset_retry_conter_with_p3(ctx),
        ResetRetryCounterMode::ResettingCode => reset_retry_conter_with_code(ctx),
    }
}

fn reset_retry_conter_with_p3<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    if ctx.data.len() < MIN_LENGTH_USER_PIN || ctx.data.len() > MAX_PIN_LENGTH {
        warn!(
            "Attempt to change PIN with incorrect lenght: {}",
            ctx.data.len()
        );
        return Err(Status::IncorrectDataParameter);
    }

    if !ctx.state.volatile.admin_verified() {
        return Err(Status::SecurityStatusNotSatisfied);
    }

    ctx.state
        .reset_user_code_with_pw3(ctx.backend.client_mut(), ctx.options.storage, ctx.data)
        .map_err(|_err| {
            error!("Failed to change PIN: {_err}");
            Status::UnspecifiedNonpersistentExecutionError
        })
}

fn reset_retry_conter_with_code<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let code_len = ctx.state.persistent.reset_code_len().ok_or_else(|| {
        warn!("Attempt to use reset when not set");
        Status::SecurityStatusNotSatisfied
    })?;
    if ctx.data.len() < MIN_LENGTH_RESET_CODE + MIN_LENGTH_USER_PIN {
        warn!("Attempt to reset with too small new pin");
        return Err(Status::SecurityStatusNotSatisfied);
    }
    let (old, new) = if ctx.data.len() < code_len {
        (ctx.data, [].as_slice())
    } else {
        ctx.data.split_at(code_len)
    };

    let res = ctx
        .state
        .check_pin(ctx.backend.client_mut(), old, Password::ResetCode);
    let rc_key = match res {
        Err(Error::InvalidPin) => {
            return Err(Status::RemainingRetries(
                ctx.state
                    .persistent
                    .remaining_tries(ctx.backend.client_mut(), Password::ResetCode),
            ))
        }
        Err(_err) => {
            error!("Failed to check reset code: {_err:?}");
            return Err(Status::UnspecifiedNonpersistentExecutionError);
        }
        Ok(rc_key) => rc_key,
    };

    if new.len() > MAX_PIN_LENGTH || new.len() < MIN_LENGTH_USER_PIN {
        warn!("Attempt to set resetting code with invalid length");
        return Err(Status::IncorrectDataParameter);
    }

    ctx.state
        .reset_user_code_with_rc(ctx.backend.client_mut(), ctx.options.storage, new, rc_key)
        .map_err(|_err| {
            error!("Failed to change PIN: {_err:?}");
            Status::UnspecifiedNonpersistentExecutionError
        })?;
    syscall!(ctx.backend.client_mut().delete(rc_key));
    Ok(())
}

// § 7.2.5
fn select_data<const R: usize, T: crate::card::Client>(
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
    ctx.state.volatile.cur_do = Some((tag, occurrence));
    Ok(())
}

// § 7.2.15
fn get_challenge<const R: usize, T: crate::card::Client>(
    mut ctx: Context<'_, R, T>,
    expected: usize,
) -> Result<(), Status> {
    if expected > MAX_GENERIC_LENGTH {
        return Err(Status::WrongLength);
    }

    while ctx.reply.len() < expected {
        ctx.reply.expand(
            &syscall!(ctx
                .backend
                .client_mut()
                .random_bytes((expected - ctx.reply.len()).min(MAX_MESSAGE_LENGTH)))
            .bytes,
        )?
    }

    Ok(())
}

// § 7.2.18
fn manage_security_environment<const R: usize, T: crate::card::Client>(
    ctx: Context<'_, R, T>,
    mode: ManageSecurityEnvironmentMode,
) -> Result<(), Status> {
    const DEC_DATA: &[u8] = &hex!("83 01 02");
    const AUT_DATA: &[u8] = &hex!("83 01 03");
    let key_ref = match ctx.data {
        DEC_DATA => KeyRef::Dec,
        AUT_DATA => KeyRef::Aut,
        _ => {
            warn!(
                "Manage Security Environment called with invalid reference: {:x?}",
                ctx.data
            );
            return Err(Status::IncorrectDataParameter);
        }
    };
    info!("MANAGE SECURITY ENVIRONMENT: mode = {mode:?}, ref = {key_ref:?}");

    match mode {
        ManageSecurityEnvironmentMode::Dec => ctx.state.volatile.keyrefs.pso_decipher = key_ref,
        ManageSecurityEnvironmentMode::Authentication => {
            ctx.state.volatile.keyrefs.internal_aut = key_ref
        }
    }
    Ok(())
}
