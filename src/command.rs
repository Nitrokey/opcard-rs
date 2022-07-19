// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;

use crate::card::{Context, RID};

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Select,
    SelectData(Instance),
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
    pub fn exec<const R: usize, T: trussed::Client>(
        &self,
        context: Context<'_, R, T>,
    ) -> Result<(), Status> {
        match self {
            Self::Select => select(context),
            Self::Verify(mode, password) => verify(context, *mode, *password),
            Self::ChangeReferenceData(password) => change_reference_data(context, *password),
            _ => {
                log::warn!("Command not yet implemented: {:?}", self);
                unimplemented!();
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
                let instance = Instance::try_from(command.p1)?;
                require(command.p2, 0x04)?;
                Ok(Self::SelectData(instance))
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

#[derive(Debug, Eq, PartialEq)]
pub enum GetDataMode {
    Even,
    Odd,
}

#[derive(Debug, Eq, PartialEq)]
pub enum PutDataMode {
    Even,
    Odd,
}

#[derive(Debug, Eq, PartialEq)]
pub enum GenerateAsymmetricKeyPairMode {
    GenerateKey,
    ReadTemplate,
}

impl TryFrom<u8> for GenerateAsymmetricKeyPairMode {
    type Error = Status;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::GenerateKey),
            0x02 => Ok(Self::ReadTemplate),
            _ => Err(Status::IncorrectP1OrP2Parameter),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ManageSecurityEnvironmentMode {
    Authentication,
    Confidentiality,
}

impl TryFrom<u8> for ManageSecurityEnvironmentMode {
    type Error = Status;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0xA4 => Ok(Self::Authentication),
            0xB8 => Ok(Self::Confidentiality),
            _ => Err(Status::IncorrectP1OrP2Parameter),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Instance(u8);

impl TryFrom<u8> for Instance {
    type Error = Status;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= 0x03 {
            Ok(Self(value))
        } else {
            Err(Status::IncorrectP1OrP2Parameter)
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Tag(u16);

impl From<(u8, u8)> for Tag {
    fn from((p1, p2): (u8, u8)) -> Self {
        Self(u16::from_be_bytes([p1, p2]))
    }
}

impl<const C: usize> From<&iso7816::Command<C>> for Tag {
    fn from(command: &iso7816::Command<C>) -> Self {
        Self::from((command.p1, command.p2))
    }
}

// § 7.2.1
fn select<const R: usize, T: trussed::Client>(context: Context<'_, R, T>) -> Result<(), Status> {
    if context.data.starts_with(&RID) {
        Ok(())
    } else {
        log::info!("Selected application {:x?} not found", context.data);
        Err(Status::NotFound)
    }
}

// § 7.2.2
fn verify<const R: usize, T: trussed::Client>(
    context: Context<'_, R, T>,
    mode: VerifyMode,
    password: PasswordMode,
) -> Result<(), Status> {
    let internal = context
        .backend
        .load_internal(&mut context.state.internal)
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
    match mode {
        VerifyMode::SetOrCheck => {
            if context.data.is_empty() {
                match password {
                    PasswordMode::Pw1Sign => {
                        if context.state.runtime.sign_verified {
                            Ok(())
                        } else {
                            Err(Status::RemainingRetries(internal.remaining_user_tries()))
                        }
                    }
                    PasswordMode::Pw1Other => {
                        if context.state.runtime.other_verified {
                            Ok(())
                        } else {
                            Err(Status::RemainingRetries(internal.remaining_user_tries()))
                        }
                    }
                    PasswordMode::Pw3 => {
                        if context.state.runtime.admin_verified {
                            Ok(())
                        } else {
                            Err(Status::RemainingRetries(internal.remaining_admin_tries()))
                        }
                    }
                }
            } else {
                let pin = password.into();
                if context.backend.verify_pin(pin, context.data, internal) {
                    match password {
                        PasswordMode::Pw1Sign => context.state.runtime.sign_verified = true,
                        PasswordMode::Pw1Other => context.state.runtime.other_verified = true,
                        PasswordMode::Pw3 => context.state.runtime.admin_verified = true,
                    }
                    Ok(())
                } else {
                    Err(Status::VerificationFailed)
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
    context: Context<'_, R, T>,
    password: Password,
) -> Result<(), Status> {
    let internal = context
        .backend
        .load_internal(&mut context.state.internal)
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
    const MIN_LENGTH_ADMIN_PIN: usize = 8;
    const MIN_LENGTH_USER_PIN: usize = 6;
    let (current_len, min_len) = match password {
        Password::Pw1 => (internal.user_pin_len(), MIN_LENGTH_USER_PIN),
        Password::Pw3 => (internal.admin_pin_len(), MIN_LENGTH_ADMIN_PIN),
    };
    if current_len + min_len > context.data.len() {
        return Err(Status::WrongLength);
    }
    let (old, new) = context.data.split_at(current_len);
    let client_mut = context.backend.client_mut();
    match password {
        Password::Pw1 => internal
            .verify_user_pin(client_mut, old)
            .and_then(|_| internal.change_user_pin(client_mut, new)),
        Password::Pw3 => internal
            .verify_admin_pin(client_mut, old)
            .and_then(|_| internal.change_admin_pin(client_mut, new)),
    }
    .map_err(|_| Status::VerificationFailed)
}
