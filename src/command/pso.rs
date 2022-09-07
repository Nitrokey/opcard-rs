// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;

use trussed::try_syscall;
use trussed::types::*;

use crate::card::LoadedContext;
use crate::tlv::get_do;
use crate::types::*;

// § 7.2.10
pub fn sign<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx.state.internal.key_id(KeyType::Sign).ok_or_else(|| {
        warn!("Attempt to sign without a key set");
        Status::KeyReferenceNotFound
    })?;
    if !ctx.state.runtime.sign_verified {
        warn!("Attempt to sign without PW1 verified");
        return Err(Status::SecurityStatusNotSatisfied);
    }

    if ctx.state.internal.uif(KeyType::Sign).is_enabled()
        && !ctx
            .backend
            .confirm_user_present()
            .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?
    {
        warn!("User presence confirmation timed out");
        // FIXME SecurityRelatedIssues (0x6600 is not available?)
        return Err(Status::SecurityStatusNotSatisfied);
    }
    if !ctx.state.internal.pw1_valid_multiple() {
        ctx.state.runtime.sign_verified = false;
    }

    match ctx.state.internal.sign_alg() {
        SignatureAlgorithm::Ed255 => sign_ec(ctx, key_id, Mechanism::Ed255),
        SignatureAlgorithm::EcDsaP256 => {
            if ctx.data.len() != 32 {
                return Err(Status::ConditionsOfUseNotSatisfied);
            }
            sign_ec(ctx, key_id, Mechanism::P256Prehashed)
        }
        _ => {
            error!("Unimplemented operation");
            Err(Status::ConditionsOfUseNotSatisfied)
        }
    }
}

fn sign_ec<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    key_id: KeyId,
    mechanism: Mechanism,
) -> Result<(), Status> {
    let signature = try_syscall!(ctx.backend.client_mut().sign(
        mechanism,
        key_id,
        ctx.data,
        SignatureSerialization::Raw
    ))
    .map_err(|_err| {
        error!("Failed to sign data: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .signature;
    ctx.reply.expand(&signature)
}

// § 7.2.13
pub fn internal_authenticate<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx.state.internal.key_id(KeyType::Aut).ok_or_else(|| {
        warn!("Attempt to authenticate without a key set");
        Status::KeyReferenceNotFound
    })?;
    if !ctx.state.runtime.other_verified {
        warn!("Attempt to sign without PW1 verified");
        return Err(Status::SecurityStatusNotSatisfied);
    }

    if ctx.state.internal.uif(KeyType::Aut).is_enabled()
        && !ctx
            .backend
            .confirm_user_present()
            .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?
    {
        warn!("User presence confirmation timed out");
        // FIXME SecurityRelatedIssues (0x6600 is not available?)
        return Err(Status::SecurityStatusNotSatisfied);
    }
    match ctx.state.internal.aut_alg() {
        AuthenticationAlgorithm::Ed255 => sign_ec(ctx, key_id, Mechanism::Ed255),
        AuthenticationAlgorithm::EcDsaP256 => {
            if ctx.data.len() != 32 {
                return Err(Status::ConditionsOfUseNotSatisfied);
            }
            sign_ec(ctx, key_id, Mechanism::P256Prehashed)
        }
        _ => {
            error!("Unimplemented operation");
            Err(Status::ConditionsOfUseNotSatisfied)
        }
    }
}

// § 7.2.11
pub fn decipher<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx.state.internal.key_id(KeyType::Dec).ok_or_else(|| {
        warn!("Attempt to authenticat without a key set");
        Status::KeyReferenceNotFound
    })?;
    if !ctx.state.runtime.other_verified {
        warn!("Attempt to sign without PW1 verified");
        return Err(Status::SecurityStatusNotSatisfied);
    }

    if ctx.state.internal.uif(KeyType::Dec).is_enabled()
        && !ctx
            .backend
            .confirm_user_present()
            .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?
    {
        warn!("User presence confirmation timed out");
        // FIXME SecurityRelatedIssues (0x6600 is not available?)
        return Err(Status::SecurityStatusNotSatisfied);
    }

    match ctx.state.internal.dec_alg() {
        DecryptionAlgorithm::X255 => decrypt_ec(ctx, key_id, Mechanism::X255),
        DecryptionAlgorithm::EcDhP256 => decrypt_ec(ctx, key_id, Mechanism::P256),
        _ => {
            error!("Unimplemented operation");
            Err(Status::ConditionsOfUseNotSatisfied)
        }
    }
}

fn decrypt_ec<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    private_key: KeyId,
    mechanism: Mechanism,
) -> Result<(), Status> {
    let data = get_do(&[0xA6, 0x7F49, 0x86], ctx.data).ok_or_else(|| {
        warn!("Failed to parse serialized key DOs");
        Status::IncorrectDataParameter
    })?;
    if data.is_empty() {
        warn!("Seriliazed key is not long enough");
        return Err(Status::IncorrectDataParameter);
    }

    let serialized_key = if matches!(mechanism, Mechanism::X255) {
        // There is no format specifier for x25519
        data
    } else {
        if data[0] != 0x04 {
            warn!("Seriliazed isn't in raw format");
            return Err(Status::IncorrectDataParameter);
        }
        // Does not panic because of the previous `is_empty` check
        &data[1..]
    };

    let pubk_id = try_syscall!(ctx.backend.client_mut().deserialize_key(
        mechanism,
        serialized_key,
        KeySerialization::Raw,
        StorageAttributes::new().set_persistence(Location::Volatile),
    ))
    .map_err(|_err| {
        error!("Failed to deserialize data: {_err:?}");
        Status::IncorrectDataParameter
    })?
    .key;
    let res = try_syscall!(ctx.backend.client_mut().agree(
        mechanism,
        private_key,
        pubk_id,
        StorageAttributes::new()
            .set_persistence(Location::Volatile)
            .set_serializable(true),
    ));

    try_syscall!(ctx.backend.client_mut().delete(pubk_id)).map_err(|_err| {
        error!("Failed to delete key {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?;

    let shared_secret = res
        .map_err(|_err| {
            error!("Failed to derive secret {_err:?}");
            Status::UnspecifiedNonpersistentExecutionError
        })?
        .shared_secret;

    let data = try_syscall!(ctx.backend.client_mut().serialize_key(
        Mechanism::SharedSecret,
        shared_secret,
        KeySerialization::Raw,
    ))
    .map_err(|_err| {
        error!("Failed to serialize secret {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .serialized_key;

    try_syscall!(ctx.backend.client_mut().delete(shared_secret)).map_err(|_err| {
        error!("Failed to delete shared secret{_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?;

    ctx.reply.expand(&data)
}
