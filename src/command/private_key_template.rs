// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;
use trussed::types::{KeyId, KeySerialization, Location};
use trussed::{syscall, try_syscall};

use crate::card::LoadedContext;
use crate::state::KeyOrigin;
use crate::tlv::get_do;
use crate::types::*;

const PRIVATE_KEY_TEMPLATE_DO: u16 = 0x4D;
const CONCATENATION_KEY_DATA_DO: u16 = 0x5F48;

// § 4.4.3.12
pub fn put_private_key_template<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let data = get_do(&[PRIVATE_KEY_TEMPLATE_DO], ctx.data).ok_or_else(|| {
        warn!("Got put private key template without 4D DO");
        Status::IncorrectDataParameter
    })?;

    let key_type = KeyType::try_from_crt(data)?;
    debug!("Importing {key_type:?} key");

    match key_type {
        KeyType::Sign => put_sign(ctx)?,
        KeyType::Dec => put_dec(ctx)?,
        KeyType::Aut => put_aut(ctx)?,
    }
    Ok(())
}

pub fn put_sign<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let attr = ctx.state.internal.sign_alg();
    let key_id = match attr {
        SignatureAlgorithm::EcDsaP256 => put_ec(ctx.lend(), CurveAlgo::EcDsaP256)?,
        SignatureAlgorithm::Ed255 => put_ec(ctx.lend(), CurveAlgo::Ed255)?,
        SignatureAlgorithm::Rsa2k | SignatureAlgorithm::Rsa4k => {
            warn!("Key import for RSA not supported");
            return Err(Status::FunctionNotSupported);
        }
    }
    .map(|key_id| (key_id, KeyOrigin::Imported));
    let old_key_id = ctx
        .state
        .internal
        .set_key_id(KeyType::Sign, key_id, ctx.backend.client_mut())
        .map_err(|_err| {
            error!("Failed to store new key: {_err:?}");
            Status::UnspecifiedNonpersistentExecutionError
        })?;
    if let Some((k, _)) = old_key_id {
        syscall!(ctx.backend.client_mut().delete(k));
    }
    Ok(())
}

pub fn put_dec<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let attr = ctx.state.internal.dec_alg();
    let key_id = match attr {
        DecryptionAlgorithm::EcDhP256 => put_ec(ctx.lend(), CurveAlgo::EcDhP256)?,
        DecryptionAlgorithm::X255 => put_ec(ctx.lend(), CurveAlgo::X255)?,
        DecryptionAlgorithm::Rsa2k | DecryptionAlgorithm::Rsa4k => {
            warn!("Key import for RSA not supported");
            return Err(Status::FunctionNotSupported);
        }
    }
    .map(|key_id| (key_id, KeyOrigin::Imported));
    let old_key_id = ctx
        .state
        .internal
        .set_key_id(KeyType::Dec, key_id, ctx.backend.client_mut())
        .map_err(|_err| {
            error!("Failed to store new key: {_err:?}");
            Status::UnspecifiedNonpersistentExecutionError
        })?;
    if let Some((k, _)) = old_key_id {
        syscall!(ctx.backend.client_mut().delete(k));
    }
    Ok(())
}

pub fn put_aut<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let attr = ctx.state.internal.aut_alg();
    let key_id = match attr {
        AuthenticationAlgorithm::EcDsaP256 => put_ec(ctx.lend(), CurveAlgo::EcDsaP256)?,
        AuthenticationAlgorithm::Ed255 => put_ec(ctx.lend(), CurveAlgo::Ed255)?,
        AuthenticationAlgorithm::Rsa2k | AuthenticationAlgorithm::Rsa4k => {
            warn!("Key import for RSA not supported");
            return Err(Status::FunctionNotSupported);
        }
    }
    .map(|key_id| (key_id, KeyOrigin::Imported));
    let old_key_id = ctx
        .state
        .internal
        .set_key_id(KeyType::Aut, key_id, ctx.backend.client_mut())
        .map_err(|_err| {
            error!("Failed to store new key: {_err:?}");
            Status::UnspecifiedNonpersistentExecutionError
        })?;
    if let Some((k, _)) = old_key_id {
        syscall!(ctx.backend.client_mut().delete(k));
    }
    Ok(())
}

fn put_ec<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
    curve: CurveAlgo,
) -> Result<Option<KeyId>, Status> {
    debug!("Importing key for algo {curve:?}");
    let private_key_data = get_do(
        &[PRIVATE_KEY_TEMPLATE_DO, CONCATENATION_KEY_DATA_DO],
        ctx.data,
    )
    .ok_or_else(|| {
        warn!("Missing key data");
        Status::IncorrectDataParameter
    })?;

    let key = try_syscall!(ctx.backend.client_mut().unsafe_inject_key(
        curve.mechanism(),
        private_key_data,
        Location::Internal,
        KeySerialization::Raw
    ))
    .map_err(|_err| {
        warn!("Failed to store key: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .key;
    Ok(Some(key))
}
