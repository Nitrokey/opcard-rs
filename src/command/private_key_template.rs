// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;
use trussed::syscall;
use trussed::types::KeyId;

use crate::card::LoadedContext;
use crate::tlv::get_do;
use crate::types::*;

// § 4.4.3.12
pub fn put_private_key_template<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let data = get_do(&[0x4D], ctx.data).ok_or_else(|| {
        warn!("Got put private key template with 4D DO");
        Status::IncorrectDataParameter
    })?;

    match KeyType::try_from_crt(data)? {
        KeyType::Sign => {
            put_sign(ctx.lend())?;
            ctx.state
                .internal
                .set_sign_count(0, ctx.backend.client_mut())
                .map_err(|_err| {
                    warn!("Failed to save sign count: {_err}");
                    Status::UnspecifiedNonpersistentExecutionError
                })?;
        }
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
    };
    let old_key_id = ctx
        .state
        .internal
        .set_key_id(KeyType::Sign, key_id, ctx.backend.client_mut())
        .map_err(|_err| {
            error!("Failed to store new key: {_err:?}");
            Status::UnspecifiedNonpersistentExecutionError
        })?;
    if let Some(k) = old_key_id {
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
    };
    let old_key_id = ctx
        .state
        .internal
        .set_key_id(KeyType::Dec, key_id, ctx.backend.client_mut())
        .map_err(|_err| {
            error!("Failed to store new key: {_err:?}");
            Status::UnspecifiedNonpersistentExecutionError
        })?;
    if let Some(k) = old_key_id {
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
    };
    let old_key_id = ctx
        .state
        .internal
        .set_key_id(KeyType::Aut, key_id, ctx.backend.client_mut())
        .map_err(|_err| {
            error!("Failed to store new key: {_err:?}");
            Status::UnspecifiedNonpersistentExecutionError
        })?;
    if let Some(k) = old_key_id {
        syscall!(ctx.backend.client_mut().delete(k));
    }
    Ok(())
}

fn put_ec<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    curve: CurveAlgo,
) -> Result<Option<KeyId>, Status> {
    // FIXME: handle deletion
    todo!()
}
