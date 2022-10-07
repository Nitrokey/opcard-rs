// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use hex_literal::hex;
use iso7816::Status;
use trussed::types::{KeyId, KeySerialization, Location, Mechanism, StorageAttributes};
use trussed::{syscall, try_syscall};

use crate::card::LoadedContext;
use crate::state::KeyOrigin;
use crate::types::*;
use crate::utils::InspectErr;

const KEYGEN_DO_TAG: &[u8] = &hex!("7f49");

fn serialize_pub<const R: usize, T: trussed::Client>(
    algo: CurveAlgo,
    ctx: LoadedContext<'_, R, T>,
    public_key: &[u8],
) -> Result<(), Status> {
    match algo {
        CurveAlgo::EcDsaP256 | CurveAlgo::EcDhP256 => serialize_p256(ctx, public_key),
        CurveAlgo::X255 | CurveAlgo::Ed255 => serialize_25519(ctx, public_key),
    }
}

pub fn sign<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let algo = ctx.state.internal.sign_alg();
    info!("Generating sign key with algorithm: {algo:?}");
    match algo {
        SignatureAlgorithm::Ed255 => gen_ec_key(ctx.lend(), KeyType::Sign, CurveAlgo::Ed255),
        SignatureAlgorithm::EcDsaP256 => {
            gen_ec_key(ctx.lend(), KeyType::Sign, CurveAlgo::EcDsaP256)
        }
        SignatureAlgorithm::Rsa2k => gen_rsa_key(ctx.lend(), KeyType::Sign, Mechanism::Rsa2kPkcs),
        _ => {
            error!("Unimplemented operation");
            Err(Status::ConditionsOfUseNotSatisfied)
        }
    }
}

pub fn dec<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let algo = ctx.state.internal.dec_alg();
    info!("Generating dec key with algorithm: {algo:?}");
    match algo {
        DecryptionAlgorithm::X255 => gen_ec_key(ctx.lend(), KeyType::Dec, CurveAlgo::X255),
        DecryptionAlgorithm::EcDhP256 => gen_ec_key(ctx.lend(), KeyType::Dec, CurveAlgo::EcDhP256),
        DecryptionAlgorithm::Rsa2k => gen_rsa_key(ctx.lend(), KeyType::Dec, Mechanism::Rsa2kPkcs),
        _ => {
            error!("Unimplemented operation");
            Err(Status::ConditionsOfUseNotSatisfied)
        }
    }
}

pub fn aut<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let algo = ctx.state.internal.aut_alg();
    info!("Generating aut key with algorithm: {algo:?}");
    match algo {
        AuthenticationAlgorithm::Ed255 => gen_ec_key(ctx.lend(), KeyType::Aut, CurveAlgo::Ed255),
        AuthenticationAlgorithm::EcDsaP256 => {
            gen_ec_key(ctx.lend(), KeyType::Aut, CurveAlgo::EcDsaP256)
        }
        AuthenticationAlgorithm::Rsa2k => {
            gen_rsa_key(ctx.lend(), KeyType::Aut, Mechanism::Rsa2kPkcs)
        }
        _ => {
            error!("Unimplemented operation");
            Err(Status::ConditionsOfUseNotSatisfied)
        }
    }
}

fn gen_rsa_key<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
    key: KeyType,
    mechanism: Mechanism,
) -> Result<(), Status> {
    let client = ctx.backend.client_mut();
    let key_id = try_syscall!(client.generate_key(
        mechanism,
        StorageAttributes::new().set_persistence(Location::Internal)
    ))
    .map_err(|_err| {
        error!("Failed to generate key: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .key;

    if let Some((old_key, _)) = ctx
        .state
        .internal
        .set_key_id(key, Some((key_id, KeyOrigin::Generated)), client)
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?
    {
        // Deletion is not a fatal error
        try_syscall!(client.delete(old_key))
            .inspect_err_stable(|_err| {
                error!("Failed to delete old key: {_err:?}");
            })
            .ok();
    }
    read_rsa_key(ctx, key_id, mechanism)
}

fn gen_ec_key<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
    key: KeyType,
    curve: CurveAlgo,
) -> Result<(), Status> {
    let client = ctx.backend.client_mut();
    let key_id = try_syscall!(client.generate_key(
        curve.mechanism(),
        StorageAttributes::new().set_persistence(Location::Internal)
    ))
    .map_err(|_err| {
        error!("Failed to generate key: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .key;
    if let Some((old_key, _)) = ctx
        .state
        .internal
        .set_key_id(key, Some((key_id, KeyOrigin::Generated)), client)
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?
    {
        // Deletion is not a fatal error
        try_syscall!(client.delete(old_key))
            .inspect_err_stable(|_err| {
                error!("Failed to delete old key: {_err:?}");
            })
            .ok();
    }
    read_ec_key(ctx, key_id, curve)
}

pub fn read_sign<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx
        .state
        .internal
        .key_id(KeyType::Sign)
        .ok_or(Status::KeyReferenceNotFound)?;

    let algo = ctx.state.internal.sign_alg();
    match algo {
        SignatureAlgorithm::Ed255 => read_ec_key(ctx.lend(), key_id, CurveAlgo::Ed255),
        SignatureAlgorithm::EcDsaP256 => read_ec_key(ctx.lend(), key_id, CurveAlgo::EcDsaP256),
        SignatureAlgorithm::Rsa2k => read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa2kPkcs),
        _ => {
            error!("Unimplemented operation");
            Err(Status::ConditionsOfUseNotSatisfied)
        }
    }
}

pub fn read_dec<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx
        .state
        .internal
        .key_id(KeyType::Dec)
        .ok_or(Status::KeyReferenceNotFound)?;

    let algo = ctx.state.internal.dec_alg();
    match algo {
        DecryptionAlgorithm::X255 => read_ec_key(ctx.lend(), key_id, CurveAlgo::X255),
        DecryptionAlgorithm::EcDhP256 => read_ec_key(ctx.lend(), key_id, CurveAlgo::EcDhP256),
        DecryptionAlgorithm::Rsa2k => read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa2kPkcs),
        _ => {
            error!("Unimplemented operation");
            Err(Status::ConditionsOfUseNotSatisfied)
        }
    }
}

pub fn read_aut<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx
        .state
        .internal
        .key_id(KeyType::Aut)
        .ok_or(Status::KeyReferenceNotFound)?;

    let algo = ctx.state.internal.aut_alg();
    match algo {
        AuthenticationAlgorithm::Ed255 => read_ec_key(ctx.lend(), key_id, CurveAlgo::Ed255),
        AuthenticationAlgorithm::EcDsaP256 => read_ec_key(ctx.lend(), key_id, CurveAlgo::EcDsaP256),
        AuthenticationAlgorithm::Rsa2k => read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa2kPkcs),
        _ => {
            error!("Unimplemented operation");
            Err(Status::ConditionsOfUseNotSatisfied)
        }
    }
}

fn serialize_p256<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    serialized: &[u8],
) -> Result<(), Status> {
    ctx.reply.expand(&[0x86])?;
    ctx.reply.append_len(serialized.len() + 1)?;
    ctx.reply.expand(&[0x04])?;
    ctx.reply.expand(serialized)
}

fn serialize_25519<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    serialized: &[u8],
) -> Result<(), Status> {
    ctx.reply.expand(&[0x86])?;
    ctx.reply.append_len(serialized.len())?;
    ctx.reply.expand(serialized)
}

fn read_ec_key<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    key_id: KeyId,
    curve: CurveAlgo,
) -> Result<(), Status> {
    let client = ctx.backend.client_mut();
    let public_key = syscall!(client.derive_key(
        curve.mechanism(),
        key_id,
        None,
        StorageAttributes::new().set_persistence(Location::Volatile)
    ))
    .key;
    let serialized =
        try_syscall!(client.serialize_key(curve.mechanism(), public_key, KeySerialization::Raw))
            .map_err(|_err| {
                error!("Failed to serialize public key: {_err:?}");
                syscall!(client.delete(public_key));
                Status::UnspecifiedNonpersistentExecutionError
            })?
            .serialized_key;
    syscall!(client.delete(public_key));
    ctx.reply.expand(KEYGEN_DO_TAG)?;
    let offset = ctx.reply.len();
    serialize_pub(curve, ctx.lend(), &serialized)?;
    ctx.reply.prepend_len(offset)
}

fn read_rsa_key<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    key_id: KeyId,
    mechanism: Mechanism,
) -> Result<(), Status> {
    let client = ctx.backend.client_mut();
    let public_key = syscall!(client.derive_key(
        mechanism,
        key_id,
        None,
        StorageAttributes::new().set_persistence(Location::Volatile)
    ))
    .key;
    ctx.reply.expand(KEYGEN_DO_TAG)?;
    let offset = ctx.reply.len();

    let serialized_n =
        try_syscall!(client.serialize_key(mechanism, public_key, KeySerialization::RsaN))
            .map_err(|_err| {
                error!("Failed to serialize public key N: {_err:?}");
                syscall!(client.delete(public_key));
                Status::UnspecifiedNonpersistentExecutionError
            })?
            .serialized_key;
    ctx.reply.expand(&[0x81])?;
    ctx.reply.append_len(serialized_n.len())?;
    ctx.reply.expand(&serialized_n)?;
    drop(serialized_n);

    let serialized_e =
        try_syscall!(client.serialize_key(mechanism, public_key, KeySerialization::RsaE))
            .map_err(|_err| {
                error!("Failed to serialize public key E: {_err:?}");
                syscall!(client.delete(public_key));
                Status::UnspecifiedNonpersistentExecutionError
            })?
            .serialized_key;
    ctx.reply.expand(&[0x82])?;
    ctx.reply.append_len(serialized_e.len())?;
    ctx.reply.expand(&serialized_e)?;

    ctx.reply.prepend_len(offset)?;

    syscall!(client.delete(public_key));
    Ok(())
}
