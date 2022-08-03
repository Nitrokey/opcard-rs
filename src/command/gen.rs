// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use hex_literal::hex;
use iso7816::Status;
use trussed::types::{KeyId, KeySerialization, Location, Mechanism, StorageAttributes};
use trussed::{syscall, try_syscall};

use crate::card::LoadedContext;
use crate::types::*;
use crate::utils::InspectErr;

pub fn sign<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let algo = ctx.state.internal.sign_alg();
    match algo {
        SignatureAlgorithm::Ed255 => gen_ec_key(ctx.lend(), KeyType::Sign, Mechanism::Ed255),
        SignatureAlgorithm::EcDsaP256 => gen_ec_key(ctx.lend(), KeyType::Sign, Mechanism::P256),
        _ => unimplemented!(),
    }
}

pub fn dec<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let algo = ctx.state.internal.dec_alg();
    match algo {
        DecryptionAlgorithm::X255 => gen_ec_key(ctx.lend(), KeyType::Dec, Mechanism::X255),
        DecryptionAlgorithm::EcDhP256 => gen_ec_key(ctx.lend(), KeyType::Aut, Mechanism::P256),
        _ => unimplemented!(),
    }
}

pub fn aut<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let algo = ctx.state.internal.aut_alg();
    match algo {
        AuthenticationAlgorithm::Ed255 => gen_ec_key(ctx.lend(), KeyType::Aut, Mechanism::Ed255),
        AuthenticationAlgorithm::EcDsaP256 => gen_ec_key(ctx.lend(), KeyType::Aut, Mechanism::P256),
        _ => unimplemented!(),
    }
}

fn gen_ec_key<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
    key: KeyType,
    mechanism: Mechanism,
) -> Result<(), Status> {
    let client = ctx.backend.client_mut();
    let key_id = try_syscall!(client.generate_key(
        mechanism,
        StorageAttributes {
            persistence: Location::Internal
        }
    ))
    .map_err(|_err| {
        error!("Failed to generate key: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .key;
    if let Some(old_key) = ctx
        .state
        .internal
        .set_key_id(key, Some(key_id), client)
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?
    {
        // Deletion is not a fatal error
        try_syscall!(client.delete(old_key))
            .inspect_err_stable(|_err| {
                error!("Failed to delete old key: {_err:?}");
            })
            .ok();
    }
    read_ec_key(ctx, key_id, mechanism)
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
        SignatureAlgorithm::Ed255 => read_ec_key(ctx.lend(), key_id, Mechanism::Ed255),
        SignatureAlgorithm::EcDsaP256 => read_ec_key(ctx.lend(), key_id, Mechanism::P256),
        _ => unimplemented!(),
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
        DecryptionAlgorithm::X255 => read_ec_key(ctx.lend(), key_id, Mechanism::X255),
        DecryptionAlgorithm::EcDhP256 => read_ec_key(ctx.lend(), key_id, Mechanism::P256),
        _ => unimplemented!(),
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
        AuthenticationAlgorithm::Ed255 => read_ec_key(ctx.lend(), key_id, Mechanism::Ed255),
        AuthenticationAlgorithm::EcDsaP256 => read_ec_key(ctx.lend(), key_id, Mechanism::P256),
        _ => unimplemented!(),
    }
}

fn read_ec_key<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    key_id: KeyId,
    mechanism: Mechanism,
) -> Result<(), Status> {
    let client = ctx.backend.client_mut();
    let public_key = syscall!(client.derive_key(
        mechanism,
        key_id,
        None,
        StorageAttributes {
            persistence: Location::Volatile
        }
    ))
    .key;
    let serialized =
        try_syscall!(client.serialize_key(mechanism, public_key, KeySerialization::Raw))
            .map_err(|_err| {
                error!("Failed to serialize public key: {_err:?}");
                Status::UnspecifiedNonpersistentExecutionError
            })?
            .serialized_key;
    ctx.reply.expand(&hex!("7f49"))?;
    let offset = ctx.reply.len();
    ctx.reply.expand(&[0x86])?;
    ctx.reply.append_len(serialized.len() + 1)?;
    ctx.reply.expand(&[0x04])?;
    ctx.reply.expand(&serialized)?;
    ctx.reply.prepend_len(offset)
}
