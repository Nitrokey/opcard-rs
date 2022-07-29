// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use hex_literal::hex;
use iso7816::Status;
use trussed::try_syscall;
use trussed::types::{KeySerialization, Location, Mechanism, StorageAttributes};

use crate::card::reply::Reply;
use crate::card::LoadedContext;
use crate::types::*;

pub fn sign<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let algo = ctx.state.internal.sign_alg();
    ctx.reply.expand(&hex!("7f49"))?;
    let offset = ctx.reply.len();
    let tmp_ctx = LoadedContext {
        state: ctx.state,
        options: ctx.options,
        backend: ctx.backend,
        data: ctx.data,
        reply: Reply(ctx.reply.0),
    };
    match algo {
        SignatureAlgorithm::Ed255 => gen_ed255(tmp_ctx)?,
        SignatureAlgorithm::EcDsaP256 => gen_ecdsa(tmp_ctx)?,
        _ => unimplemented!(),
    }
    ctx.reply.prepend_len(offset)
}

pub fn dec<const R: usize, T: trussed::Client>(ctx: LoadedContext<'_, R, T>) -> Result<(), Status> {
    todo!()
}

pub fn aut<const R: usize, T: trussed::Client>(ctx: LoadedContext<'_, R, T>) -> Result<(), Status> {
    todo!()
}

fn gen_x255<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
    key: KeyType,
) -> Result<(), Status> {
    todo!()
}

fn gen_ed255<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let client = ctx.backend.client_mut();
    let key_id = try_syscall!(client.generate_key(
        Mechanism::Ed255,
        StorageAttributes {
            persistence: Location::Internal,
        }
    ))
    .map_err(|_err| {
        error!("Failed to generate key: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .key;
    let serialized =
        try_syscall!(client.serialize_key(Mechanism::Ed255, key_id, KeySerialization::Raw))
            .map_err(|_err| {
                error!("Failed to serialize public key: {_err:?}");
                Status::UnspecifiedNonpersistentExecutionError
            })?
            .serialized_key;
    ctx.reply.expand(&[0x86])?;
    ctx.reply.append_len(serialized.len())?;
    ctx.reply.expand(&serialized)
}

fn gen_ecdh<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
    key: KeyType,
) -> Result<(), Status> {
    todo!()
}

fn gen_ecdsa<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    todo!()
}
