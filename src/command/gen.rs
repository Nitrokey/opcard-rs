// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use hex_literal::hex;
use iso7816::Status;
use trussed::types::{KeyId, KeySerialization, Location, Mechanism, StorageAttributes};
use trussed::{syscall, try_syscall};
use trussed_auth::AuthClient;

use crate::card::LoadedContext;
use crate::state::KeyOrigin;
use crate::types::*;

const KEYGEN_DO_TAG: &[u8] = &hex!("7f49");

#[cfg(feature = "rsa")]
use trussed_rsa_alloc::RsaPublicParts;

fn serialize_pub<const R: usize, T: trussed::Client + AuthClient>(
    algo: CurveAlgo,
    ctx: LoadedContext<'_, R, T>,
    public_key: &[u8],
) -> Result<(), Status> {
    match algo {
        CurveAlgo::EcDsaP256 | CurveAlgo::EcDhP256 => serialize_p256(ctx, public_key),
        CurveAlgo::X255 | CurveAlgo::Ed255 => serialize_25519(ctx, public_key),
    }
}

pub fn sign<const R: usize, T: trussed::Client + AuthClient>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let algo = ctx.state.persistent.sign_alg();
    info!("Generating sign key with algorithm: {algo:?}");
    match algo {
        SignatureAlgorithm::Ed255 => gen_ec_key(ctx.lend(), KeyType::Sign, CurveAlgo::Ed255),
        SignatureAlgorithm::EcDsaP256 => {
            gen_ec_key(ctx.lend(), KeyType::Sign, CurveAlgo::EcDsaP256)
        }
        SignatureAlgorithm::Rsa2048 => {
            gen_rsa_key(ctx.lend(), KeyType::Sign, Mechanism::Rsa2048Pkcs1v15)
        }
        SignatureAlgorithm::Rsa3072 => {
            gen_rsa_key(ctx.lend(), KeyType::Sign, Mechanism::Rsa3072Pkcs1v15)
        }
        SignatureAlgorithm::Rsa4096 => {
            #[cfg(feature = "rsa4096-gen")]
            return gen_rsa_key(ctx.lend(), KeyType::Sign, Mechanism::Rsa4096Pkcs1v15);
            #[cfg(not(feature = "rsa4096-gen"))]
            return Err(Status::FunctionNotSupported);
        }
    }
}

pub fn dec<const R: usize, T: trussed::Client + AuthClient>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let algo = ctx.state.persistent.dec_alg();
    info!("Generating dec key with algorithm: {algo:?}");
    match algo {
        DecryptionAlgorithm::X255 => gen_ec_key(ctx.lend(), KeyType::Dec, CurveAlgo::X255),
        DecryptionAlgorithm::EcDhP256 => gen_ec_key(ctx.lend(), KeyType::Dec, CurveAlgo::EcDhP256),
        DecryptionAlgorithm::Rsa2048 => {
            gen_rsa_key(ctx.lend(), KeyType::Dec, Mechanism::Rsa2048Pkcs1v15)
        }
        DecryptionAlgorithm::Rsa3072 => {
            gen_rsa_key(ctx.lend(), KeyType::Dec, Mechanism::Rsa3072Pkcs1v15)
        }
        DecryptionAlgorithm::Rsa4096 => {
            #[cfg(feature = "rsa4096-gen")]
            return gen_rsa_key(ctx.lend(), KeyType::Dec, Mechanism::Rsa4096Pkcs1v15);
            #[cfg(not(feature = "rsa4096-gen"))]
            return Err(Status::FunctionNotSupported);
        }
    }
}

pub fn aut<const R: usize, T: trussed::Client + AuthClient>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let algo = ctx.state.persistent.aut_alg();
    info!("Generating aut key with algorithm: {algo:?}");
    match algo {
        AuthenticationAlgorithm::Ed255 => gen_ec_key(ctx.lend(), KeyType::Aut, CurveAlgo::Ed255),
        AuthenticationAlgorithm::EcDsaP256 => {
            gen_ec_key(ctx.lend(), KeyType::Aut, CurveAlgo::EcDsaP256)
        }
        AuthenticationAlgorithm::Rsa2048 => {
            gen_rsa_key(ctx.lend(), KeyType::Aut, Mechanism::Rsa2048Pkcs1v15)
        }
        AuthenticationAlgorithm::Rsa3072 => {
            gen_rsa_key(ctx.lend(), KeyType::Aut, Mechanism::Rsa3072Pkcs1v15)
        }
        AuthenticationAlgorithm::Rsa4096 => {
            #[cfg(feature = "rsa4096-gen")]
            return gen_rsa_key(ctx.lend(), KeyType::Aut, Mechanism::Rsa4096Pkcs1v15);
            #[cfg(not(feature = "rsa4096-gen"))]
            return Err(Status::FunctionNotSupported);
        }
    }
}

#[cfg(feature = "rsa")]
fn gen_rsa_key<const R: usize, T: trussed::Client + AuthClient>(
    mut ctx: LoadedContext<'_, R, T>,
    key: KeyType,
    mechanism: Mechanism,
) -> Result<(), Status> {
    let client = ctx.backend.client_mut();
    let key_id = try_syscall!(client.generate_key(
        mechanism,
        StorageAttributes::default().set_persistence(Location::Volatile)
    ))
    .map_err(|_err| {
        error!("Failed to generate key: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .key;

    let pubkey = try_syscall!(client.derive_key(
        mechanism,
        key_id,
        None,
        StorageAttributes::default().set_persistence(ctx.options.storage)
    ))
    .map_err(|_err| {
        warn!("Failed to derive_ke: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .key;
    ctx.state
        .set_key(
            key,
            Some((key_id, (pubkey, KeyOrigin::Generated))),
            client,
            ctx.options.storage,
        )
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?;
    read_rsa_key(ctx, pubkey, mechanism)
}

fn gen_ec_key<const R: usize, T: trussed::Client + AuthClient>(
    mut ctx: LoadedContext<'_, R, T>,
    key: KeyType,
    curve: CurveAlgo,
) -> Result<(), Status> {
    let client = ctx.backend.client_mut();
    let key_id = try_syscall!(client.generate_key(
        curve.mechanism(),
        StorageAttributes::default().set_persistence(Location::Volatile)
    ))
    .map_err(|_err| {
        error!("Failed to generate key: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .key;

    let pubkey = try_syscall!(client.derive_key(
        curve.mechanism(),
        key_id,
        None,
        StorageAttributes::default().set_persistence(ctx.options.storage)
    ))
    .map_err(|_err| {
        warn!("Failed to derive_ke: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .key;
    ctx.state
        .set_key(
            key,
            Some((key_id, (pubkey, KeyOrigin::Generated))),
            client,
            ctx.options.storage,
        )
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?;
    read_ec_key(ctx, key_id, curve)
}

pub fn read_sign<const R: usize, T: trussed::Client + AuthClient>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx
        .state
        .persistent
        .public_key_id(KeyType::Sign)
        .ok_or(Status::KeyReferenceNotFound)?;

    let algo = ctx.state.persistent.sign_alg();
    match algo {
        SignatureAlgorithm::Ed255 => read_ec_key(ctx.lend(), key_id, CurveAlgo::Ed255),
        SignatureAlgorithm::EcDsaP256 => read_ec_key(ctx.lend(), key_id, CurveAlgo::EcDsaP256),
        SignatureAlgorithm::Rsa2048 => read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa2048Pkcs1v15),
        SignatureAlgorithm::Rsa3072 => read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa3072Pkcs1v15),
        SignatureAlgorithm::Rsa4096 => read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa4096Pkcs1v15),
    }
}

pub fn read_dec<const R: usize, T: trussed::Client + AuthClient>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx
        .state
        .persistent
        .public_key_id(KeyType::Dec)
        .ok_or(Status::KeyReferenceNotFound)?;

    let algo = ctx.state.persistent.dec_alg();
    match algo {
        DecryptionAlgorithm::X255 => read_ec_key(ctx.lend(), key_id, CurveAlgo::X255),
        DecryptionAlgorithm::EcDhP256 => read_ec_key(ctx.lend(), key_id, CurveAlgo::EcDhP256),
        DecryptionAlgorithm::Rsa2048 => {
            read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa2048Pkcs1v15)
        }
        DecryptionAlgorithm::Rsa3072 => {
            read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa3072Pkcs1v15)
        }
        DecryptionAlgorithm::Rsa4096 => {
            read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa4096Pkcs1v15)
        }
    }
}

pub fn read_aut<const R: usize, T: trussed::Client + AuthClient>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx
        .state
        .persistent
        .public_key_id(KeyType::Aut)
        .ok_or(Status::KeyReferenceNotFound)?;

    let algo = ctx.state.persistent.aut_alg();
    match algo {
        AuthenticationAlgorithm::Ed255 => read_ec_key(ctx.lend(), key_id, CurveAlgo::Ed255),
        AuthenticationAlgorithm::EcDsaP256 => read_ec_key(ctx.lend(), key_id, CurveAlgo::EcDsaP256),
        AuthenticationAlgorithm::Rsa2048 => {
            read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa2048Pkcs1v15)
        }
        AuthenticationAlgorithm::Rsa3072 => {
            read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa3072Pkcs1v15)
        }
        AuthenticationAlgorithm::Rsa4096 => {
            read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa4096Pkcs1v15)
        }
    }
}

fn serialize_p256<const R: usize, T: trussed::Client + AuthClient>(
    mut ctx: LoadedContext<'_, R, T>,
    serialized: &[u8],
) -> Result<(), Status> {
    ctx.reply.expand(&[0x86])?;
    ctx.reply.append_len(serialized.len() + 1)?;
    ctx.reply.expand(&[0x04])?;
    ctx.reply.expand(serialized)
}

fn serialize_25519<const R: usize, T: trussed::Client + AuthClient>(
    mut ctx: LoadedContext<'_, R, T>,
    serialized: &[u8],
) -> Result<(), Status> {
    ctx.reply.expand(&[0x86])?;
    ctx.reply.append_len(serialized.len())?;
    ctx.reply.expand(serialized)
}

fn read_ec_key<const R: usize, T: trussed::Client + AuthClient>(
    mut ctx: LoadedContext<'_, R, T>,
    public_key: KeyId,
    curve: CurveAlgo,
) -> Result<(), Status> {
    let client = ctx.backend.client_mut();
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

#[cfg(feature = "rsa")]
fn read_rsa_key<const R: usize, T: trussed::Client + AuthClient>(
    mut ctx: LoadedContext<'_, R, T>,
    public_key: KeyId,
    mechanism: Mechanism,
) -> Result<(), Status> {
    let client = ctx.backend.client_mut();
    ctx.reply.expand(KEYGEN_DO_TAG)?;
    let offset = ctx.reply.len();

    let pubkey_data =
        try_syscall!(client.serialize_key(mechanism, public_key, KeySerialization::RsaParts))
            .map_err(|_err| {
                error!("Failed to serialize public key N: {_err:?}");
                syscall!(client.delete(public_key));
                Status::UnspecifiedNonpersistentExecutionError
            })?
            .serialized_key;
    let parsed_pubkey_data: RsaPublicParts =
        trussed::postcard_deserialize(&pubkey_data).map_err(|_err| {
            error!("Failed to deserialize public key");
            syscall!(client.delete(public_key));
            Status::UnspecifiedNonpersistentExecutionError
        })?;
    ctx.reply.expand(&[0x81])?;
    ctx.reply.append_len(parsed_pubkey_data.n.len())?;
    ctx.reply.expand(parsed_pubkey_data.n)?;

    ctx.reply.expand(&[0x82])?;
    ctx.reply.append_len(parsed_pubkey_data.e.len())?;
    ctx.reply.expand(parsed_pubkey_data.e)?;

    ctx.reply.prepend_len(offset)?;

    syscall!(client.delete(public_key));
    Ok(())
}

#[cfg(not(feature = "rsa"))]
fn gen_rsa_key<const R: usize, T: trussed::Client + AuthClient>(
    _ctx: LoadedContext<'_, R, T>,
    _key: KeyType,
    _mechanism: Mechanism,
) -> Result<(), Status> {
    Err(Status::FunctionNotSupported)
}

#[cfg(not(feature = "rsa"))]
fn read_rsa_key<const R: usize, T: trussed::Client + AuthClient>(
    _ctx: LoadedContext<'_, R, T>,
    _key_id: KeyId,
    _mechanism: Mechanism,
) -> Result<(), Status> {
    Err(Status::FunctionNotSupported)
}
