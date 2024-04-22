// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use hex_literal::hex;
use iso7816::Status;
use trussed::try_syscall;
use trussed::types::{KeyId, KeySerialization, Location, Mechanism, StorageAttributes};

use crate::card::LoadedContext;
use crate::state::KeyOrigin;
use crate::types::*;

const KEYGEN_DO_TAG: &[u8] = &hex!("7f49");

#[cfg(feature = "rsa")]
use trussed_rsa_alloc::RsaPublicParts;

fn serialize_pub<const R: usize, T: crate::card::Client>(
    algo: CurveAlgo,
    ctx: LoadedContext<'_, R, T>,
    public_key: &[u8],
) -> Result<(), Status> {
    match algo {
        CurveAlgo::EcDsaP256 | CurveAlgo::EcDhP256 => serialize_nist_curve(ctx, public_key),
        CurveAlgo::EcDsaP384 | CurveAlgo::EcDhP384 => serialize_nist_curve(ctx, public_key),
        CurveAlgo::EcDsaP521 | CurveAlgo::EcDhP521 => serialize_nist_curve(ctx, public_key),
        CurveAlgo::X255 | CurveAlgo::Ed255 => serialize_25519(ctx, public_key),
    }
}

pub fn sign<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let algo = ctx.state.persistent.sign_alg();
    if !algo.is_allowed(ctx.options.allowed_generation) {
        warn!("Attempt to generate key disabled {:?}", algo);
        return Err(Status::FunctionNotSupported);
    }
    info!("Generating sign key with algorithm: {algo:?}");
    match algo {
        SignatureAlgorithm::Ed255 => gen_ec_key(ctx.lend(), KeyType::Sign, CurveAlgo::Ed255),
        SignatureAlgorithm::EcDsaP256 => {
            gen_ec_key(ctx.lend(), KeyType::Sign, CurveAlgo::EcDsaP256)
        }
        SignatureAlgorithm::EcDsaP384 => {
            gen_ec_key(ctx.lend(), KeyType::Sign, CurveAlgo::EcDsaP384)
        }
        SignatureAlgorithm::EcDsaP521 => {
            gen_ec_key(ctx.lend(), KeyType::Sign, CurveAlgo::EcDsaP521)
        }
        SignatureAlgorithm::Rsa2048 => {
            gen_rsa_key(ctx.lend(), KeyType::Sign, Mechanism::Rsa2048Pkcs1v15)
        }
        SignatureAlgorithm::Rsa3072 => {
            gen_rsa_key(ctx.lend(), KeyType::Sign, Mechanism::Rsa3072Pkcs1v15)
        }
        SignatureAlgorithm::Rsa4096 => {
            gen_rsa_key(ctx.lend(), KeyType::Sign, Mechanism::Rsa4096Pkcs1v15)
        }
    }
}

pub fn dec<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let algo = ctx.state.persistent.dec_alg();
    if !algo.is_allowed(ctx.options.allowed_generation) {
        warn!("Attempt to generate key disabled {:?}", algo);
        return Err(Status::FunctionNotSupported);
    }
    info!("Generating dec key with algorithm: {algo:?}");
    match algo {
        DecryptionAlgorithm::X255 => gen_ec_key(ctx.lend(), KeyType::Dec, CurveAlgo::X255),
        DecryptionAlgorithm::EcDhP256 => gen_ec_key(ctx.lend(), KeyType::Dec, CurveAlgo::EcDhP256),
        DecryptionAlgorithm::EcDhP384 => gen_ec_key(ctx.lend(), KeyType::Dec, CurveAlgo::EcDhP384),
        DecryptionAlgorithm::EcDhP521 => gen_ec_key(ctx.lend(), KeyType::Dec, CurveAlgo::EcDhP521),
        DecryptionAlgorithm::Rsa2048 => {
            gen_rsa_key(ctx.lend(), KeyType::Dec, Mechanism::Rsa2048Pkcs1v15)
        }
        DecryptionAlgorithm::Rsa3072 => {
            gen_rsa_key(ctx.lend(), KeyType::Dec, Mechanism::Rsa3072Pkcs1v15)
        }
        DecryptionAlgorithm::Rsa4096 => {
            gen_rsa_key(ctx.lend(), KeyType::Dec, Mechanism::Rsa4096Pkcs1v15)
        }
    }
}

pub fn aut<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let algo = ctx.state.persistent.aut_alg();
    if !algo.is_allowed(ctx.options.allowed_generation) {
        warn!("Attempt to generate key disabled {:?}", algo);
        return Err(Status::FunctionNotSupported);
    }
    info!("Generating aut key with algorithm: {algo:?}");
    match algo {
        AuthenticationAlgorithm::Ed255 => gen_ec_key(ctx.lend(), KeyType::Aut, CurveAlgo::Ed255),
        AuthenticationAlgorithm::EcDsaP256 => {
            gen_ec_key(ctx.lend(), KeyType::Aut, CurveAlgo::EcDsaP256)
        }
        AuthenticationAlgorithm::EcDsaP384 => {
            gen_ec_key(ctx.lend(), KeyType::Aut, CurveAlgo::EcDsaP384)
        }
        AuthenticationAlgorithm::EcDsaP521 => {
            gen_ec_key(ctx.lend(), KeyType::Aut, CurveAlgo::EcDsaP521)
        }
        AuthenticationAlgorithm::Rsa2048 => {
            gen_rsa_key(ctx.lend(), KeyType::Aut, Mechanism::Rsa2048Pkcs1v15)
        }
        AuthenticationAlgorithm::Rsa3072 => {
            gen_rsa_key(ctx.lend(), KeyType::Aut, Mechanism::Rsa3072Pkcs1v15)
        }
        AuthenticationAlgorithm::Rsa4096 => {
            gen_rsa_key(ctx.lend(), KeyType::Aut, Mechanism::Rsa4096Pkcs1v15)
        }
    }
}

#[cfg(feature = "rsa")]
fn gen_rsa_key<const R: usize, T: crate::card::Client>(
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
#[cfg(not(feature = "rsa"))]
fn gen_rsa_key<const R: usize, T: crate::card::Client>(
    _ctx: LoadedContext<'_, R, T>,
    _key: KeyType,
    _mechanism: Mechanism,
) -> Result<(), Status> {
    Err(Status::FunctionNotSupported)
}

fn gen_ec_key<const R: usize, T: crate::card::Client>(
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
    read_ec_key(ctx, pubkey, curve)
}

pub fn read_sign<const R: usize, T: crate::card::Client>(
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
        SignatureAlgorithm::EcDsaP384 => read_ec_key(ctx.lend(), key_id, CurveAlgo::EcDsaP384),
        SignatureAlgorithm::EcDsaP521 => read_ec_key(ctx.lend(), key_id, CurveAlgo::EcDsaP521),
        SignatureAlgorithm::Rsa2048 => read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa2048Pkcs1v15),
        SignatureAlgorithm::Rsa3072 => read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa3072Pkcs1v15),
        SignatureAlgorithm::Rsa4096 => read_rsa_key(ctx.lend(), key_id, Mechanism::Rsa4096Pkcs1v15),
    }
}

pub fn read_dec<const R: usize, T: crate::card::Client>(
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
        DecryptionAlgorithm::EcDhP384 => read_ec_key(ctx.lend(), key_id, CurveAlgo::EcDhP384),
        DecryptionAlgorithm::EcDhP521 => read_ec_key(ctx.lend(), key_id, CurveAlgo::EcDhP521),
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

pub fn read_aut<const R: usize, T: crate::card::Client>(
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
        AuthenticationAlgorithm::EcDsaP384 => read_ec_key(ctx.lend(), key_id, CurveAlgo::EcDsaP384),
        AuthenticationAlgorithm::EcDsaP521 => read_ec_key(ctx.lend(), key_id, CurveAlgo::EcDsaP521),
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

fn serialize_nist_curve<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    serialized: &[u8],
) -> Result<(), Status> {
    ctx.reply.expand(&[0x86])?;
    ctx.reply.append_len(serialized.len() + 1)?;
    ctx.reply.expand(&[0x04])?;
    ctx.reply.expand(serialized)
}

fn serialize_25519<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    serialized: &[u8],
) -> Result<(), Status> {
    ctx.reply.expand(&[0x86])?;
    ctx.reply.append_len(serialized.len())?;
    ctx.reply.expand(serialized)
}

fn read_ec_key<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    public_key: KeyId,
    curve: CurveAlgo,
) -> Result<(), Status> {
    let client = ctx.backend.client_mut();
    let serialized =
        try_syscall!(client.serialize_key(curve.mechanism(), public_key, KeySerialization::Raw))
            .map_err(|_err| {
                error!("Failed to serialize public key: {_err:?}");
                Status::UnspecifiedNonpersistentExecutionError
            })?
            .serialized_key;
    ctx.reply.expand(KEYGEN_DO_TAG)?;
    let offset = ctx.reply.len();
    serialize_pub(curve, ctx.lend(), &serialized)?;
    ctx.reply.prepend_len(offset)
}

#[cfg(feature = "rsa")]
fn read_rsa_key<const R: usize, T: crate::card::Client>(
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
                Status::UnspecifiedNonpersistentExecutionError
            })?
            .serialized_key;
    let parsed_pubkey_data = RsaPublicParts::deserialize(&pubkey_data).map_err(|_err| {
        error!("Failed to deserialize public key");
        Status::UnspecifiedNonpersistentExecutionError
    })?;
    ctx.reply.expand(&[0x81])?;
    ctx.reply.append_len(parsed_pubkey_data.n.len())?;
    ctx.reply.expand(parsed_pubkey_data.n)?;

    ctx.reply.expand(&[0x82])?;
    ctx.reply.append_len(parsed_pubkey_data.e.len())?;
    ctx.reply.expand(parsed_pubkey_data.e)?;

    ctx.reply.prepend_len(offset)?;

    Ok(())
}

#[cfg(not(feature = "rsa"))]
fn read_rsa_key<const R: usize, T: crate::card::Client>(
    _ctx: LoadedContext<'_, R, T>,
    _key_id: KeyId,
    _mechanism: Mechanism,
) -> Result<(), Status> {
    Err(Status::FunctionNotSupported)
}
