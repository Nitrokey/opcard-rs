// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;
use trussed::try_syscall;
use trussed::types::{KeyId, KeySerialization, Location, Mechanism, StorageAttributes};

use crate::card::LoadedContext;
use crate::state::KeyOrigin;
use crate::tlv::get_do;
use crate::types::*;

const PRIVATE_KEY_TEMPLATE_DO: u16 = 0x4D;
const CONCATENATION_KEY_DATA_DO: u16 = 0x5F48;

#[cfg(feature = "rsa")]
use trussed_rsa_alloc::RsaImportFormat;

// § 4.4.3.12
pub fn put_private_key_template<const R: usize, T: crate::card::Client>(
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

pub fn put_sign<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let attr = ctx.state.persistent.sign_alg();
    let key_id = match attr {
        SignatureAlgorithm::EcDsaP256 => put_ec(ctx.lend(), CurveAlgo::EcDsaP256)?,
        SignatureAlgorithm::Ed255 => put_ec(ctx.lend(), CurveAlgo::Ed255)?,
        SignatureAlgorithm::Rsa2048 => put_rsa(ctx.lend(), Mechanism::Rsa2048Pkcs1v15)?,
        SignatureAlgorithm::Rsa3072 => put_rsa(ctx.lend(), Mechanism::Rsa3072Pkcs1v15)?,
        SignatureAlgorithm::Rsa4096 => put_rsa(ctx.lend(), Mechanism::Rsa4096Pkcs1v15)?,
    }
    .map(|(private_key, pubkey)| (private_key, (pubkey, KeyOrigin::Imported)));
    ctx.state
        .set_key(
            KeyType::Sign,
            key_id,
            ctx.backend.client_mut(),
            ctx.options.storage,
        )
        .map_err(|_err| {
            error!("Failed to store new key: {_err:?}");
            Status::UnspecifiedNonpersistentExecutionError
        })?;
    Ok(())
}

pub fn put_dec<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let attr = ctx.state.persistent.dec_alg();
    let key_id = match attr {
        DecryptionAlgorithm::EcDhP256 => put_ec(ctx.lend(), CurveAlgo::EcDhP256)?,
        DecryptionAlgorithm::X255 => put_ec(ctx.lend(), CurveAlgo::X255)?,
        DecryptionAlgorithm::Rsa2048 => put_rsa(ctx.lend(), Mechanism::Rsa2048Pkcs1v15)?,
        DecryptionAlgorithm::Rsa3072 => put_rsa(ctx.lend(), Mechanism::Rsa3072Pkcs1v15)?,
        DecryptionAlgorithm::Rsa4096 => put_rsa(ctx.lend(), Mechanism::Rsa4096Pkcs1v15)?,
    }
    .map(|(private_key, pubkey)| (private_key, (pubkey, KeyOrigin::Imported)));
    ctx.state
        .set_key(
            KeyType::Dec,
            key_id,
            ctx.backend.client_mut(),
            ctx.options.storage,
        )
        .map_err(|_err| {
            error!("Failed to store new key: {_err:?}");
            Status::UnspecifiedNonpersistentExecutionError
        })?;
    Ok(())
}

pub fn put_aut<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let attr = ctx.state.persistent.aut_alg();
    let key_id = match attr {
        AuthenticationAlgorithm::EcDsaP256 => put_ec(ctx.lend(), CurveAlgo::EcDsaP256)?,
        AuthenticationAlgorithm::Ed255 => put_ec(ctx.lend(), CurveAlgo::Ed255)?,
        AuthenticationAlgorithm::Rsa2048 => put_rsa(ctx.lend(), Mechanism::Rsa2048Pkcs1v15)?,
        AuthenticationAlgorithm::Rsa3072 => put_rsa(ctx.lend(), Mechanism::Rsa3072Pkcs1v15)?,
        AuthenticationAlgorithm::Rsa4096 => put_rsa(ctx.lend(), Mechanism::Rsa4096Pkcs1v15)?,
    }
    .map(|(private_key, public_key)| (private_key, (public_key, KeyOrigin::Imported)));
    ctx.state
        .set_key(
            KeyType::Aut,
            key_id,
            ctx.backend.client_mut(),
            ctx.options.storage,
        )
        .map_err(|_err| {
            error!("Failed to store new key: {_err:?}");
            Status::UnspecifiedNonpersistentExecutionError
        })?;
    Ok(())
}

fn put_ec<const R: usize, T: crate::card::Client>(
    ctx: LoadedContext<'_, R, T>,
    curve: CurveAlgo,
) -> Result<Option<(KeyId, KeyId)>, Status> {
    debug!("Importing key for algo {curve:?}");
    let private_key_data = get_do(
        &[PRIVATE_KEY_TEMPLATE_DO, CONCATENATION_KEY_DATA_DO],
        ctx.data,
    )
    .ok_or_else(|| {
        warn!("Missing key data");
        Status::IncorrectDataParameter
    })?;

    // GPG stores scalars as big endian when X25519 specifies them to be little endian
    // See https://lists.gnupg.org/pipermail/gnupg-devel/2018-February/033437.html
    let mut data: [u8; 32];
    let message;
    if matches!(curve, CurveAlgo::X255) {
        data = private_key_data.try_into().map_err(|_| {
            warn!(
                "Bad private key length for x25519: {}",
                private_key_data.len()
            );
            Status::IncorrectDataParameter
        })?;
        data.reverse();
        message = data.as_slice();
    } else {
        message = private_key_data;
    }

    let key = try_syscall!(ctx.backend.client_mut().unsafe_inject_key(
        curve.mechanism(),
        message,
        Location::Volatile,
        KeySerialization::Raw
    ))
    .map_err(|_err| {
        warn!("Failed to store key: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .key;

    let pubkey = try_syscall!(ctx.backend.client_mut().derive_key(
        curve.mechanism(),
        key,
        None,
        StorageAttributes::default().set_persistence(ctx.options.storage)
    ))
    .map_err(|_err| {
        warn!("Failed to derive_ke: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .key;
    Ok(Some((key, pubkey)))
}

#[cfg(feature = "rsa")]
fn parse_rsa_template(data: &[u8]) -> Option<RsaImportFormat> {
    use crate::tlv::take_len;
    const TEMPLATE_DO: u16 = 0x7F48;

    let mut template = get_do(&[PRIVATE_KEY_TEMPLATE_DO, TEMPLATE_DO], data)?;
    let mut res = [(0, 0); 6];
    let mut acc = 0;
    for i in 0..3 {
        let Some(tag) = template.first() else {
            warn!("Missing template data. Only got up to {:x}", i+0x90);
            return None;
        };
        if *tag != i + 0x91 {
            warn!("Unexpected template data: {}", template.first()?);
            return None;
        }
        let (size, d) = take_len(&template[1..])?;
        res[i as usize] = (acc, acc + size);
        acc += size;
        template = d;
    }
    let key_data = get_do(&[PRIVATE_KEY_TEMPLATE_DO, CONCATENATION_KEY_DATA_DO], data)?;
    Some(RsaImportFormat {
        e: key_data.get(res[0].0..res[0].1)?,
        p: key_data.get(res[1].0..res[1].1)?,
        q: key_data.get(res[2].0..res[2].1)?,
    })
}

#[cfg(feature = "rsa")]
fn put_rsa<const R: usize, T: crate::card::Client>(
    ctx: LoadedContext<'_, R, T>,
    mechanism: Mechanism,
) -> Result<Option<(KeyId, KeyId)>, Status> {
    match mechanism {
        #[cfg(feature = "rsa2048")]
        Mechanism::Rsa2048Pkcs1v15 => {}
        #[cfg(feature = "rsa3072")]
        Mechanism::Rsa3072Pkcs1v15 => {}
        #[cfg(feature = "rsa4096")]
        Mechanism::Rsa4096Pkcs1v15 => {}
        _ => return Err(Status::FunctionNotSupported),
    };

    let key_data = parse_rsa_template(ctx.data).ok_or_else(|| {
        warn!("Unable to parse RSA key");
        Status::IncorrectDataParameter
    })?;

    let key_message = key_data.serialize().map_err(|_err| {
        error!("Failed to serialize RSA key: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?;
    let key = try_syscall!(ctx.backend.client_mut().unsafe_inject_key(
        mechanism,
        &key_message,
        Location::Volatile,
        KeySerialization::RsaParts
    ))
    .map_err(|_err| {
        warn!("Failed to store key: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .key;

    let pubkey = try_syscall!(ctx.backend.client_mut().derive_key(
        mechanism,
        key,
        None,
        StorageAttributes::default().set_persistence(ctx.options.storage)
    ))
    .map_err(|_err| {
        warn!("Failed to derive_ke: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .key;
    Ok(Some((key, pubkey)))
}

#[cfg(not(feature = "rsa"))]
fn put_rsa<const R: usize, T: crate::card::Client>(
    _ctx: LoadedContext<'_, R, T>,
    _mechanism: Mechanism,
) -> Result<Option<(KeyId, KeyId)>, Status> {
    Err(Status::FunctionNotSupported)
}
