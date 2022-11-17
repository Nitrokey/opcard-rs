// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;

use trussed::types::*;
use trussed::{syscall, try_syscall};

use crate::card::LoadedContext;
use crate::state::KeyRef;
use crate::tlv::get_do;
use crate::types::*;

fn check_uif<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
    key: KeyType,
) -> Result<(), Status> {
    if ctx.state.internal.uif(key).is_enabled() {
        prompt_uif(ctx)
    } else {
        Ok(())
    }
}

fn prompt_uif<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let success = ctx
        .backend
        .confirm_user_present()
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?;
    if !success {
        warn!("User presence confirmation timed out");
        // FIXME SecurityRelatedIssues (0x6600 is not available?)
        Err(Status::SecurityStatusNotSatisfied)
    } else {
        Ok(())
    }
}

// § 7.2.10
pub fn sign<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx.state.internal.key_id(KeyType::Sign).ok_or_else(|| {
        warn!("Attempt to sign without a key set");
        Status::KeyReferenceNotFound
    })?;
    if !ctx.state.runtime.sign_verified {
        warn!("Attempt to sign without PW1 verified");
        return Err(Status::SecurityStatusNotSatisfied);
    }

    check_uif(ctx.lend(), KeyType::Sign)?;
    if !ctx.state.internal.pw1_valid_multiple() {
        ctx.state.runtime.sign_verified = false;
    }
    ctx.state
        .internal
        .increment_sign_count(ctx.backend.client_mut())
        .map_err(|_err| {
            error!("Failed to increment sign count");
            Status::UnspecifiedPersistentExecutionError
        })?;

    match ctx.state.internal.sign_alg() {
        SignatureAlgorithm::Ed255 => sign_ec(ctx, key_id, Mechanism::Ed255),
        SignatureAlgorithm::EcDsaP256 => {
            if ctx.data.len() != 32 {
                return Err(Status::ConditionsOfUseNotSatisfied);
            }
            sign_ec(ctx, key_id, Mechanism::P256Prehashed)
        }
        SignatureAlgorithm::Rsa2048 => sign_rsa(ctx, key_id, Mechanism::Rsa2048Pkcs),
        SignatureAlgorithm::Rsa4096 => sign_rsa(ctx, key_id, Mechanism::Rsa4096Pkcs),
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

fn sign_rsa<const R: usize, T: trussed::Client>(
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

enum RsaOrEcc {
    Rsa,
    Ecc,
}

fn int_aut_key_mecha_uif<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(KeyId, Mechanism, bool, RsaOrEcc), Status> {
    let (key_type, (mechanism, key_kind)) = match ctx.state.runtime.keyrefs.internal_aut {
        KeyRef::Aut => (
            KeyType::Aut,
            match ctx.state.internal.aut_alg() {
                AuthenticationAlgorithm::EcDsaP256 => (Mechanism::P256Prehashed, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::Ed255 => (Mechanism::Ed255, RsaOrEcc::Ecc),

                AuthenticationAlgorithm::Rsa2048 => (Mechanism::Rsa2048Pkcs, RsaOrEcc::Rsa),
                AuthenticationAlgorithm::Rsa4096 => (Mechanism::Rsa4096Pkcs, RsaOrEcc::Rsa),
            },
        ),
        KeyRef::Dec => (
            KeyType::Dec,
            match ctx.state.internal.dec_alg() {
                DecryptionAlgorithm::X255 => {
                    warn!("Attempt to authenticate with X25519 key");
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                DecryptionAlgorithm::EcDhP256 => (Mechanism::P256Prehashed, RsaOrEcc::Ecc),
                DecryptionAlgorithm::Rsa2048 => (Mechanism::Rsa2048Pkcs, RsaOrEcc::Rsa),
                DecryptionAlgorithm::Rsa4096 => (Mechanism::Rsa4096Pkcs, RsaOrEcc::Rsa),
            },
        ),
    };

    if mechanism == Mechanism::P256Prehashed && ctx.data.len() != 32 {
        warn!(
            "Attempt to sign with P256 with data length != 32: {}",
            ctx.data.len()
        );
        return Err(Status::ConditionsOfUseNotSatisfied);
    }

    Ok((
        ctx.state.internal.key_id(key_type).ok_or_else(|| {
            warn!("Attempt to INTERNAL AUTHENTICATE without a key set");
            Status::KeyReferenceNotFound
        })?,
        mechanism,
        ctx.state.internal.uif(key_type).is_enabled(),
        key_kind,
    ))
}

// § 7.2.13
pub fn internal_authenticate<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    if !ctx.state.runtime.other_verified {
        warn!("Attempt to sign without PW1 verified");
        return Err(Status::SecurityStatusNotSatisfied);
    }

    let (key_id, mechanism, uif, key_kind) = int_aut_key_mecha_uif(ctx.lend())?;
    if uif {
        prompt_uif(ctx.lend())?;
    }

    match key_kind {
        RsaOrEcc::Ecc => sign_ec(ctx, key_id, mechanism),
        RsaOrEcc::Rsa => sign_rsa(ctx, key_id, mechanism),
    }
}

fn decipher_key_mecha_uif<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(KeyId, Mechanism, bool, RsaOrEcc), Status> {
    let (key_type, (mechanism, key_kind)) = match ctx.state.runtime.keyrefs.pso_decipher {
        KeyRef::Dec => (
            KeyType::Dec,
            match ctx.state.internal.dec_alg() {
                DecryptionAlgorithm::X255 => (Mechanism::X255, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhP256 => (Mechanism::P256, RsaOrEcc::Ecc),
                DecryptionAlgorithm::Rsa2048 => (Mechanism::Rsa2048Pkcs, RsaOrEcc::Rsa),
                DecryptionAlgorithm::Rsa4096 => (Mechanism::Rsa4096Pkcs, RsaOrEcc::Rsa),
            },
        ),
        KeyRef::Aut => (
            KeyType::Aut,
            match ctx.state.internal.aut_alg() {
                AuthenticationAlgorithm::EcDsaP256 => (Mechanism::P256, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::Ed255 => {
                    warn!("Attempt to decipher with Ed255 key");
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }

                AuthenticationAlgorithm::Rsa2048 => (Mechanism::Rsa2048Pkcs, RsaOrEcc::Rsa),
                AuthenticationAlgorithm::Rsa4096 => (Mechanism::Rsa4096Pkcs, RsaOrEcc::Rsa),
            },
        ),
    };

    Ok((
        ctx.state.internal.key_id(key_type).ok_or_else(|| {
            warn!("Attempt to decrypt without a key set");
            Status::KeyReferenceNotFound
        })?,
        mechanism,
        ctx.state.internal.uif(key_type).is_enabled(),
        key_kind,
    ))
}

// § 7.2.11
pub fn decipher<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    if !ctx.state.runtime.other_verified {
        warn!("Attempt to sign without PW1 verified");
        return Err(Status::SecurityStatusNotSatisfied);
    }

    if ctx.data.is_empty() {
        return Err(Status::IncorrectDataParameter);
    }
    if ctx.data[0] == 0x02 {
        return decipher_aes(ctx);
    }

    let (key_id, mechanism, uif, key_kind) = decipher_key_mecha_uif(ctx.lend())?;
    if uif {
        prompt_uif(ctx.lend())?;
    }
    match key_kind {
        RsaOrEcc::Ecc => decrypt_ec(ctx, key_id, mechanism),
        RsaOrEcc::Rsa => decrypt_rsa(ctx, key_id, mechanism),
    }
}

fn decrypt_rsa<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    private_key: KeyId,
    mechanism: Mechanism,
) -> Result<(), Status> {
    if ctx.data.is_empty() {
        return Err(Status::IncorrectDataParameter);
    }
    let plaintext = try_syscall!(ctx.backend.client_mut().decrypt(
        mechanism,
        private_key,
        &ctx.data[1..],
        &[],
        &[],
        &[]
    ))
    .map_err(|_err| {
        error!("Failed to decrypt data: {_err:?}");
        Status::IncorrectDataParameter
    })?
    .plaintext
    .ok_or_else(|| {
        warn!("No plaintext");
        Status::IncorrectDataParameter
    })?;
    ctx.reply.expand(&plaintext)
}

fn decrypt_ec<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    private_key: KeyId,
    mechanism: Mechanism,
) -> Result<(), Status> {
    // Cipher DO - Public key DO - External public key
    const DATA_PATH: &[u16] = &[0xA6, 0x7F49, 0x86];
    let data = get_do(DATA_PATH, ctx.data).ok_or_else(|| {
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

fn decipher_aes<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx.state.internal.aes_key().ok_or_else(|| {
        warn!("Attempt to decipher with AES and no key set");
        Status::ConditionsOfUseNotSatisfied
    })?;

    if (ctx.data.len() - 1) % 16 != 0 {
        warn!("Attempt to decipher with AES with length not a multiple of block size");
        return Err(Status::IncorrectDataParameter);
    }

    let plaintext = syscall!(ctx.backend.client_mut().decrypt(
        Mechanism::Aes256Cbc,
        key_id,
        &ctx.data[1..],
        &[], // No AAD
        &[], // Zero IV
        &[]  // No authentication tag
    ))
    .plaintext
    .ok_or_else(|| {
        warn!("Failed decryption");
        Status::UnspecifiedCheckingError
    })?;
    ctx.reply.expand(&plaintext)
}

pub fn encipher<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    if !ctx.state.runtime.other_verified {
        warn!("Attempt to encipher without PW1 verified");
        return Err(Status::SecurityStatusNotSatisfied);
    }

    let key_id = ctx.state.internal.aes_key().ok_or_else(|| {
        warn!("Attempt to decipher with AES and no key set");
        Status::ConditionsOfUseNotSatisfied
    })?;

    if ctx.data.len() % 16 != 0 {
        warn!("Attempt to encipher with AES with length not a multiple of block size");
        return Err(Status::IncorrectDataParameter);
    }

    let plaintext = syscall!(ctx.backend.client_mut().encrypt(
        Mechanism::Aes256Cbc,
        key_id,
        ctx.data,
        &[],
        None
    ))
    .ciphertext;
    ctx.reply.expand(&[0x02])?;
    ctx.reply.expand(&plaintext)
}
