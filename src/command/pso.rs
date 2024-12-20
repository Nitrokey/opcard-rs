// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;

use trussed_core::config::MAX_MESSAGE_LENGTH;
use trussed_core::types::*;
use trussed_core::{syscall, try_syscall};

use crate::card::LoadedContext;
use crate::state::KeyRef;
use crate::tlv::get_do;
use crate::types::*;

fn check_uif<const R: usize, T: crate::card::Client>(
    ctx: LoadedContext<'_, R, T>,
    key: KeyType,
) -> Result<(), Status> {
    if ctx.state.persistent.uif(key).is_enabled() {
        prompt_uif(ctx)
    } else {
        Ok(())
    }
}

fn prompt_uif<const R: usize, T: crate::card::Client>(
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
pub fn sign<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx
        .state
        .key_id(ctx.backend.client_mut(), KeyType::Sign, ctx.options.storage)?;

    check_uif(ctx.lend(), KeyType::Sign)?;
    let sign_result = ctx
        .state
        .persistent
        .increment_sign_count(ctx.backend.client_mut(), ctx.options.storage)
        .map_err(|_err| {
            error!("Failed to increment sign count");
            Status::UnspecifiedPersistentExecutionError
        })
        .and_then(|_| match ctx.state.persistent.sign_alg() {
            SignatureAlgorithm::Ed255 => sign_ec(ctx.lend(), key_id, Mechanism::Ed255),
            SignatureAlgorithm::EcDsaP256 => {
                if ctx.data.len() != 32 {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                sign_ec(ctx.lend(), key_id, Mechanism::P256Prehashed)
            }
            SignatureAlgorithm::EcDsaP384 => {
                if ctx.data.len() != 48 {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                sign_ec(ctx.lend(), key_id, Mechanism::P384Prehashed)
            }
            SignatureAlgorithm::EcDsaP521 => {
                if ctx.data.len() != 64 {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                sign_ec(ctx.lend(), key_id, Mechanism::P521Prehashed)
            }
            SignatureAlgorithm::EcDsaBrainpoolP256R1 => {
                if ctx.data.len() != 32 {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                sign_ec(ctx.lend(), key_id, Mechanism::BrainpoolP256R1Prehashed)
            }
            SignatureAlgorithm::EcDsaBrainpoolP384R1 => {
                if ctx.data.len() != 48 {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                sign_ec(ctx.lend(), key_id, Mechanism::BrainpoolP384R1Prehashed)
            }
            SignatureAlgorithm::EcDsaBrainpoolP512R1 => {
                if ctx.data.len() != 64 {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                sign_ec(ctx.lend(), key_id, Mechanism::BrainpoolP512R1Prehashed)
            }
            SignatureAlgorithm::EcDsaSecp256k1 => {
                if ctx.data.len() != 32 {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                sign_ec(ctx.lend(), key_id, Mechanism::Secp256k1Prehashed)
            }
            SignatureAlgorithm::Rsa2048 => sign_rsa(ctx.lend(), key_id, Mechanism::Rsa2048Pkcs1v15),
            SignatureAlgorithm::Rsa3072 => sign_rsa(ctx.lend(), key_id, Mechanism::Rsa3072Pkcs1v15),
            SignatureAlgorithm::Rsa4096 => sign_rsa(ctx.lend(), key_id, Mechanism::Rsa4096Pkcs1v15),
        });

    if !ctx.state.persistent.pw1_valid_multiple() {
        ctx.state.volatile.clear_sign(ctx.backend.client_mut())
    }
    sign_result
}

fn sign_ec<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    key_id: KeyId,
    mechanism: Mechanism,
) -> Result<(), Status> {
    if ctx.data.len() > MAX_MESSAGE_LENGTH {
        error!("Attempt to sign more than 1Kb of data");
        return Err(Status::NotEnoughMemory);
    }

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

fn sign_rsa<const R: usize, T: crate::card::Client>(
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

fn int_aut_key_mecha_uif<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(KeyId, Mechanism, bool, RsaOrEcc), Status> {
    let (key_type, (mechanism, key_kind)) = match ctx.state.volatile.keyrefs.internal_aut {
        KeyRef::Aut => (
            KeyType::Aut,
            match ctx.state.persistent.aut_alg() {
                AuthenticationAlgorithm::EcDsaP256 => (Mechanism::P256Prehashed, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::EcDsaP384 => (Mechanism::P384Prehashed, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::EcDsaP521 => (Mechanism::P521Prehashed, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::EcDsaBrainpoolP256R1 => {
                    (Mechanism::BrainpoolP256R1Prehashed, RsaOrEcc::Ecc)
                }
                AuthenticationAlgorithm::EcDsaBrainpoolP384R1 => {
                    (Mechanism::BrainpoolP384R1Prehashed, RsaOrEcc::Ecc)
                }
                AuthenticationAlgorithm::EcDsaBrainpoolP512R1 => {
                    (Mechanism::BrainpoolP512R1Prehashed, RsaOrEcc::Ecc)
                }
                AuthenticationAlgorithm::EcDsaSecp256k1 => {
                    (Mechanism::Secp256k1Prehashed, RsaOrEcc::Ecc)
                }
                AuthenticationAlgorithm::Ed255 => (Mechanism::Ed255, RsaOrEcc::Ecc),

                AuthenticationAlgorithm::Rsa2048 => (Mechanism::Rsa2048Pkcs1v15, RsaOrEcc::Rsa),
                AuthenticationAlgorithm::Rsa3072 => (Mechanism::Rsa3072Pkcs1v15, RsaOrEcc::Rsa),
                AuthenticationAlgorithm::Rsa4096 => (Mechanism::Rsa4096Pkcs1v15, RsaOrEcc::Rsa),
            },
        ),
        KeyRef::Dec => (
            KeyType::Dec,
            match ctx.state.persistent.dec_alg() {
                DecryptionAlgorithm::X255 => {
                    warn!("Attempt to authenticate with X25519 key");
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                DecryptionAlgorithm::EcDhP256 => (Mechanism::P256Prehashed, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhP384 => (Mechanism::P384Prehashed, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhP521 => (Mechanism::P521Prehashed, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhBrainpoolP256R1 => {
                    (Mechanism::BrainpoolP256R1Prehashed, RsaOrEcc::Ecc)
                }
                DecryptionAlgorithm::EcDhBrainpoolP384R1 => {
                    (Mechanism::BrainpoolP384R1Prehashed, RsaOrEcc::Ecc)
                }
                DecryptionAlgorithm::EcDhBrainpoolP512R1 => {
                    (Mechanism::BrainpoolP512R1Prehashed, RsaOrEcc::Ecc)
                }
                DecryptionAlgorithm::EcDhSecp256k1 => {
                    (Mechanism::Secp256k1Prehashed, RsaOrEcc::Ecc)
                }
                DecryptionAlgorithm::Rsa2048 => (Mechanism::Rsa2048Pkcs1v15, RsaOrEcc::Rsa),
                DecryptionAlgorithm::Rsa3072 => (Mechanism::Rsa3072Pkcs1v15, RsaOrEcc::Rsa),
                DecryptionAlgorithm::Rsa4096 => (Mechanism::Rsa4096Pkcs1v15, RsaOrEcc::Rsa),
            },
        ),
    };

    match (mechanism, ctx.data.len()) {
        (Mechanism::P256Prehashed, 32)
        | (Mechanism::P384Prehashed, 48)
        | (Mechanism::P521Prehashed, 64) => {}
        (Mechanism::P256Prehashed, _)
        | (Mechanism::P384Prehashed, _)
        | (Mechanism::P521Prehashed, _) => {
            warn!(
                "Attempt to sign with invalind data length: {:?} {}",
                mechanism,
                ctx.data.len()
            );
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        _ => {}
    }

    Ok((
        ctx.state
            .key_id(ctx.backend.client_mut(), key_type, ctx.options.storage)?,
        mechanism,
        ctx.state.persistent.uif(key_type).is_enabled(),
        key_kind,
    ))
}

// § 7.2.13
pub fn internal_authenticate<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    if !ctx.state.volatile.other_verified() {
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

fn decipher_key_mecha_uif<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(KeyId, Mechanism, bool, RsaOrEcc), Status> {
    let (key_type, (mechanism, key_kind)) = match ctx.state.volatile.keyrefs.pso_decipher {
        KeyRef::Dec => (
            KeyType::Dec,
            match ctx.state.persistent.dec_alg() {
                DecryptionAlgorithm::X255 => (Mechanism::X255, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhP256 => (Mechanism::P256, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhP384 => (Mechanism::P384, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhP521 => (Mechanism::P521, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhBrainpoolP256R1 => {
                    (Mechanism::BrainpoolP256R1, RsaOrEcc::Ecc)
                }
                DecryptionAlgorithm::EcDhBrainpoolP384R1 => {
                    (Mechanism::BrainpoolP384R1, RsaOrEcc::Ecc)
                }
                DecryptionAlgorithm::EcDhBrainpoolP512R1 => {
                    (Mechanism::BrainpoolP512R1, RsaOrEcc::Ecc)
                }
                DecryptionAlgorithm::EcDhSecp256k1 => (Mechanism::Secp256k1, RsaOrEcc::Ecc),
                DecryptionAlgorithm::Rsa2048 => (Mechanism::Rsa2048Pkcs1v15, RsaOrEcc::Rsa),
                DecryptionAlgorithm::Rsa3072 => (Mechanism::Rsa3072Pkcs1v15, RsaOrEcc::Rsa),
                DecryptionAlgorithm::Rsa4096 => (Mechanism::Rsa4096Pkcs1v15, RsaOrEcc::Rsa),
            },
        ),
        KeyRef::Aut => (
            KeyType::Aut,
            match ctx.state.persistent.aut_alg() {
                AuthenticationAlgorithm::EcDsaP256 => (Mechanism::P256, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::EcDsaP384 => (Mechanism::P384, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::EcDsaP521 => (Mechanism::P521, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::EcDsaBrainpoolP256R1 => {
                    (Mechanism::BrainpoolP256R1, RsaOrEcc::Ecc)
                }
                AuthenticationAlgorithm::EcDsaBrainpoolP384R1 => {
                    (Mechanism::BrainpoolP384R1, RsaOrEcc::Ecc)
                }
                AuthenticationAlgorithm::EcDsaBrainpoolP512R1 => {
                    (Mechanism::BrainpoolP512R1, RsaOrEcc::Ecc)
                }
                AuthenticationAlgorithm::EcDsaSecp256k1 => (Mechanism::Secp256k1, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::Ed255 => {
                    warn!("Attempt to decipher with Ed255 key");
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }

                AuthenticationAlgorithm::Rsa2048 => (Mechanism::Rsa2048Pkcs1v15, RsaOrEcc::Rsa),
                AuthenticationAlgorithm::Rsa3072 => (Mechanism::Rsa3072Pkcs1v15, RsaOrEcc::Rsa),
                AuthenticationAlgorithm::Rsa4096 => (Mechanism::Rsa4096Pkcs1v15, RsaOrEcc::Rsa),
            },
        ),
    };

    Ok((
        ctx.state
            .key_id(ctx.backend.client_mut(), key_type, ctx.options.storage)?,
        mechanism,
        ctx.state.persistent.uif(key_type).is_enabled(),
        key_kind,
    ))
}

// § 7.2.11
pub fn decipher<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    if !ctx.state.volatile.other_verified() {
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

fn decrypt_rsa<const R: usize, T: crate::card::Client>(
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

fn decrypt_ec<const R: usize, T: crate::card::Client>(
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

fn decipher_aes<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx
        .state
        .volatile
        .aes_key_id(ctx.backend.client_mut(), ctx.options.storage)
        .map_err(|_err| {
            warn!("Failed to load aes key: {:?}", _err);
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

pub fn encipher<const R: usize, T: crate::card::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx
        .state
        .volatile
        .aes_key_id(ctx.backend.client_mut(), ctx.options.storage)
        .map_err(|_err| {
            warn!("Failed to load aes key: {:?}", _err);
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
