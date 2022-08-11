// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;

use trussed::try_syscall;
use trussed::types::*;

use crate::card::LoadedContext;
use crate::types::*;

// § 7.2.10
pub fn sign<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let key_id = ctx.state.internal.key_id(KeyType::Sign).ok_or_else(|| {
        warn!("Attempt to sign without a key set");
        Status::KeyReferenceNotFound
    })?;
    if !ctx.state.runtime.sign_verified {
        warn!("Attempt to sign without PW1 verified");
        return Err(Status::SecurityStatusNotSatisfied);
    }

    if !ctx.state.internal.pw1_valid_multiple() {
        ctx.state.runtime.sign_verified = false;
    }
    if ctx.state.internal.uif(KeyType::Sign).is_enabled()
        && !ctx
            .backend
            .confirm_user_present()
            .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?
    {
        warn!("User presence confirmation timed out");
        ctx.state.runtime.sign_verified = true;
        // FIXME SecurityRelatedIssues (0x6600 is not available?)
        return Err(Status::SecurityStatusNotSatisfied);
    }

    match ctx.state.internal.sign_alg() {
        SignatureAlgorithm::Ed255 => sign_ec(ctx, key_id, Mechanism::Ed255),
        SignatureAlgorithm::EcDsaP256 => {
            if ctx.data.len() != 32 {
                return Err(Status::ConditionsOfUseNotSatisfied);
            }
            sign_ec(ctx, key_id, Mechanism::P256Prehashed)
        }
        _ => {
            error!("Unimplemented operation");
            Err(Status::ConditionsOfUseNotSatisfied)
        }
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
