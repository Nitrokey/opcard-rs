// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;

use crate::card::LoadedContext;
use crate::types::*;

pub fn sign<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    todo!()
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
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    todo!()
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
