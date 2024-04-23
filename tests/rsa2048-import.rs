// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(all(feature = "vpicc", feature = "rsa2048"))]

mod gpg;
mod virt;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn rsa2048_import_gpg() {
    virt::with_vsc(|| gpg::gpg_test_import(gpg::KeyAlgo::Rsa2048));
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn rsa2048_import_gpg_hardware() {
    gpg::gpg_test_import(gpg::KeyAlgo::Rsa2048);
}
