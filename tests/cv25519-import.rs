// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "vpicc")]

mod gpg;
mod virt;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn gpg_cv25519_import() {
    virt::with_vsc(|| gpg::gpg_test_import(gpg::KeyAlgo::Cv25519));
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn gpg_cv25519_import_hardware() {
    gpg::gpg_test_import(gpg::KeyAlgo::Cv25519);
}
