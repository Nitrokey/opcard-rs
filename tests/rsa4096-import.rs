// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(all(feature = "vpicc", feature = "rsa4096"))]

mod gpg;
mod virt;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn gpg_rsa4096_import() {
    virt::with_vsc(|| gpg::gpg_test_import(gpg::KeyAlgo::Rsa4096));
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn gpg_rsa4096_import_hardware() {
    gpg::gpg_test_import(gpg::KeyAlgo::Rsa4096);
}
