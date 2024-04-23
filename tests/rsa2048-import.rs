// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(all(feature = "vpicc", feature = "rsa2048"))]

mod virt;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn gpg_rsa2048_import() {
    virt::with_vsc(|| virt::gpg_test_import(virt::KeyAlgo::Rsa2048));
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn gpg_rsa2048_import_hardware() {
    virt::gpg_test_import(virt::KeyAlgo::Rsa2048);
}
