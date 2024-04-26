// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(all(feature = "vpicc", feature = "rsa3072"))]

mod gpg;
mod virt;

use test_log::test;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn rsa3072_import_gpg() {
    virt::with_vsc(|| gpg::gpg_test_import(gpg::KeyAlgo::Rsa3072));
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn rsa3072_import_gpg_hardware() {
    gpg::gpg_test_import(gpg::KeyAlgo::Rsa3072);
}
