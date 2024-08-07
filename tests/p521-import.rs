// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(any(feature = "vpicc", feature = "dangerous-test-real-card"))]

mod gpg;
mod virt;

use test_log::test;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn p521_import_gpg() {
    virt::with_vsc(|| gpg::gpg_test_import(gpg::KeyAlgo::P521));
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn p521_import_gpg_hardware() {
    gpg::gpg_test_import(gpg::KeyAlgo::P521);
}
