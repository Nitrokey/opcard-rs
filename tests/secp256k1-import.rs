// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "dangerous-test-real-card")]

mod gpg;

use test_log::test;

#[test]
fn secp256k1_import_gpg_hardware() {
    gpg::gpg_test_import(gpg::KeyAlgo::Secp256k1);
}
