// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "dangerous-test-real-card")]

mod gpg;
mod virt;

use test_log::test;

#[test]
fn p384_import_gpg_hardware() {
    gpg::gpg_test_import(gpg::KeyAlgo::BrainpoolP384R1);
}
