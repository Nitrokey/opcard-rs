// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "dangerous-test-real-card")]

mod gpg;

use test_log::test;

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn p384_gpg_hardware() {
    gpg::gpg_test(gpg::KeyAlgo::BrainpoolP384R1);
}
