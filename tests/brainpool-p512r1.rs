// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "dangerous-test-real-card")]

mod gpg;

use test_log::test;

#[test]
fn p521_gpg_hardware() {
    gpg::gpg_test(gpg::KeyAlgo::BrainpoolP512R1);
}
