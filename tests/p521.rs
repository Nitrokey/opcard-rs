// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "vpicc")]

mod gpg;
mod virt;

use test_log::test;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn p521_gpg() {
    virt::with_vsc(|| gpg::gpg_test(gpg::KeyAlgo::P521));
}

// #[cfg(feature = "dangerous-test-real-card")]
// #[test]
// fn p521_gpg_hardware() {
//     gpg::gpg_test(gpg::KeyAlgo::P521);
// }
