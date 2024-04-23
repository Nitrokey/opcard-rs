// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "vpicc")]

mod gpg;
mod virt;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn gpg_p521() {
    virt::with_vsc(|| gpg::gpg_test(gpg::KeyAlgo::P521));
}

// #[cfg(feature = "dangerous-test-real-card")]
// #[test]
// fn gpg_p521_hardware() {
//     gpg::gpg_test(gpg::KeyAlgo::P521);
// }
