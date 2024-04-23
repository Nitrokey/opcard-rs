// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "vpicc")]

mod virt;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn gpg_p521() {
    virt::with_vsc(|| virt::gpg_test(virt::KeyAlgo::P521));
}

// #[cfg(feature = "dangerous-test-real-card")]
// #[test]
// fn gpg_p521_hardware() {
//     virt::gpg_test(virt::KeyAlgo::P521);
// }
