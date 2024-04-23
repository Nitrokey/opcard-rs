// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "vpicc")]

mod virt;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn gpg_p384_import() {
    virt::with_vsc(|| virt::gpg_test_import(virt::KeyAlgo::P384));
}

// #[cfg(feature = "dangerous-test-real-card")]
// #[test]
// fn gpg_p384_import_hardware() {
//     virt::gpg_test_import(virt::KeyAlgo::P384);
// }
