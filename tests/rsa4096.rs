// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(all(feature = "vpicc", feature = "rsa4096-gen"))]

mod virt;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn gpg_rsa4096() {
    virt::with_vsc(|| virt::gpg_test(virt::KeyAlgo::Rsa4096));
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn gpg_rsa4096_hardware() {
    virt::gpg_test(virt::KeyAlgo::Rsa4096);
}
