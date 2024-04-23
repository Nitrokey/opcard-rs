// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(all(feature = "vpicc", feature = "rsa3072-gen"))]

mod virt;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn gpg_rsa3072() {
    virt::with_vsc(|| virt::gpg_test(virt::KeyAlgo::Rsa3072));
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn gpg_rsa3072_hardware() {
    virt::gpg_test(virt::KeyAlgo::Rsa3072);
}
