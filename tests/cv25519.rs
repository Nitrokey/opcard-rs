// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "vpicc")]

mod virt;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn gpg_cv25519() {
    virt::with_vsc(|| virt::gpg_test(virt::KeyAlgo::Cv25519));
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn gpg_cv25519_hardware() {
    virt::gpg_test(virt::KeyAlgo::Cv25519);
}
