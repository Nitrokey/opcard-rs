// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "vpicc")]

mod gpg;
mod virt;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn cv25519_gpg() {
    virt::with_vsc(|| gpg::gpg_test(gpg::KeyAlgo::Cv25519));
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn cv25519_gpg_hardware() {
    gpg::gpg_test(gpg::KeyAlgo::Cv25519);
}
