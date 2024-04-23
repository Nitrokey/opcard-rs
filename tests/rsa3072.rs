// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(all(feature = "vpicc", feature = "rsa3072-gen"))]

mod gpg;
mod virt;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn rsa3072_gpg() {
    virt::with_vsc(|| gpg::gpg_test(gpg::KeyAlgo::Rsa3072));
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn rsa3072_gpg_hardware() {
    gpg::gpg_test(gpg::KeyAlgo::Rsa3072);
}
