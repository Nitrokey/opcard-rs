// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "vpicc")]

mod gpg;
mod virt;

#[cfg(not(feature = "dangerous-test-real-card"))]
#[test]
fn gpg_p256() {
    virt::with_vsc(|| gpg::gpg_test(gpg::KeyAlgo::P256));
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn gpg_p256_hardware() {
    gpg::gpg_test(gpg::KeyAlgo::P256);
}
