// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(any(feature = "vpicc", feature = "dangerous-test-real-card"))]

mod card;
mod virt;

use card::{sequoia_test, KeyAlgo};

use test_log::test;

#[cfg(all(feature = "vpicc", not(feature = "dangerous-test-real-card")))]
#[test]
fn rsa2048_sequoia() {
    virt::with_vsc(|| sequoia_test(KeyAlgo::Rsa2048));
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn rsa2048_sequoia_hardware() {
    sequoia_test(KeyAlgo::Rsa2048);
}
