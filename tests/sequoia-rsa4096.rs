// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

mod card;
mod virt;

use card::{sequoia_test, KeyAlgo};

use test_log::test;

#[test]
fn rsa4096_sequoia() {
    if card::dangerous_real_card_enabled() {
        sequoia_test(KeyAlgo::Rsa4096);
    } else {
        virt::with_vsc(|| sequoia_test(KeyAlgo::Rsa4096));
    }
}
