// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

mod card;
mod virt;

use card::{rpgp_test, KeyAlgo};

use test_log::test;

#[test]
fn rsa2048_rpgp() {
    if card::dangerous_real_card_enabled() {
        rpgp_test(KeyAlgo::Rsa2048);
    } else {
        virt::with_vsc(|| rpgp_test(KeyAlgo::Rsa2048));
    }
}
