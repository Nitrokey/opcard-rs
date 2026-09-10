// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

mod card;
mod gpg;

use test_log::test;

#[test]
fn secp256k1_gpg_hardware() {
    if !card::dangerous_real_card_enabled() {
        return;
    }

    gpg::gpg_test(gpg::KeyAlgo::Secp256k1);
}
