// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

mod card;
mod gpg;
mod virt;

use test_log::test;

#[test]
fn cv25519_import_gpg() {
    if card::dangerous_real_card_enabled() {
        virt::with_vsc(|| gpg::gpg_test_import(gpg::KeyAlgo::Cv25519));
    } else {
        gpg::gpg_test_import(gpg::KeyAlgo::Cv25519);
    }
}
