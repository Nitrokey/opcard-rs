// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

mod card;
mod gpg;
mod virt;

use test_log::test;

#[test]
fn p384_import_gpg() {
    if card::dangerous_real_card_enabled() {
        gpg::gpg_test_import(gpg::KeyAlgo::P384);
    } else {
        virt::with_vsc(|| gpg::gpg_test_import(gpg::KeyAlgo::P384));
    }
}
