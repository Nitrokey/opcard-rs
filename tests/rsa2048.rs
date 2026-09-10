// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
mod card;
mod gpg;
mod virt;

use test_log::test;

use crate::card::dangerous_real_card_enabled;

#[test]
fn rsa2048_gpg() {
    if dangerous_real_card_enabled() {
        gpg::gpg_test(gpg::KeyAlgo::Rsa2048);
    } else {
        virt::with_vsc(|| gpg::gpg_test(gpg::KeyAlgo::Rsa2048));
    }
}
