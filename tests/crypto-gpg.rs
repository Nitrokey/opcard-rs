// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(feature = "virtual")]
mod virt;

#[test]
fn gen_key() {
    virt::gnupg_test(
        &[
            "admin",
            "key-attr",
            "2",
            "1",
            "12345678",
            "2",
            "1",
            "12345678",
            "2",
            "1",
            "12345678",
            "generate",
            "n",
            "12345678",
            "123456",
            "0",
            "test name",
            "test@email.com",
            "no comment",
            "quit",
        ],
        [r"\[GNUPG:\] CARDCTRL \d D2760001240103040000000000000000"]
            .into_iter()
            .chain(virt::gpg_status())
            .chain([
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GOT_IT",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GOT_IT",
            ])
            .chain([
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.algo",
                r"\[GNUPG:\] GOT_IT",
                r"\[GNUPG:\] GET_LINE keygen.curve",
                r"\[GNUPG:\] GOT_IT",
            ])
            .chain(virt::gpg_inquire_pin())
            .chain([
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.algo",
                r"\[GNUPG:\] GOT_IT",
                r"\[GNUPG:\] GET_LINE keygen.curve",
                r"\[GNUPG:\] GOT_IT",
            ])
            .chain(virt::gpg_inquire_pin())
            .chain([
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.algo",
                r"\[GNUPG:\] GOT_IT",
                r"\[GNUPG:\] GET_LINE keygen.curve",
                r"\[GNUPG:\] GOT_IT",
            ])
            .chain(virt::gpg_inquire_pin())
            .chain([
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GOT_IT",
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.backup_enc",
                r"\[GNUPG:\] GOT_IT",
            ])
            .chain(virt::gpg_inquire_pin())
            .chain(virt::gpg_inquire_pin())
            .chain([
                r"\[GNUPG:\] GET_LINE keygen.valid",
                r"\[GNUPG:\] GOT_IT",
                r"\[GNUPG:\] GET_LINE keygen.name",
                r"\[GNUPG:\] GOT_IT",
                r"\[GNUPG:\] GET_LINE keygen.email",
                r"\[GNUPG:\] GOT_IT",
                r"\[GNUPG:\] GET_LINE keygen.comment",
                r"\[GNUPG:\] GOT_IT",
            ]),
        [],
    );
}
