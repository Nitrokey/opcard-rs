// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(feature = "virtual")]
mod virt;

use test_log::test;

#[test]
fn gpg_gen_key() {
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
            "123456",
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
                r"\[GNUPG:\] USERID_HINT [0-9A-Z]{16} \[\?\]",
                r"\[GNUPG:\] NEED_PASSPHRASE [0-9A-Z]{16} [0-9A-Z]{16} \d\d \d",
            ])
            .chain(virt::gpg_inquire_pin())
            .chain([
                r"pub:u:255:22:[0-9A-Z]{16}:[0-9A-Z]{10}:::u:::scESCA:::D2760001240103040000000000000000::ed25519:::0:",
                r"fpr:::::::::[0-9A-Z]{40}:",
                r"grp:::::::::ECE6906D9B68B2D4C9880B8149011535B628DF91:",
                r"uid:u::::\d{10}::[0-9A-Z]{40}::test name \(no comment\) <test@email.com>::::::::::0:",
                r"sub:u:255:22:[0-9A-Z]{16}:[0-9A-Z]{10}::::::a:::D2760001240103040000000000000000::ed25519::",
                r"fpr:::::::::[0-9A-Z]{40}:",
                r"grp:::::::::F1153D038DBC7E69214304ED535791539E81F4FC:",
                r"sub:u:255:18:[0-9A-Z]{16}:[0-9A-Z]{10}::::::e:::D2760001240103040000000000000000::cv25519::",
                r"fpr:::::::::[0-9A-Z]{40}:",
                r"grp:::::::::7D448D69BEE476BF0CF79832D29F692E49113AEC:",
                r"\[GNUPG:\] KEY_CREATED B [0-9A-Z]{40}",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GOT_IT",
            ]),
        [
                r"gpg: revocation certificate stored as '.*\.rev'",
                r"gpg: checking the trustdb",
                r"gpg: marginals needed: \d  completes needed: \d  trust model: pgp",
                r"gpg: depth:[ 0-9]*valid:[ 0-9]*signed:[ 0-9]*trust: \d*-, \d*q, \d*n, \d*m, \d*f, \d*u"
        ],
    );
}
