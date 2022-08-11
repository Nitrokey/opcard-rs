// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(feature = "virtual")]
mod virt;

use std::iter;

use test_log::test;

fn attr_ec_ask() -> impl Iterator<Item = &'static str> {
    iter::repeat(
        [
            r"\[GNUPG:\] GET_LINE cardedit.genkeys.algo",
            r"\[GNUPG:\] GET_LINE keygen.curve",
        ]
        .into_iter()
        .chain(virt::gpg_inquire_pin()),
    )
    .take(3)
    .flatten()
}

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
        "key-attr",
        "2",
        "3",
        "2",
        "3",
        "12345678",
        "2",
        "3",
        "12345678",
        "generate",
        "n",
        "12345678",
        "123456",
        "0",
        "test name2",
        "test2@email.com",
        "no comment2",
        "quit",
    ],
    [r"\[GNUPG:\] CARDCTRL \d D2760001240103040000000000000000"]
        .into_iter()
        .chain(virt::gpg_status())
        .chain([
            r"\[GNUPG:\] GET_LINE cardedit.prompt",
            r"\[GNUPG:\] GET_LINE cardedit.prompt",
        ])
        .chain(attr_ec_ask())
        .chain([
            r"\[GNUPG:\] GET_LINE cardedit.prompt",
            r"\[GNUPG:\] GET_LINE cardedit.genkeys.backup_enc",
        ])
        .chain(virt::gpg_inquire_pin())
        .chain(virt::gpg_inquire_pin())
        .chain([
            r"\[GNUPG:\] GET_LINE keygen.valid",
            r"\[GNUPG:\] GET_LINE keygen.name",
            r"\[GNUPG:\] GET_LINE keygen.email",
            r"\[GNUPG:\] GET_LINE keygen.comment",
            r"\[GNUPG:\] USERID_HINT [0-9A-F]{16} \[\?\]",
            r"\[GNUPG:\] NEED_PASSPHRASE [0-9A-F]{16} [0-9A-F]{16} \d\d \d",
        ])
        .chain(virt::gpg_inquire_pin())
        .chain([
            r"pub:u:\d*:22:[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESCA:::D2760001240103040000000000000000::ed25519:::0:",
            r"fpr:::::::::[0-9A-F]{40}:",
            r"grp:::::::::ECE6906D9B68B2D4C9880B8149011535B628DF91:",
            r"uid:u::::\d{10}::[0-9A-F]{40}::test name \(no comment\) <test@email.com>::::::::::0:",
            r"sub:u:\d*:22:[0-9A-F]{16}:[0-9A-F]{10}::::::a:::D2760001240103040000000000000000::ed25519::",
            r"fpr:::::::::[0-9A-F]{40}:",
            r"grp:::::::::F1153D038DBC7E69214304ED535791539E81F4FC:",
            r"sub:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}::::::e:::D2760001240103040000000000000000::cv25519::",
            r"fpr:::::::::[0-9A-F]{40}:",
            r"grp:::::::::7D448D69BEE476BF0CF79832D29F692E49113AEC:",
            r"\[GNUPG:\] KEY_CREATED B [0-9A-F]{40}",
            r"\[GNUPG:\] GET_LINE cardedit.prompt",
        ])
        .chain([
            r"\[GNUPG:\] GET_LINE cardedit.genkeys.algo",
            r"\[GNUPG:\] GET_LINE keygen.curve",
            r"\[GNUPG:\] GET_LINE cardedit.genkeys.algo",
            r"\[GNUPG:\] GET_LINE keygen.curve",
        ])
        .chain(virt::gpg_inquire_pin())
        .chain([
            r"\[GNUPG:\] GET_LINE cardedit.genkeys.algo",
            r"\[GNUPG:\] GET_LINE keygen.curve",
        ])
        .chain(virt::gpg_inquire_pin())
        .chain([
            r"\[GNUPG:\] GET_LINE cardedit.prompt",
            r"\[GNUPG:\] GET_LINE cardedit.genkeys.backup_enc",
        ])
        .chain(virt::gpg_inquire_pin())
        .chain(virt::gpg_inquire_pin())

        .chain([
            r"\[GNUPG:\] GET_LINE keygen.valid",
            r"\[GNUPG:\] GET_LINE keygen.name",
            r"\[GNUPG:\] GET_LINE keygen.email",
            r"\[GNUPG:\] GET_LINE keygen.comment",
        ])
        .chain([
            r"pub:-:\d*:19:[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESCA:::D2760001240103040000000000000000::nistp256:::0:",
            r"fpr:::::::::[0-9A-F]{40}:",
            r"grp:::::::::D4D22042ED6492B2B97993800D090F2642E89F1B:",
            r"uid:-::::\d{10}::[0-9A-F]{40}::test name2 \(no comment2\) <test2@email.com>::::::::::0:",
            r"sub:-:\d*:19:[0-9A-F]{16}:[0-9A-F]{10}::::::a:::D2760001240103040000000000000000::nistp256::",
            r"fpr:::::::::[0-9A-F]{40}:",
            r"grp:::::::::8EA186B6028CA01F8486B97AE2EBB631679F8125:",
            r"sub:-:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}::::::e:::D2760001240103040000000000000000::nistp256::",
            r"fpr:::::::::[0-9A-F]{40}:",
            r"grp:::::::::1FD4F6A5E7DFF4534FAF2E7EBADBAA11F96945DB:",
            r"\[GNUPG:\] KEY_CREATED B [0-9A-F]{40}",
            r"\[GNUPG:\] GET_LINE cardedit.prompt",
        ]),
        [
            r"gpg: revocation certificate stored as '.*\.rev'",
            r"gpg: checking the trustdb",
            r"gpg: marginals needed: \d  completes needed: \d  trust model: pgp",
            r"gpg: depth:[ 0-9]*valid:[ 0-9]*signed:[ 0-9]*trust: \d*-, \d*q, \d*n, \d*m, \d*f, \d*u",
            r"gpg: revocation certificate stored as '.*\.rev'",
        ],
    );
}
