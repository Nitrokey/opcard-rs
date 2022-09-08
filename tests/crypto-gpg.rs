// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(feature = "virtual")]
mod virt;

use std::iter;
use std::sync::Mutex;

use rand::Rng;
use test_log::test;

use virt::gnupg_test;
use virt::GpgCommand::*;

static SERIAL_TEST: Mutex<()> = Mutex::new(());

fn attr_ec_ask() -> Vec<&'static str> {
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
    .collect()
}

const DEFAULT_PW3: &str = "12345678";
const DEFAULT_PW1: &str = "123456";

struct FileDropper<'s> {
    temp_file_name: &'s str,
}
impl<'s> Drop for FileDropper<'s> {
    fn drop(&mut self) {
        std::fs::remove_file(self.temp_file_name).ok();
    }
}

#[test]
fn gpg_255() {
    #[allow(unused_must_use)]
    let _lock = SERIAL_TEST.lock();
    let file_number: u32 = rand::rngs::OsRng.gen();
    let tmp = format!("/tmp/opcard-tests.{file_number}");
    let encrypted_file = &tmp;
    let tmp = format!("/tmp/opcard-tests.{file_number}.dec");
    let decrypted_file = &tmp;
    let _dropper = FileDropper {
        temp_file_name: encrypted_file,
    };
    let _dropper = FileDropper {
        temp_file_name: decrypted_file,
    };

    let tmp = format!("test name{file_number}");
    let temp_name = &tmp;

    let tmp = format!("test{file_number}@email.com");
    let temp_email = &tmp;

    let custom_match = format!(
        r"uid:u::::\d{{10}}::[0-9A-F]{{40}}::{temp_name} \(no comment\) <{temp_email}>::::::::::0:"
    );

    let first_line = r"\[GNUPG:\] CARDCTRL \d D2760001240103040000000000000000".to_string();
    let first_ref: &str = &first_line;

    gnupg_test(
        &[
            "admin",
            "key-attr",
            "2",
            "1",
            DEFAULT_PW3,
            "2",
            "1",
            DEFAULT_PW3,
            "2",
            "1",
            DEFAULT_PW3,
            "generate",
            "n",
            DEFAULT_PW3,
            DEFAULT_PW1,
            "0",
            temp_name,
            temp_email,
            "no comment",
            DEFAULT_PW1,
            "quit",
        ],
        &[
            vec![first_ref],
            virt::gpg_status(),
            vec![
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
            ],
            attr_ec_ask(),
            vec![
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.backup_enc",
            ],
            virt::gpg_inquire_pin(),
            virt::gpg_inquire_pin(),
            vec![
                r"\[GNUPG:\] GET_LINE keygen.valid",
                r"\[GNUPG:\] GET_LINE keygen.name",
                r"\[GNUPG:\] GET_LINE keygen.email",
                r"\[GNUPG:\] GET_LINE keygen.comment",
                r"\[GNUPG:\] USERID_HINT [0-9A-F]{16} \[\?\]",
                r"\[GNUPG:\] NEED_PASSPHRASE [0-9A-F]{16} [0-9A-F]{16} \d\d \d",
            ],
            virt::gpg_inquire_pin(),
            vec![
                r"pub:u:\d*:22:[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESCA:::D2760001240103040000000000000000::ed25519:::0:",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                &custom_match,
                r"sub:u:\d*:22:[0-9A-F]{16}:[0-9A-F]{10}::::::a:::D2760001240103040000000000000000::ed25519::",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                r"sub:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}::::::e:::D2760001240103040000000000000000::cv25519::",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                r"\[GNUPG:\] KEY_CREATED B [0-9A-F]{40}",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
            ],
        ].into_iter().flatten().collect::<Vec<&str>>(),
        &[
            r"gpg: revocation certificate stored as '.*\.rev'",
            r"gpg: checking the trustdb",
            r"gpg: marginals needed: \d  completes needed: \d  trust model: pgp",
            r"gpg: depth:[ 0-9]*valid:[ 0-9]*signed:[ 0-9]*trust: \d*-, \d*q, \d*n, \d*m, \d*f, \d*u",
        ],
        EditCard,
    );

    println!("================ FINISHED GENERATING 25519 KEYS ================");

    gnupg_test(
        &[],
        &[
            r"\[GNUPG:\] BEGIN_ENCRYPTION \d \d",
            r"\[GNUPG:\] END_ENCRYPTION",
        ],
        &[
            //r"gpg: checking the trustdb",
            //r"gpg: marginals needed: \d  completes needed: \d  trust model: pgp",
            //r"gpg: depth:[ 0-9]*valid:[ 0-9]*signed:[ 0-9]*trust: \d*-, \d*q, \d*n, \d*m, \d*f, \d*u",
        ],
        Encrypt {
            i: "Cargo.toml",
            o: encrypted_file,
            r: temp_email,
        },
    );

    println!("================ FINISHED ENCRYPTION ================");

    gnupg_test(
        &[DEFAULT_PW1],
        &[
            r"\[GNUPG:\] ENC_TO [a-fA-F0-9]{16} \d* \d*",
            r"\[GNUPG:\] END_ENCRYPTION",
        ],
        &[r"gpg: encrypted with 256-bit ECDH key, ID [a-fA-F0-9]{16}, created \d{4}-\d\d-\d\d"],
        Decrypt {
            i: encrypted_file,
            o: decrypted_file,
        },
    );
}
#[test]
fn gpg_p256() {
    #[allow(unused_must_use)]
    let _lock = SERIAL_TEST.lock();
    let file_number: u32 = rand::rngs::OsRng.gen();
    let tmp = format!("/tmp/opcard-tests.{file_number}");
    let encrypted_file = &tmp;
    let tmp = format!("/tmp/opcard-tests.{file_number}.dec");
    let decrypted_file = &tmp;
    let _dropper = FileDropper {
        temp_file_name: encrypted_file,
    };
    let _dropper = FileDropper {
        temp_file_name: decrypted_file,
    };

    let tmp = format!("test name{file_number}");
    let temp_name = &tmp;

    let tmp = format!("test{file_number}@email.com");
    let temp_email = &tmp;

    let custom_match = format!(
        r"uid:u::::\d{{10}}::[0-9A-F]{{40}}::{temp_name} \(no comment\) <{temp_email}>::::::::::0:"
    );

    let first_line = r"\[GNUPG:\] CARDCTRL \d D2760001240103040000000000000000".to_string();
    let first_ref: &str = &first_line;

    gnupg_test(
        &[
            "admin",
            "key-attr",
            "2",
            "3",
            DEFAULT_PW3,
            "2",
            "3",
            DEFAULT_PW3,
            "2",
            "3",
            DEFAULT_PW3,
            "generate",
            "n",
            DEFAULT_PW3,
            DEFAULT_PW1,
            "0",
            temp_name,
            temp_email,
            "no comment",
            DEFAULT_PW1,
            "quit",
        ],
        &[
            vec![first_ref],
            virt::gpg_status(),
            vec![
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
            ],
            attr_ec_ask(),
            vec![
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.backup_enc",
            ],
            virt::gpg_inquire_pin(),
            virt::gpg_inquire_pin(),
            vec![
                r"\[GNUPG:\] GET_LINE keygen.valid",
                r"\[GNUPG:\] GET_LINE keygen.name",
                r"\[GNUPG:\] GET_LINE keygen.email",
                r"\[GNUPG:\] GET_LINE keygen.comment",
                r"\[GNUPG:\] USERID_HINT [0-9A-F]{16} \[\?\]",
                r"\[GNUPG:\] NEED_PASSPHRASE [0-9A-F]{16} [0-9A-F]{16} \d\d \d",
            ],
            virt::gpg_inquire_pin(),
            vec![
                r"pub:u:\d*:19:[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESCA:::D2760001240103040000000000000000::nistp256:::0:",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                &custom_match,
                r"sub:u:\d*:19:[0-9A-F]{16}:[0-9A-F]{10}::::::a:::D2760001240103040000000000000000::nistp256::",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                r"sub:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}::::::e:::D2760001240103040000000000000000::nistp256::",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                r"\[GNUPG:\] KEY_CREATED B [0-9A-F]{40}",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
            ],
        ].into_iter().flatten().collect::<Vec<&str>>(),
        &[
            r"gpg: revocation certificate stored as '.*\.rev'",
            r"gpg: checking the trustdb",
            r"gpg: marginals needed: \d  completes needed: \d  trust model: pgp",
            r"gpg: depth:[ 0-9]*valid:[ 0-9]*signed:[ 0-9]*trust: \d*-, \d*q, \d*n, \d*m, \d*f, \d*u",
        ],
        EditCard,
    );

    println!("================ FINISHED GENERATING P256 KEYS ================");

    gnupg_test(
        &[],
        &[
            r"\[GNUPG:\] BEGIN_ENCRYPTION \d \d",
            r"\[GNUPG:\] END_ENCRYPTION",
        ],
        &[
            //r"gpg: checking the trustdb",
            //r"gpg: marginals needed: \d  completes needed: \d  trust model: pgp",
            //r"gpg: depth:[ 0-9]*valid:[ 0-9]*signed:[ 0-9]*trust: \d*-, \d*q, \d*n, \d*m, \d*f, \d*u",
        ],
        Encrypt {
            i: "Cargo.toml",
            o: encrypted_file,
            r: temp_email,
        },
    );

    println!("================ FINISHED ENCRYPTION ================");

    gnupg_test(
        &[DEFAULT_PW1],
        &[
            r"\[GNUPG:\] ENC_TO [a-fA-F0-9]{16} \d* \d*",
            r"\[GNUPG:\] END_ENCRYPTION",
        ],
        &[r"gpg: encrypted with 256-bit ECDH key, ID [a-fA-F0-9]{16}, created \d{4}-\d\d-\d\d"],
        Decrypt {
            i: encrypted_file,
            o: decrypted_file,
        },
    );
}
