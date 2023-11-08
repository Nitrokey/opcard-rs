// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(any(feature = "vpicc", feature = "dangerous-test-real-card"))]

mod virt;

use std::iter;

use rand::Rng;
use test_log::test;

use virt::gnupg_test;
use virt::GpgCommand::*;

#[cfg(feature = "vpicc")]
#[allow(unused)]
use virt::with_vsc;

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

#[cfg(feature = "rsa2048-gen")]
fn attr_rsa_ask() -> Vec<&'static str> {
    iter::repeat(
        [
            r"\[GNUPG:\] GET_LINE cardedit.genkeys.algo",
            r"\[GNUPG:\] GET_LINE cardedit.genkeys.size",
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

fn gpg_255() {
    let file_number: u32 = rand::rngs::OsRng.gen();
    let tmp = format!("/tmp/opcard-tests-{file_number}.gpg");
    let encrypted_file = &tmp;
    let tmp = format!("/tmp/opcard-tests-{file_number}-sig.gpg");
    let sign_file = &tmp;
    let tmp = format!("/tmp/opcard-tests-{file_number}.toml");
    let decrypted_file = &tmp;
    let _dropper = FileDropper {
        temp_file_name: encrypted_file,
    };
    let _dropper = FileDropper {
        temp_file_name: sign_file,
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

    gnupg_test(
        &[],
        &[
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
            virt::gpg_status(virt::KeyType::RsaNone, 0),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        CardStatus,
    );

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
                vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
                virt::gpg_status(virt::KeyType::RsaNone,0),
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
                    r"pub:u:\d*:22:[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESCA:::D276000124010304[A-Z0-9]*::ed25519:::0:",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    &custom_match,
                    r"sub:u:\d*:22:[0-9A-F]{16}:[0-9A-F]{10}::::::a:::D276000124010304[A-Z0-9]*::ed25519::",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    r"sub:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}::::::e:::D276000124010304[A-Z0-9]*::cv25519::",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    r"\[GNUPG:\] KEY_CREATED B [0-9A-F]{40}",
                    r"\[GNUPG:\] GET_LINE cardedit.prompt",
                ]
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
        &[],
        Encrypt {
            i: "Cargo.toml",
            o: encrypted_file,
            r: temp_email,
        },
    );

    println!("================ FINISHED ENCRYPTION ================");

    let custom1 = format!(
        r"\[GNUPG:\] USERID_HINT [a-fA-F0-9]{{16}} {temp_name} \(no comment\) <{temp_email}>"
    );
    let custom2 = format!(r"{temp_name} \(no comment\) <{temp_email}>");
    gnupg_test(
        &[DEFAULT_PW1],
        &[
            vec![
                r"\[GNUPG:\] ENC_TO [a-fA-F0-9]{16} \d* \d*",
                &custom1,
                r"\[GNUPG:\] NEED_PASSPHRASE [a-fA-F0-9]{16} [a-fA-F0-9]{16} 18 0",
            ],
            virt::gpg_inquire_pin(),
            vec![
                r"\[GNUPG:\] DECRYPTION_KEY [a-fA-F0-9]{40} [a-fA-F0-9]{40} u",
                r"\[GNUPG:\] BEGIN_DECRYPTION",
                r"\[GNUPG:\] DECRYPTION_INFO \d \d \d",
                r"\[GNUPG:\] PLAINTEXT \d* \d* Cargo.toml",
                r"\[GNUPG:\] PLAINTEXT_LENGTH \d*",
                r"\[GNUPG:\] DECRYPTION_OKAY",
                r"\[GNUPG:\] GOODMDC",
                r"\[GNUPG:\] END_DECRYPTION",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: encrypted with \d*-bit ECDH key, ID [a-fA-F0-9]{16}, created \d{4}-\d\d-\d\d",
            &custom2,
        ],
        Decrypt {
            i: encrypted_file,
            o: decrypted_file,
        },
    );

    println!("================ FINISHED DECRYPTION ================");

    gnupg_test(
        &[DEFAULT_PW1],
        &[
            vec![
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-Z0-9]*",
                r"\[GNUPG:\] BEGIN_SIGNING H\d*",
                &custom1,
                r"\[GNUPG:\] NEED_PASSPHRASE [a-fA-F0-9]{16} [a-fA-F0-9]{16} 22 0",
            ],
            virt::gpg_inquire_pin(),
            vec![r"\[GNUPG:\] SIG_CREATED S 22 8 00 [a-fA-F0-9]{10} [a-fA-F0-9]{40}"],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[r#"gpg: using "test\d*@email.com" as default secret key for signing"#],
        Sign {
            i: "Cargo.toml",
            o: sign_file,
            s: temp_email,
        },
    );

    println!("================ FINISHED SIGNATURE ================");

    gnupg_test(
        &[],
        &[
            r"\[GNUPG:\] NEWSIG test\d*@email.com",
            r"\[GNUPG:\] SIG_ID [^ ]* \d{4}-\d\d-\d\d [a-fA-F0-9]{10}",
            r"\[GNUPG:\] GOODSIG [a-fA-F0-9]{16} test name\d* \(no comment\) <test\d*@email.com>",
            r"\[GNUPG:\] VALIDSIG [a-fA-F0-9]{40} \d{4}-\d\d-\d\d [a-fA-F0-9]{10} \d \d \d 22 8 00 [a-fA-F0-9]{40}",
            r"\[GNUPG:\] TRUST_ULTIMATE 0 pgp",
        ],
        &[
            r"gpg: Signature made .*",
            r"gpg:                using EDDSA key [a-fA-F0-9]{40}",
            r#"gpg:                issuer "test\d*@email.com""#,
            r#"pg: Good signature from "test name\d* \(no comment\) <test\d*@email.com>"#,
        ],
        Verify { i: sign_file },
    );
    gnupg_test(
        &[
            "admin",
            "factory-reset",
            "y",
            "yes",
            "verify",
            DEFAULT_PW1,
            "quit",
        ],
        &[
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
            virt::gpg_status(virt::KeyType::Cv25519, 5),
            vec![
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_BOOL cardedit.factory-reset.proceed",
                r"\[GNUPG:\] GET_LINE cardedit.factory-reset.really",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
            ],
            virt::gpg_inquire_pin(),
            virt::gpg_status(virt::KeyType::RsaNone, 0),
            vec![r"\[GNUPG:\] GET_LINE cardedit.prompt"],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: OpenPGP card no. [0-9A-F]{32} detected",
            r"gpg: Note: This command destroys all keys stored on the card!",
        ],
        EditCard,
    );
}

fn gpg_p256() {
    let file_number: u32 = rand::rngs::OsRng.gen();
    let tmp = format!("/tmp/opcard-tests-{file_number}.gpg");
    let encrypted_file = &tmp;
    let tmp = format!("/tmp/opcard-tests-{file_number}-sig.gpg");
    let sign_file = &tmp;
    let tmp = format!("/tmp/opcard-tests-{file_number}.toml");
    let decrypted_file = &tmp;
    let _dropper = FileDropper {
        temp_file_name: encrypted_file,
    };
    let _dropper = FileDropper {
        temp_file_name: sign_file,
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

    gnupg_test(
        &[],
        &[
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
            virt::gpg_status(virt::KeyType::RsaNone, 0),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        CardStatus,
    );

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
                vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
                virt::gpg_status(virt::KeyType::RsaNone,0),
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
                    r"pub:u:\d*:19:[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESCA:::D276000124010304[A-Z0-9]*::nistp256:::0:",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    &custom_match,
                    r"sub:u:\d*:19:[0-9A-F]{16}:[0-9A-F]{10}::::::a:::D276000124010304[A-Z0-9]*::nistp256::",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    r"sub:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}::::::e:::D276000124010304[A-Z0-9]*::nistp256::",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    r"\[GNUPG:\] KEY_CREATED B [0-9A-F]{40}",
                    r"\[GNUPG:\] GET_LINE cardedit.prompt",
                ]
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
        &[],
        Encrypt {
            i: "Cargo.toml",
            o: encrypted_file,
            r: temp_email,
        },
    );

    println!("================ FINISHED ENCRYPTION ================");

    let custom1 = format!(
        r"\[GNUPG:\] USERID_HINT [a-fA-F0-9]{{16}} {temp_name} \(no comment\) <{temp_email}>"
    );
    let custom2 = format!(r"{temp_name} \(no comment\) <{temp_email}>");

    gnupg_test(
        &[DEFAULT_PW1],
        &[
            vec![
                r"\[GNUPG:\] ENC_TO [a-fA-F0-9]{16} \d* \d*",
                &custom1,
                r"\[GNUPG:\] NEED_PASSPHRASE [a-fA-F0-9]{16} [a-fA-F0-9]{16} 18 0",
            ],
            virt::gpg_inquire_pin(),
            vec![
                r"\[GNUPG:\] DECRYPTION_KEY [a-fA-F0-9]{40} [a-fA-F0-9]{40} u",
                r"\[GNUPG:\] BEGIN_DECRYPTION",
                r"\[GNUPG:\] DECRYPTION_INFO \d \d \d",
                r"\[GNUPG:\] PLAINTEXT \d* \d* Cargo.toml",
                r"\[GNUPG:\] PLAINTEXT_LENGTH \d*",
                r"\[GNUPG:\] DECRYPTION_OKAY",
                r"\[GNUPG:\] GOODMDC",
                r"\[GNUPG:\] END_DECRYPTION",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: encrypted with \d*-bit ECDH key, ID [a-fA-F0-9]{16}, created \d{4}-\d\d-\d\d",
            &custom2,
        ],
        Decrypt {
            i: encrypted_file,
            o: decrypted_file,
        },
    );

    println!("================ FINISHED DECRYPTION ================");

    gnupg_test(
        &[DEFAULT_PW1],
        &[
            vec![
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-Z0-9]*",
                r"\[GNUPG:\] BEGIN_SIGNING H\d*",
                &custom1,
                r"\[GNUPG:\] NEED_PASSPHRASE [a-fA-F0-9]{16} [a-fA-F0-9]{16} 19 0",
            ],
            virt::gpg_inquire_pin(),
            vec![r"\[GNUPG:\] SIG_CREATED S 19 8 00 [a-fA-F0-9]{10} [a-fA-F0-9]{40}"],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[r#"gpg: using "test\d*@email.com" as default secret key for signing"#],
        Sign {
            i: "Cargo.toml",
            o: sign_file,
            s: temp_email,
        },
    );

    println!("================ FINISHED SIGNATURE ================");

    gnupg_test(
        &[],
        &[
            r"\[GNUPG:\] NEWSIG test\d*@email.com",
            r"\[GNUPG:\] SIG_ID [^ ]* \d{4}-\d\d-\d\d [a-fA-F0-9]{10}",
            r"\[GNUPG:\] GOODSIG [a-fA-F0-9]{16} test name\d* \(no comment\) <test\d*@email.com>",
            r"\[GNUPG:\] VALIDSIG [a-fA-F0-9]{40} \d{4}-\d\d-\d\d [a-fA-F0-9]{10} \d \d \d 19 8 00 [a-fA-F0-9]{40}",
            r"\[GNUPG:\] TRUST_ULTIMATE 0 pgp",
        ],
        &[
            r"gpg: Signature made .*",
            r"gpg:                using ECDSA key [a-fA-F0-9]{40}",
            r#"gpg:                issuer "test\d*@email.com""#,
            r#"pg: Good signature from "test name\d* \(no comment\) <test\d*@email.com>"#,
        ],
        Verify { i: sign_file },
    );

    gnupg_test(
        &[
            "admin",
            "factory-reset",
            "y",
            "yes",
            "verify",
            DEFAULT_PW1,
            "quit",
        ],
        &[
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
            virt::gpg_status(virt::KeyType::P256, 5),
            vec![
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_BOOL cardedit.factory-reset.proceed",
                r"\[GNUPG:\] GET_LINE cardedit.factory-reset.really",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
            ],
            virt::gpg_inquire_pin(),
            virt::gpg_status(virt::KeyType::RsaNone, 0),
            vec![r"\[GNUPG:\] GET_LINE cardedit.prompt"],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: OpenPGP card no. [0-9A-F]{32} detected",
            r"gpg: Note: This command destroys all keys stored on the card!",
        ],
        EditCard,
    );
}

#[cfg(feature = "rsa2048-gen")]
fn gpg_rsa_2048() {
    let file_number: u32 = rand::rngs::OsRng.gen();
    let tmp = format!("/tmp/opcard-tests-{file_number}.gpg");
    let encrypted_file = &tmp;
    let tmp = format!("/tmp/opcard-tests-{file_number}-sig.gpg");
    let sign_file = &tmp;
    let tmp = format!("/tmp/opcard-tests-{file_number}.toml");
    let decrypted_file = &tmp;
    let _dropper = FileDropper {
        temp_file_name: encrypted_file,
    };
    let _dropper = FileDropper {
        temp_file_name: sign_file,
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

    gnupg_test(
        &[],
        &[
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
            virt::gpg_status(virt::KeyType::RsaNone, 0),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        CardStatus,
    );

    gnupg_test(
            &[
                "admin",
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
                vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
                virt::gpg_status(virt::KeyType::RsaNone,0),
                vec![
                    r"\[GNUPG:\] GET_LINE cardedit.prompt",
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
                    r"\[GNUPG:\] NEED_PASSPHRASE [0-9A-F]{16} [0-9A-F]{16} 1 \d",
                ],
                virt::gpg_inquire_pin(),
                vec![
                    r"pub:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESCA:::D276000124010304[A-Z0-9]*:::23::0:",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    &custom_match,
                    r"sub:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}::::::a:::D276000124010304[A-Z0-9]*:::23:",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    r"sub:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}::::::e:::D276000124010304[A-Z0-9]*:::23:",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    r"\[GNUPG:\] KEY_CREATED B [0-9A-F]{40}",
                    r"\[GNUPG:\] GET_LINE cardedit.prompt",
                ]
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
        &[],
        Encrypt {
            i: "Cargo.toml",
            o: encrypted_file,
            r: temp_email,
        },
    );

    println!("================ FINISHED ENCRYPTION ================");

    let custom1 = format!(
        r"\[GNUPG:\] USERID_HINT [a-fA-F0-9]{{16}} {temp_name} \(no comment\) <{temp_email}>"
    );
    let custom2 = format!(r"{temp_name} \(no comment\) <{temp_email}>");
    gnupg_test(
        &[DEFAULT_PW1],
        &[
            vec![
                r"\[GNUPG:\] ENC_TO [a-fA-F0-9]{16} \d* \d*",
                &custom1,
                r"\[GNUPG:\] NEED_PASSPHRASE [a-fA-F0-9]{16} [a-fA-F0-9]{16} 1 0",
            ],
            virt::gpg_inquire_pin(),
            vec![
                r"\[GNUPG:\] DECRYPTION_KEY [a-fA-F0-9]{40} [a-fA-F0-9]{40} u",
                r"\[GNUPG:\] BEGIN_DECRYPTION",
                r"\[GNUPG:\] DECRYPTION_INFO \d \d \d",
                r"\[GNUPG:\] PLAINTEXT \d* \d* Cargo.toml",
                r"\[GNUPG:\] PLAINTEXT_LENGTH \d*",
                r"\[GNUPG:\] DECRYPTION_OKAY",
                r"\[GNUPG:\] GOODMDC",
                r"\[GNUPG:\] END_DECRYPTION",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: encrypted with \d*-bit RSA key, ID [a-fA-F0-9]{16}, created \d{4}-\d\d-\d\d",
            &custom2,
        ],
        Decrypt {
            i: encrypted_file,
            o: decrypted_file,
        },
    );

    println!("================ FINISHED DECRYPTION ================");

    gnupg_test(
        &[DEFAULT_PW1],
        &[
            vec![
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-Z0-9]*",
                r"\[GNUPG:\] BEGIN_SIGNING H\d*",
                &custom1,
                r"\[GNUPG:\] NEED_PASSPHRASE [a-fA-F0-9]{16} [a-fA-F0-9]{16} 1 0",
            ],
            virt::gpg_inquire_pin(),
            vec![r"\[GNUPG:\] SIG_CREATED S 1 \d* 00 [a-fA-F0-9]{10} [a-fA-F0-9]{40}"],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[r#"gpg: using "test\d*@email.com" as default secret key for signing"#],
        Sign {
            i: "Cargo.toml",
            o: sign_file,
            s: temp_email,
        },
    );

    println!("================ FINISHED SIGNATURE ================");

    gnupg_test(
        &[],
        &[
            r"\[GNUPG:\] NEWSIG test\d*@email.com",
            r"\[GNUPG:\] SIG_ID [^ ]* \d{4}-\d\d-\d\d [a-fA-F0-9]{10}",
            r"\[GNUPG:\] GOODSIG [a-fA-F0-9]{16} test name\d* \(no comment\) <test\d*@email.com>",
            r"\[GNUPG:\] VALIDSIG [a-fA-F0-9]{40} \d{4}-\d\d-\d\d [a-fA-F0-9]{10} \d \d \d 1 \d* 00 [a-fA-F0-9]{40}",
            r"\[GNUPG:\] TRUST_ULTIMATE 0 pgp",
        ],
        &[
            r"gpg: Signature made .*",
            r"gpg:                using RSA key [a-fA-F0-9]{40}",
            r#"gpg:                issuer "test\d*@email.com""#,
            r#"pg: Good signature from "test name\d* \(no comment\) <test\d*@email.com>"#,
        ],
        Verify { i: sign_file },
    );
    gnupg_test(
        &[
            "admin",
            "factory-reset",
            "y",
            "yes",
            "verify",
            DEFAULT_PW1,
            "quit",
        ],
        &[
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
            virt::gpg_status(virt::KeyType::Rsa2048, 5),
            vec![
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_BOOL cardedit.factory-reset.proceed",
                r"\[GNUPG:\] GET_LINE cardedit.factory-reset.really",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
            ],
            virt::gpg_inquire_pin(),
            virt::gpg_status(virt::KeyType::RsaNone, 0),
            vec![r"\[GNUPG:\] GET_LINE cardedit.prompt"],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: OpenPGP card no. [0-9A-F]{32} detected",
            r"gpg: Note: This command destroys all keys stored on the card!",
        ],
        EditCard,
    );
}

#[cfg(feature = "rsa3072-gen")]
fn gpg_rsa_3072() {
    let file_number: u32 = rand::rngs::OsRng.gen();
    let tmp = format!("/tmp/opcard-tests-{file_number}.gpg");
    let encrypted_file = &tmp;
    let tmp = format!("/tmp/opcard-tests-{file_number}-sig.gpg");
    let sign_file = &tmp;
    let tmp = format!("/tmp/opcard-tests-{file_number}.toml");
    let decrypted_file = &tmp;
    let _dropper = FileDropper {
        temp_file_name: encrypted_file,
    };
    let _dropper = FileDropper {
        temp_file_name: sign_file,
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

    gnupg_test(
        &[],
        &[
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
            virt::gpg_status(virt::KeyType::RsaNone, 0),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        CardStatus,
    );

    gnupg_test(
            &[
                "admin",
                "key-attr",
                "1",
                "3072",
                DEFAULT_PW3,
                "1",
                "3072",
                DEFAULT_PW3,
                "1",
                "3072",
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
                vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
                virt::gpg_status(virt::KeyType::RsaNone,0),
                vec![
                    r"\[GNUPG:\] GET_LINE cardedit.prompt",
                    r"\[GNUPG:\] GET_LINE cardedit.prompt",
                ],
                attr_rsa_ask(),
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
                    r"\[GNUPG:\] NEED_PASSPHRASE [0-9A-F]{16} [0-9A-F]{16} 1 \d",
                ],
                virt::gpg_inquire_pin(),
                vec![
                    r"pub:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESCA:::D276000124010304[A-Z0-9]*:::23::0:",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    &custom_match,
                    r"sub:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}::::::a:::D276000124010304[A-Z0-9]*:::23:",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    r"sub:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}::::::e:::D276000124010304[A-Z0-9]*:::23:",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    r"\[GNUPG:\] KEY_CREATED B [0-9A-F]{40}",
                    r"\[GNUPG:\] GET_LINE cardedit.prompt",
                ]
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
        &[],
        Encrypt {
            i: "Cargo.toml",
            o: encrypted_file,
            r: temp_email,
        },
    );

    println!("================ FINISHED ENCRYPTION ================");

    let custom1 = format!(
        r"\[GNUPG:\] USERID_HINT [a-fA-F0-9]{{16}} {temp_name} \(no comment\) <{temp_email}>"
    );
    let custom2 = format!(r"{temp_name} \(no comment\) <{temp_email}>");
    gnupg_test(
        &[DEFAULT_PW1],
        &[
            vec![
                r"\[GNUPG:\] ENC_TO [a-fA-F0-9]{16} \d* \d*",
                &custom1,
                r"\[GNUPG:\] NEED_PASSPHRASE [a-fA-F0-9]{16} [a-fA-F0-9]{16} 1 0",
            ],
            virt::gpg_inquire_pin(),
            vec![
                r"\[GNUPG:\] DECRYPTION_KEY [a-fA-F0-9]{40} [a-fA-F0-9]{40} u",
                r"\[GNUPG:\] BEGIN_DECRYPTION",
                r"\[GNUPG:\] DECRYPTION_INFO \d \d \d",
                r"\[GNUPG:\] PLAINTEXT \d* \d* Cargo.toml",
                r"\[GNUPG:\] PLAINTEXT_LENGTH \d*",
                r"\[GNUPG:\] DECRYPTION_OKAY",
                r"\[GNUPG:\] GOODMDC",
                r"\[GNUPG:\] END_DECRYPTION",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: encrypted with \d*-bit RSA key, ID [a-fA-F0-9]{16}, created \d{4}-\d\d-\d\d",
            &custom2,
        ],
        Decrypt {
            i: encrypted_file,
            o: decrypted_file,
        },
    );

    println!("================ FINISHED DECRYPTION ================");

    gnupg_test(
        &[DEFAULT_PW1],
        &[
            vec![
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-Z0-9]*",
                r"\[GNUPG:\] BEGIN_SIGNING H\d*",
                &custom1,
                r"\[GNUPG:\] NEED_PASSPHRASE [a-fA-F0-9]{16} [a-fA-F0-9]{16} 1 0",
            ],
            virt::gpg_inquire_pin(),
            vec![r"\[GNUPG:\] SIG_CREATED S 1 \d* 00 [a-fA-F0-9]{10} [a-fA-F0-9]{40}"],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[r#"gpg: using "test\d*@email.com" as default secret key for signing"#],
        Sign {
            i: "Cargo.toml",
            o: sign_file,
            s: temp_email,
        },
    );

    println!("================ FINISHED SIGNATURE ================");

    gnupg_test(
        &[],
        &[
            r"\[GNUPG:\] NEWSIG test\d*@email.com",
            r"\[GNUPG:\] SIG_ID [^ ]* \d{4}-\d\d-\d\d [a-fA-F0-9]{10}",
            r"\[GNUPG:\] GOODSIG [a-fA-F0-9]{16} test name\d* \(no comment\) <test\d*@email.com>",
            r"\[GNUPG:\] VALIDSIG [a-fA-F0-9]{40} \d{4}-\d\d-\d\d [a-fA-F0-9]{10} \d \d \d 1 \d* 00 [a-fA-F0-9]{40}",
            r"\[GNUPG:\] TRUST_ULTIMATE 0 pgp",
        ],
        &[
            r"gpg: Signature made .*",
            r"gpg:                using RSA key [a-fA-F0-9]{40}",
            r#"gpg:                issuer "test\d*@email.com""#,
            r#"pg: Good signature from "test name\d* \(no comment\) <test\d*@email.com>"#,
        ],
        Verify { i: sign_file },
    );
    gnupg_test(
        &[
            "admin",
            "factory-reset",
            "y",
            "yes",
            "verify",
            DEFAULT_PW1,
            "quit",
        ],
        &[
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
            virt::gpg_status(virt::KeyType::Rsa3072, 5),
            vec![
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_BOOL cardedit.factory-reset.proceed",
                r"\[GNUPG:\] GET_LINE cardedit.factory-reset.really",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
            ],
            virt::gpg_inquire_pin(),
            virt::gpg_status(virt::KeyType::RsaNone, 0),
            vec![r"\[GNUPG:\] GET_LINE cardedit.prompt"],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: OpenPGP card no. [0-9A-F]{32} detected",
            r"gpg: Note: This command destroys all keys stored on the card!",
        ],
        EditCard,
    );
}

#[cfg(feature = "rsa4096-gen")]
fn gpg_rsa_4096() {
    let file_number: u32 = rand::rngs::OsRng.gen();
    let tmp = format!("/tmp/opcard-tests-{file_number}.gpg");
    let encrypted_file = &tmp;
    let tmp = format!("/tmp/opcard-tests-{file_number}-sig.gpg");
    let sign_file = &tmp;
    let tmp = format!("/tmp/opcard-tests-{file_number}.toml");
    let decrypted_file = &tmp;
    let _dropper = FileDropper {
        temp_file_name: encrypted_file,
    };
    let _dropper = FileDropper {
        temp_file_name: sign_file,
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

    gnupg_test(
        &[],
        &[
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
            virt::gpg_status(virt::KeyType::RsaNone, 0),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        CardStatus,
    );

    gnupg_test(
            &[
                "admin",
                "key-attr",
                "1",
                "4096",
                DEFAULT_PW3,
                "1",
                "4096",
                DEFAULT_PW3,
                "1",
                "4096",
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
                vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
                virt::gpg_status(virt::KeyType::RsaNone,0),
                vec![
                    r"\[GNUPG:\] GET_LINE cardedit.prompt",
                    r"\[GNUPG:\] GET_LINE cardedit.prompt",
                ],
                attr_rsa_ask(),
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
                    r"\[GNUPG:\] NEED_PASSPHRASE [0-9A-F]{16} [0-9A-F]{16} 1 \d",
                ],
                virt::gpg_inquire_pin(),
                vec![
                    r"pub:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESCA:::D276000124010304[A-Z0-9]*:::23::0:",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    &custom_match,
                    r"sub:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}::::::a:::D276000124010304[A-Z0-9]*:::23:",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    r"sub:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}::::::e:::D276000124010304[A-Z0-9]*:::23:",
                    r"fpr:::::::::[0-9A-F]{40}:",
                    r"grp:::::::::[0-9A-F]{40}:",
                    r"\[GNUPG:\] KEY_CREATED B [0-9A-F]{40}",
                    r"\[GNUPG:\] GET_LINE cardedit.prompt",
                ]
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
        &[],
        Encrypt {
            i: "Cargo.toml",
            o: encrypted_file,
            r: temp_email,
        },
    );

    println!("================ FINISHED ENCRYPTION ================");

    let custom1 = format!(
        r"\[GNUPG:\] USERID_HINT [a-fA-F0-9]{{16}} {temp_name} \(no comment\) <{temp_email}>"
    );
    let custom2 = format!(r"{temp_name} \(no comment\) <{temp_email}>");
    gnupg_test(
        &[DEFAULT_PW1],
        &[
            vec![
                r"\[GNUPG:\] ENC_TO [a-fA-F0-9]{16} \d* \d*",
                &custom1,
                r"\[GNUPG:\] NEED_PASSPHRASE [a-fA-F0-9]{16} [a-fA-F0-9]{16} 1 0",
            ],
            virt::gpg_inquire_pin(),
            vec![
                r"\[GNUPG:\] DECRYPTION_KEY [a-fA-F0-9]{40} [a-fA-F0-9]{40} u",
                r"\[GNUPG:\] BEGIN_DECRYPTION",
                r"\[GNUPG:\] DECRYPTION_INFO \d \d \d",
                r"\[GNUPG:\] PLAINTEXT \d* \d* Cargo.toml",
                r"\[GNUPG:\] PLAINTEXT_LENGTH \d*",
                r"\[GNUPG:\] DECRYPTION_OKAY",
                r"\[GNUPG:\] GOODMDC",
                r"\[GNUPG:\] END_DECRYPTION",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: encrypted with \d*-bit RSA key, ID [a-fA-F0-9]{16}, created \d{4}-\d\d-\d\d",
            &custom2,
        ],
        Decrypt {
            i: encrypted_file,
            o: decrypted_file,
        },
    );

    println!("================ FINISHED DECRYPTION ================");

    gnupg_test(
        &[DEFAULT_PW1],
        &[
            vec![
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-Z0-9]*",
                r"\[GNUPG:\] BEGIN_SIGNING H\d*",
                &custom1,
                r"\[GNUPG:\] NEED_PASSPHRASE [a-fA-F0-9]{16} [a-fA-F0-9]{16} 1 0",
            ],
            virt::gpg_inquire_pin(),
            vec![r"\[GNUPG:\] SIG_CREATED S 1 \d* 00 [a-fA-F0-9]{10} [a-fA-F0-9]{40}"],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[r#"gpg: using "test\d*@email.com" as default secret key for signing"#],
        Sign {
            i: "Cargo.toml",
            o: sign_file,
            s: temp_email,
        },
    );

    println!("================ FINISHED SIGNATURE ================");

    gnupg_test(
        &[],
        &[
            r"\[GNUPG:\] NEWSIG test\d*@email.com",
            r"\[GNUPG:\] SIG_ID [^ ]* \d{4}-\d\d-\d\d [a-fA-F0-9]{10}",
            r"\[GNUPG:\] GOODSIG [a-fA-F0-9]{16} test name\d* \(no comment\) <test\d*@email.com>",
            r"\[GNUPG:\] VALIDSIG [a-fA-F0-9]{40} \d{4}-\d\d-\d\d [a-fA-F0-9]{10} \d \d \d 1 \d* 00 [a-fA-F0-9]{40}",
            r"\[GNUPG:\] TRUST_ULTIMATE 0 pgp",
        ],
        &[
            r"gpg: Signature made .*",
            r"gpg:                using RSA key [a-fA-F0-9]{40}",
            r#"gpg:                issuer "test\d*@email.com""#,
            r#"pg: Good signature from "test name\d* \(no comment\) <test\d*@email.com>"#,
        ],
        Verify { i: sign_file },
    );
    gnupg_test(
        &[
            "admin",
            "factory-reset",
            "y",
            "yes",
            "verify",
            DEFAULT_PW1,
            "quit",
        ],
        &[
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
            virt::gpg_status(virt::KeyType::Rsa4096, 5),
            vec![
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_BOOL cardedit.factory-reset.proceed",
                r"\[GNUPG:\] GET_LINE cardedit.factory-reset.really",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
            ],
            virt::gpg_inquire_pin(),
            virt::gpg_status(virt::KeyType::RsaNone, 0),
            vec![r"\[GNUPG:\] GET_LINE cardedit.prompt"],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: OpenPGP card no. [0-9A-F]{32} detected",
            r"gpg: Note: This command destroys all keys stored on the card!",
        ],
        EditCard,
    );
}

#[cfg(all(feature = "vpicc", not(feature = "dangerous-test-real-card")))]
#[test]
fn gpg_crypto() {
    with_vsc(gpg_255);
    with_vsc(gpg_p256);
    #[cfg(feature = "rsa2048-gen")]
    with_vsc(gpg_rsa_2048);
    #[cfg(feature = "rsa3072-gen")]
    with_vsc(gpg_rsa_3072);
    #[cfg(feature = "rsa4096-gen")]
    with_vsc(gpg_rsa_4096);
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn gpg_crypto() {
    gpg_255();
    gpg_p256();
    #[cfg(feature = "rsa2048-gen")]
    gpg_rsa_2048();
    #[cfg(feature = "rsa3072-gen")]
    gpg_rsa_3072();
    #[cfg(feature = "rsa4096-gen")]
    gpg_rsa_4096();
}
