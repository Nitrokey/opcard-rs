// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(any(feature = "virtual", feature = "dangerous-test-real-card"))]

mod virt;

use rand::Rng;
use test_log::test;

use virt::gnupg_test;
use virt::GpgCommand::*;

#[cfg(feature = "virtual")]
use virt::with_vsc;

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

    let custom_match2 = format!(
        r"uid:u::::::::{temp_name} \(no comment\) <{temp_email}>:::.*,mdc,no-ks-modify:1,p::"
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
        &["9", "1", "0", temp_name, temp_email, "no comment", "", ""],
        &[
            vec![
                r"\[GNUPG:\] GET_LINE keygen.algo",
                r"\[GNUPG:\] GET_LINE keygen.curve",
                r"\[GNUPG:\] GET_LINE keygen.valid",
                r"\[GNUPG:\] GET_LINE keygen.name",
                r"\[GNUPG:\] GET_LINE keygen.email",
                r"\[GNUPG:\] GET_LINE keygen.comment",
            ],
            virt::gpg_inquire_pin(),
            virt::gpg_inquire_pin(),
            vec![
                r"pub:u:\d*:22:[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESC:::\+::ed25519:::0:",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                &custom_match,
                r"sub:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}::::::e:::\+::cv25519::",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                r"\[GNUPG:\] KEY_CREATED B [A-F0-9]{40}",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: revocation certificate stored as '.*\.rev'",
            r"gpg: checking the trustdb",
            r"gpg: marginals needed: \d  completes needed: \d  trust model: pgp",
            r"gpg: depth:[ 0-9]*valid:[ 0-9]*signed:[ 0-9]*trust: \d*-, \d*q, \d*n, \d*m, \d*f, \d*u",
        ],
        Generate,
    );

    println!("================ FINISHED GENERATING 25519 KEYS ================");

    gnupg_test(
        &["key *", "keytocard", "2", DEFAULT_PW3, DEFAULT_PW3, "save"],
        &[
            vec![
                r"sec:u:\d*:22:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"sec:u:\d*:22:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-F0-9]*",
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.storekeytype",
            ],
            virt::gpg_inquire_pin(),
            virt::gpg_inquire_pin(),
            vec![
                r"sec:u:\d*:22:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        EditKey { o: temp_email },
    );

    println!("================ FINISHED IMPORTING DECRYPTION KEY ================");

    gnupg_test(
        &["keytocard", "y", "1", DEFAULT_PW3, "save"],
        &[
            vec![
                r"sec:u:\d*:22:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"\[GNUPG:\] GET_BOOL keyedit.keytocard.use_primary",
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-F0-9]*",
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.storekeytype",
            ],
            virt::gpg_inquire_pin(),
            vec![
                r"sec:u:\d*:22:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        EditKey { o: temp_email },
    );

    println!("================ FINISHED IMPORTING 25519 KEYS ================");

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
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-F0-9]*",
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
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-F0-9]*"],
            virt::gpg_status(virt::KeyType::Cv25519NoAut, 1),
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

    let custom_match2 = format!(
        r"uid:u::::::::{temp_name} \(no comment\) <{temp_email}>:::.*,mdc,no-ks-modify:1,p::"
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
        &["9", "3", "0", temp_name, temp_email, "no comment", "", ""],
        &[
            vec![
                r"\[GNUPG:\] GET_LINE keygen.algo",
                r"\[GNUPG:\] GET_LINE keygen.curve",
                r"\[GNUPG:\] GET_LINE keygen.valid",
                r"\[GNUPG:\] GET_LINE keygen.name",
                r"\[GNUPG:\] GET_LINE keygen.email",
                r"\[GNUPG:\] GET_LINE keygen.comment",
            ],
            virt::gpg_inquire_pin(),
            virt::gpg_inquire_pin(),
            vec![
                r"pub:u:\d*:19:[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESC:::\+::nistp256:::0:",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                &custom_match,
                r"sub:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}::::::e:::\+::nistp256::",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                r"\[GNUPG:\] KEY_CREATED B [A-F0-9]{40}",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: revocation certificate stored as '.*\.rev'",
            r"gpg: checking the trustdb",
            r"gpg: marginals needed: \d  completes needed: \d  trust model: pgp",
            r"gpg: depth:[ 0-9]*valid:[ 0-9]*signed:[ 0-9]*trust: \d*-, \d*q, \d*n, \d*m, \d*f, \d*u",
        ],
        Generate,
    );

    println!("================ FINISHED GENERATING P256 KEYS ================");

    gnupg_test(
        &["key *", "keytocard", "2", DEFAULT_PW3, DEFAULT_PW3, "save"],
        &[
            vec![
                r"sec:u:\d*:19:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"sec:u:\d*:19:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-F0-9]*",
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.storekeytype",
            ],
            virt::gpg_inquire_pin(),
            virt::gpg_inquire_pin(),
            vec![
                r"sec:u:\d*:19:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        EditKey { o: temp_email },
    );

    println!("================ FINISHED IMPORTING DECRYPTION KEY ================");

    gnupg_test(
        &["keytocard", "y", "1", DEFAULT_PW3, "save"],
        &[
            vec![
                r"sec:u:\d*:19:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"\[GNUPG:\] GET_BOOL keyedit.keytocard.use_primary",
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-F0-9]*",
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.storekeytype",
            ],
            virt::gpg_inquire_pin(),
            vec![
                r"sec:u:\d*:19:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:18:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        EditKey { o: temp_email },
    );

    println!("================ FINISHED IMPORTING P256 KEYS ================");

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
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-F0-9]*",
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
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-F0-9]*"],
            virt::gpg_status(virt::KeyType::P256NoAut, 1),
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

#[cfg(feature = "rsa2048")]
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

    let custom_match2 = format!(
        r"uid:u::::::::{temp_name} \(no comment\) <{temp_email}>:::.*,mdc,no-ks-modify:1,p::"
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
            "1",
            "2048",
            "2048",
            "0",
            temp_name,
            temp_email,
            "no comment",
            "",
            "",
        ],
        &[
            vec![
                r"\[GNUPG:\] GET_LINE keygen.algo",
                r"\[GNUPG:\] GET_LINE keygen.size",
                r"\[GNUPG:\] GET_LINE keygen.size",
                r"\[GNUPG:\] GET_LINE keygen.valid",
                r"\[GNUPG:\] GET_LINE keygen.name",
                r"\[GNUPG:\] GET_LINE keygen.email",
                r"\[GNUPG:\] GET_LINE keygen.comment",
            ],
            virt::gpg_inquire_pin(),
            virt::gpg_inquire_pin(),
            vec![
                r"pub:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESC:::\+:::23::0:",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                &custom_match,
                r"sub:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}::::::e:::\+:::23:",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                r"\[GNUPG:\] KEY_CREATED B [A-F0-9]{40}",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: revocation certificate stored as '.*\.rev'",
            r"gpg: checking the trustdb",
            r"gpg: marginals needed: \d  completes needed: \d  trust model: pgp",
            r"gpg: depth:[ 0-9]*valid:[ 0-9]*signed:[ 0-9]*trust: \d*-, \d*q, \d*n, \d*m, \d*f, \d*u",
        ],
        Generate,
    );

    println!("================ FINISHED GENERATING Rsa2048 KEYS ================");

    gnupg_test(
        &["key *", "keytocard", "2", DEFAULT_PW3, "save"],
        &[
            vec![
                r"sec:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"sec:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-F0-9]*",
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.storekeytype",
            ],
            virt::gpg_inquire_pin(),
            // virt::gpg_inquire_pin(),
            vec![
                r"sec:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        EditKey { o: temp_email },
    );

    println!("================ FINISHED IMPORTING DECRYPTION KEY ================");

    gnupg_test(
        &["keytocard", "y", "1", DEFAULT_PW3, "save"],
        &[
            vec![
                r"sec:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"\[GNUPG:\] GET_BOOL keyedit.keytocard.use_primary",
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-F0-9]*",
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.storekeytype",
            ],
            vec![
                r"sec:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        EditKey { o: temp_email },
    );

    println!("================ FINISHED IMPORTING Rsa2048 KEYS ================");

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
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-F0-9]*",
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
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-F0-9]*"],
            virt::gpg_status(virt::KeyType::RsaNoAut, 1),
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

#[cfg(feature = "rsa4096")]
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

    let custom_match2 = format!(
        r"uid:u::::::::{temp_name} \(no comment\) <{temp_email}>:::.*,mdc,no-ks-modify:1,p::"
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
            "1",
            "4096",
            "4096",
            "0",
            temp_name,
            temp_email,
            "no comment",
            "",
            "",
        ],
        &[
            vec![
                r"\[GNUPG:\] GET_LINE keygen.algo",
                r"\[GNUPG:\] GET_LINE keygen.size",
                r"\[GNUPG:\] GET_LINE keygen.size",
                r"\[GNUPG:\] GET_LINE keygen.valid",
                r"\[GNUPG:\] GET_LINE keygen.name",
                r"\[GNUPG:\] GET_LINE keygen.email",
                r"\[GNUPG:\] GET_LINE keygen.comment",
            ],
            virt::gpg_inquire_pin(),
            virt::gpg_inquire_pin(),
            vec![
                r"pub:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESC:::\+:::23::0:",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                &custom_match,
                r"sub:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}::::::e:::\+:::23:",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                r"\[GNUPG:\] KEY_CREATED B [A-F0-9]{40}",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: revocation certificate stored as '.*\.rev'",
            r"gpg: checking the trustdb",
            r"gpg: marginals needed: \d  completes needed: \d  trust model: pgp",
            r"gpg: depth:[ 0-9]*valid:[ 0-9]*signed:[ 0-9]*trust: \d*-, \d*q, \d*n, \d*m, \d*f, \d*u",
        ],
        Generate,
    );

    println!("================ FINISHED GENERATING Rsa4096 KEYS ================");

    gnupg_test(
        &["key *", "keytocard", "2", DEFAULT_PW3, DEFAULT_PW3, "save"],
        &[
            vec![
                r"sec:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"sec:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-F0-9]*",
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.storekeytype",
            ],
            virt::gpg_inquire_pin(),
            virt::gpg_inquire_pin(),
            vec![
                r"sec:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        EditKey { o: temp_email },
    );

    println!("================ FINISHED IMPORTING DECRYPTION KEY ================");

    gnupg_test(
        &["keytocard", "y", "1", DEFAULT_PW3, "save"],
        &[
            vec![
                r"sec:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"\[GNUPG:\] GET_BOOL keyedit.keytocard.use_primary",
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-F0-9]*",
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.storekeytype",
            ],
            virt::gpg_inquire_pin(),
            vec![
                r"sec:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc",
                r"fpr:::::::::[0-9A-F]{40}:",
                r"ssb:u:\d*:1:[0-9A-F]{16}:[0-9A-F]{10}:0:::::e",
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        EditKey { o: temp_email },
    );

    println!("================ FINISHED IMPORTING Rsa4096 KEYS ================");

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
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-F0-9]*",
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
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-F0-9]*"],
            virt::gpg_status(virt::KeyType::Rsa4096NoAut, 1),
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

#[cfg(feature = "virtual")]
#[test]
fn gpg_crypto() {
    #[cfg(feature = "rsa2048")]
    with_vsc(gpg_rsa_2048);
    #[cfg(feature = "rsa4096-gen")]
    with_vsc(gpg_rsa_4096);
    with_vsc(gpg_255);
    with_vsc(gpg_p256);
}
#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn gpg_crypto() {
    gpg_255();
    gpg_p256();
    #[cfg(feature = "rsa2048")]
    gpg_rsa_2048();
    #[cfg(feature = "rsa4096")]
    gpg_rsa_4096();
}
