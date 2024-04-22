// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(any(feature = "vpicc", feature = "dangerous-test-real-card"))]

mod virt;

use std::iter;

use rand::Rng;
use test_log::test;

use virt::gnupg_test;
use virt::Context;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyAlgo {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Cv25519,
    P256,
    P384,
    P521,
}

impl KeyAlgo {
    fn _generate_for_key<'a>(
        algo: &'static str,
        id: &'static str,
        temp_name: &'a str,
        temp_email: &'a str,
    ) -> Vec<&'a str> {
        vec![
            "admin",
            "key-attr",
            algo,
            id,
            DEFAULT_PW3,
            algo,
            id,
            DEFAULT_PW3,
            algo,
            id,
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
        ]
    }

    fn generate_for_key<'a>(self, temp_name: &'a str, temp_email: &'a str) -> Vec<&'a str> {
        match self {
            Self::Rsa2048 => vec![
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
            Self::Rsa3072 => Self::_generate_for_key("1", "3072", temp_name, temp_email),
            Self::Rsa4096 => Self::_generate_for_key("1", "4096", temp_name, temp_email),
            Self::Cv25519 => Self::_generate_for_key("2", "1", temp_name, temp_email),
            Self::P256 => Self::_generate_for_key("2", "3", temp_name, temp_email),
            Self::P384 => Self::_generate_for_key("2", "4", temp_name, temp_email),
            Self::P521 => Self::_generate_for_key("2", "5", temp_name, temp_email),
        }
    }

    #[allow(unused)]
    fn is_ec(self) -> bool {
        match self {
            Self::Cv25519 | Self::P256 | Self::P384 | Self::P521 => true,
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => false,
        }
    }

    fn algo_name_generation(self) -> &'static str {
        match self {
            Self::P256 => "nistp256:",
            Self::P384 => "nistp384:",
            Self::P521 => "nistp521:",
            Self::Cv25519 => "ed25519:",
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => ":23",
        }
    }

    fn algo_name(self) -> &'static str {
        match self {
            Self::P256 => "nistp256",
            Self::P384 => "nistp384",
            Self::P521 => "nistp521",
            Self::Cv25519 => "cv25519",
            Self::Rsa2048 => "rsa2048",
            Self::Rsa3072 => "rsa3072",
            Self::Rsa4096 => "rsa4096",
        }
    }

    fn algo_name_generation_encryption(self) -> &'static str {
        match self {
            Self::P256 => "nistp256",
            Self::P384 => "nistp384",
            Self::P521 => "nistp521",
            Self::Cv25519 => "cv25519",
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => "23",
        }
    }

    fn algorithm_id_signature(self) -> &'static str {
        match self {
            Self::P256 | Self::P384 | Self::P521 => "19",
            Self::Cv25519 => "22",
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => "1",
        }
    }

    fn algorithm_name_signature(self) -> &'static str {
        match self {
            Self::P256 | Self::P384 | Self::P521 => "ECDSA",
            Self::Cv25519 => "EDDSA",
            Self::Rsa2048 => "RSA2048",
            Self::Rsa3072 => "RSA3072",
            Self::Rsa4096 => "RSA4096",
        }
    }

    fn algorithm_id_encryption(self) -> &'static str {
        match self {
            Self::P256 | Self::P384 | Self::P521 => "18",
            Self::Cv25519 => "18",
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => "1",
        }
    }

    fn attr_ask(self) -> Vec<&'static str> {
        match self {
            Self::Rsa2048 => vec![],
            Self::Rsa3072 | Self::Rsa4096 => {
                let mut ask = attr_rsa_ask();
                ask.push(r"\[GNUPG:\] GET_LINE cardedit.prompt");
                ask
            }
            Self::Cv25519 | Self::P256 | Self::P384 | Self::P521 => {
                let mut ask = attr_ec_ask();
                ask.push(r"\[GNUPG:\] GET_LINE cardedit.prompt");
                ask
            }
        }
    }

    fn keytype(self) -> virt::KeyType {
        match self {
            Self::Rsa2048 => virt::KeyType::Rsa2048,
            Self::Rsa3072 => virt::KeyType::Rsa3072,
            Self::Rsa4096 => virt::KeyType::Rsa4096,
            Self::Cv25519 => virt::KeyType::Cv25519,
            Self::P256 => virt::KeyType::P256,
            Self::P384 => virt::KeyType::P384,
            Self::P521 => virt::KeyType::P521,
        }
    }

    #[allow(unused)]
    fn keytype_no_aut(self) -> virt::KeyType {
        match self {
            Self::Rsa2048 => virt::KeyType::Rsa2048NoAut,
            Self::Rsa3072 => virt::KeyType::Rsa3072NoAut,
            Self::Rsa4096 => virt::KeyType::Rsa4096NoAut,
            Self::Cv25519 => virt::KeyType::Cv25519NoAut,
            Self::P256 => virt::KeyType::P256NoAut,
            Self::P384 => virt::KeyType::P384NoAut,
            Self::P521 => virt::KeyType::P521NoAut,
        }
    }
}

fn gpg_test(algo: KeyAlgo) {
    let ctx = Context::new();

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
        .collect::<Vec<_>>(),
        &[],
        CardStatus,
        &ctx,
    );

    gnupg_test(
        &algo.generate_for_key(temp_name, temp_email),
        &[
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
            virt::gpg_status(virt::KeyType::RsaNone, 0),
            vec![
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
            ],
            algo.attr_ask(),
            vec![r"\[GNUPG:\] GET_LINE cardedit.genkeys.backup_enc"],
            virt::gpg_inquire_pin(),
            virt::gpg_inquire_pin(),
            vec![
                r"\[GNUPG:\] GET_LINE keygen.valid",
                r"\[GNUPG:\] GET_LINE keygen.name",
                r"\[GNUPG:\] GET_LINE keygen.email",
                r"\[GNUPG:\] GET_LINE keygen.comment",
                r"\[GNUPG:\] USERID_HINT [0-9A-F]{16} \[\?\]",
                r"\[GNUPG:\] NEED_PASSPHRASE [0-9A-F]{16} [0-9A-F]{16} \d* \d",
            ],
            virt::gpg_inquire_pin(),
            vec![
                &format!(
                    "{}{}{}{}::0:",
                    r"pub:u:\d*:",
                    algo.algorithm_id_signature(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESCA:::D276000124010304[A-Z0-9]*::",
                    algo.algo_name_generation()
                ),
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                &custom_match,
                &format!(
                    "{}{}{}{}:",
                    r"sub:u:\d*:",
                    algo.algorithm_id_signature(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}::::::a:::D276000124010304[A-Z0-9]*::",
                    algo.algo_name_generation()
                ),
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                &format!(
                    "{}{}{}{}:",
                    r"sub:u:\d*:",
                    algo.algorithm_id_encryption(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}::::::e:::D276000124010304[A-Z0-9]*::",
                    algo.algo_name_generation_encryption()
                ),
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                r"\[GNUPG:\] KEY_CREATED B [0-9A-F]{40}",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
            ],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>(),
        &[
            r"gpg: revocation certificate stored as '.*\.rev'",
            r"gpg: checking the trustdb",
            r"gpg: marginals needed: \d  completes needed: \d  trust model: pgp",
            r"gpg: depth:[ 0-9]*valid:[ 0-9]*signed:[ 0-9]*trust: \d*-, \d*q, \d*n, \d*m, \d*f, \d*u",
        ],
        EditCard,
        &ctx,
    );

    println!("================ FINISHED GENERATING {algo:?} ================");

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
        &ctx,
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
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-Z0-9]*",
                &custom1,
                &format!(
                    "{} {} 0",
                    r"\[GNUPG:\] NEED_PASSPHRASE [a-fA-F0-9]{16} [a-fA-F0-9]{16}",
                    algo.algorithm_id_encryption(),
                ),
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
        .collect::<Vec<_>>(),
        &[
            &format!(
                "gpg: encrypted with {} {}",
                algo.algo_name(),
                r"key, ID [a-fA-F0-9]{16}, created \d{4}-\d\d-\d\d"
            ),
            &custom2,
        ],
        Decrypt {
            i: encrypted_file,
            o: decrypted_file,
        },
        &ctx,
    );

    println!("================ FINISHED DECRYPTION ================");

    gnupg_test(
        &[DEFAULT_PW1],
        &[
            vec![
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-Z0-9]*",
                r"\[GNUPG:\] BEGIN_SIGNING H\d*",
                &custom1,
                &format!(
                    "{} {} 0",
                    r"\[GNUPG:\] NEED_PASSPHRASE [a-fA-F0-9]{16} [a-fA-F0-9]{16}",
                    algo.algorithm_id_signature(),
                ),
            ],
            virt::gpg_inquire_pin(),
            vec![&format!(
                r"\[GNUPG:\] SIG_CREATED S {} {}",
                algo.algorithm_id_signature(),
                r"\d* 00 [a-fA-F0-9]{10} [a-fA-F0-9]{40}"
            )],
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
        &ctx,
    );

    println!("================ FINISHED SIGNATURE ================");

    gnupg_test(
        &[],
        &[
            r"\[GNUPG:\] NEWSIG test\d*@email.com",
            r"\[GNUPG:\] SIG_ID [^ ]* \d{4}-\d\d-\d\d [a-fA-F0-9]{10}",
            r"\[GNUPG:\] GOODSIG [a-fA-F0-9]{16} test name\d* \(no comment\) <test\d*@email.com>",
            &format!(
                r"{} {} {}",
                r"\[GNUPG:\] VALIDSIG [a-fA-F0-9]{40} \d{4}-\d\d-\d\d [a-fA-F0-9]{10} \d \d \d",
                algo.algorithm_id_signature(),
                r"\d* 00 [a-fA-F0-9]{40}"
            ),
            r"\[GNUPG:\] TRUST_ULTIMATE 0 pgp",
        ],
        &[
            r"gpg: Signature made .*",
            &format!(
                r"gpg:                using {}",
                algo.algorithm_name_signature()
            ),
            r#"gpg:                issuer "test\d*@email.com""#,
            r#"pg: Good signature from "test name\d* \(no comment\) <test\d*@email.com>"#,
        ],
        Verify { i: sign_file },
        &ctx,
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
            virt::gpg_status(algo.keytype(), 5),
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
        &ctx,
    );
}

#[cfg(all(feature = "vpicc", not(feature = "dangerous-test-real-card")))]
#[test]
fn gpg_crypto() {
    with_vsc(|| gpg_test(KeyAlgo::Cv25519));
    with_vsc(|| gpg_test(KeyAlgo::P256));
    with_vsc(|| gpg_test(KeyAlgo::P384));
    with_vsc(|| gpg_test(KeyAlgo::P521));
    #[cfg(feature = "rsa2048-gen")]
    with_vsc(|| gpg_test(KeyAlgo::Rsa2048));
    #[cfg(feature = "rsa3072-gen")]
    with_vsc(|| gpg_test(KeyAlgo::Rsa3072));
    #[cfg(feature = "rsa4096-gen")]
    with_vsc(|| gpg_test(KeyAlgo::Rsa4096));
}

#[cfg(feature = "dangerous-test-real-card")]
#[test]
fn gpg_crypto() {
    gpg_test(KeyAlgo::Cv25519);
    gpg_test(KeyAlgo::P256);
    gpg_test(KeyAlgo::P384);
    gpg_test(KeyAlgo::P521);
    #[cfg(feature = "rsa2048-gen")]
    gpg_test(KeyAlgo::Rsa2048);
    #[cfg(feature = "rsa3072-gen")]
    gpg_test(KeyAlgo::Rsa3072);
    #[cfg(feature = "rsa4096-gen")]
    gpg_test(KeyAlgo::Rsa4096);
}
