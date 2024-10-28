// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(any(feature = "vpicc", feature = "dangerous-test-real-card"))]

use rand::Rng;
use std::iter;

use std::{
    io::{BufRead, BufReader, Write},
    mem::drop,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
};

#[cfg(feature = "vpicc")]
use std::{sync::mpsc, thread::sleep, time::Duration};

use regex::{Regex, RegexSet};
use tempfile::TempDir;

#[cfg(feature = "vpicc")]
use stoppable_thread::spawn;

const STDOUT_FILTER: &[&str] = &[
    r"\[GNUPG:\] KEY_CONSIDERED [0-9A-F]{40} \d",
    r"\[GNUPG:\] ENCRYPTION_COMPLIANCE_MODE \d*",
    r"\[GNUPG:\] DECRYPTION_COMPLIANCE_MODE \d*",
    r"\[GNUPG:\] VERIFICATION_COMPLIANCE_MODE \d*",
    r"\[GNUPG:\] GOT_IT",
];

const STDERR_FILTER: &[&str] = &[
    r"gpg: WARNING: unsafe permissions on homedir '.*'",
    r"gpg: keybox '.*' created",
    r"gpg: .*: trustdb created",
    r"gpg: key [0-9A-F]{16} marked as ultimately trusted",
    r"gpg: directory '.*/openpgp-revocs.d' created",
    r"gpg \(GnuPG\) \d*.\d*.\d*; Copyright \(C\) \d* .*",
    r"This is free software: you are free to change and redistribute it.",
    r"There is NO WARRANTY, to the extent permitted by law.",
    r"gpg: next trustdb check due at \d*-\d*-\d*",
    r"gpg: all values passed to '--default-key",
    r"gpg: problem with fast path key listing: Result truncated - ignored",
];

pub struct Context {
    tempdir: TempDir,
}

impl Context {
    #[allow(unused)]
    pub fn new() -> Self {
        let tempdir = TempDir::with_prefix("opcard-test-").expect("failed to create tempdir");
        Self { tempdir }
    }

    fn keyring(&self) -> PathBuf {
        self.tempdir.path().join("keyring.gpg")
    }

    fn trustdb(&self) -> PathBuf {
        self.tempdir.path().join("trustdb.gpg")
    }
}

#[cfg(feature = "vpicc")]
#[allow(unused)]
pub fn with_vsc<F: FnOnce() -> R, R>(f: F) -> R {
    let mut vpicc = vpicc::connect().expect("failed to connect to vpcd");

    let (tx, rx) = mpsc::channel();
    let handle = spawn(move |stopped| {
        opcard::virt::with_ram_client("opcard", |client| {
            let card = opcard::Card::new(client, opcard::Options::default());
            let mut vpicc_card = opcard::VpiccCard::new(card);
            let mut result = Ok(());
            while !stopped.get() && result.is_ok() {
                result = vpicc.poll(&mut vpicc_card);
                if result.is_ok() {
                    tx.send(()).expect("failed to send message");
                }
            }
            result
        })
    });

    rx.recv().expect("failed to read message");

    sleep(Duration::from_millis(200));

    let result = f();

    handle
        .stop()
        .join()
        .expect("failed to join vpicc thread")
        .expect("failed to run virtual smartcard");
    result
}

#[allow(unused)]
pub enum KeyType {
    RsaNone,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Rsa2048NoAut,
    Rsa3072NoAut,
    Rsa4096NoAut,
    Cv25519,
    Cv25519NoAut,
    P256,
    P256NoAut,
    P384,
    P384NoAut,
    P521,
    P521NoAut,
    BrainpoolP256R1,
    BrainpoolP256R1NoAut,
    BrainpoolP384R1,
    BrainpoolP384R1NoAut,
    BrainpoolP512R1,
    BrainpoolP512R1NoAut,
    Secp256k1,
    Secp256k1NoAut,
}

#[allow(unused)]
pub fn gpg_status(key: KeyType, sign_count: usize) -> Vec<&'static str> {
    let (first, sec, third, fpr, grp) = match key {
        KeyType::Cv25519 => (
            r"keyattr:1:22:Ed25519:",
            r"keyattr:2:18:Curve25519:",
            r"keyattr:3:22:Ed25519:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
        ),
        KeyType::Cv25519NoAut => (
            r"keyattr:1:22:Ed25519:",
            r"keyattr:2:18:Curve25519:",
            r"keyattr:3:1:2048:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}::",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0]{40}:",
        ),
        KeyType::P256 => (
            r"keyattr:1:19:NIST P-256:",
            r"keyattr:2:18:NIST P-256:",
            r"keyattr:3:19:NIST P-256:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
        ),
        KeyType::P256NoAut => (
            r"keyattr:1:19:NIST P-256:",
            r"keyattr:2:18:NIST P-256:",
            r"keyattr:3:1:2048:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}::",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0]{40}:",
        ),
        KeyType::P384 => (
            r"keyattr:1:19:NIST P-384:",
            r"keyattr:2:18:NIST P-384:",
            r"keyattr:3:19:NIST P-384:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
        ),
        KeyType::P384NoAut => (
            r"keyattr:1:19:NIST P-384:",
            r"keyattr:2:18:NIST P-384:",
            r"keyattr:3:1:2048:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}::",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0]{40}:",
        ),
        KeyType::P521 => (
            r"keyattr:1:19:NIST P-521:",
            r"keyattr:2:18:NIST P-521:",
            r"keyattr:3:19:NIST P-521:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
        ),
        KeyType::P521NoAut => (
            r"keyattr:1:19:NIST P-521:",
            r"keyattr:2:18:NIST P-521:",
            r"keyattr:3:1:2048:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}::",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0]{40}:",
        ),
        KeyType::BrainpoolP256R1 => (
            r"keyattr:1:19:brainpoolP256r1:",
            r"keyattr:2:18:brainpoolP256r1:",
            r"keyattr:3:19:brainpoolP256r1:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
        ),
        KeyType::BrainpoolP256R1NoAut => (
            r"keyattr:1:19:brainpoolP256r1:",
            r"keyattr:2:18:brainpoolP256r1:",
            r"keyattr:3:1:2048:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}::",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0]{40}:",
        ),
        KeyType::BrainpoolP384R1 => (
            r"keyattr:1:19:brainpoolP384r1:",
            r"keyattr:2:18:brainpoolP384r1:",
            r"keyattr:3:19:brainpoolP384r1:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
        ),
        KeyType::BrainpoolP384R1NoAut => (
            r"keyattr:1:19:brainpoolP384r1:",
            r"keyattr:2:18:brainpoolP384r1:",
            r"keyattr:3:1:2048:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}::",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0]{40}:",
        ),
        KeyType::BrainpoolP512R1 => (
            r"keyattr:1:19:brainpoolP512r1:",
            r"keyattr:2:18:brainpoolP512r1:",
            r"keyattr:3:19:brainpoolP512r1:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
        ),
        KeyType::BrainpoolP512R1NoAut => (
            r"keyattr:1:19:brainpoolP512r1:",
            r"keyattr:2:18:brainpoolP512r1:",
            r"keyattr:3:1:2048:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}::",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0]{40}:",
        ),
        KeyType::Secp256k1 => (
            r"keyattr:1:19:secp256k1:",
            r"keyattr:2:18:secp256k1:",
            r"keyattr:3:19:secp256k1:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
        ),
        KeyType::Secp256k1NoAut => (
            r"keyattr:1:19:secp256k1:",
            r"keyattr:2:18:secp256k1:",
            r"keyattr:3:1:2048:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}::",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0]{40}:",
        ),
        KeyType::Rsa2048 => (
            r"keyattr:1:1:2048:",
            r"keyattr:2:1:2048:",
            r"keyattr:3:1:2048:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
        ),
        KeyType::Rsa3072 => (
            r"keyattr:1:1:3072:",
            r"keyattr:2:1:3072:",
            r"keyattr:3:1:3072:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
        ),
        KeyType::Rsa4096 => (
            r"keyattr:1:1:4096:",
            r"keyattr:2:1:4096:",
            r"keyattr:3:1:4096:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:",
        ),
        KeyType::Rsa2048NoAut => (
            r"keyattr:1:1:2048:",
            r"keyattr:2:1:2048:",
            r"keyattr:3:1:2048:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}::",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0]{40}:",
        ),
        KeyType::Rsa3072NoAut => (
            r"keyattr:1:1:3072:",
            r"keyattr:2:1:3072:",
            r"keyattr:3:1:2048:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}::",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0]{40}:",
        ),
        KeyType::Rsa4096NoAut => (
            r"keyattr:1:1:4096:",
            r"keyattr:2:1:4096:",
            r"keyattr:3:1:2048:",
            "fpr:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}::",
            "grp:[0-9a-zA-Z]{40}:[0-9a-zA-Z]{40}:[0]{40}:",
        ),
        KeyType::RsaNone => (
            r"keyattr:1:1:2048:",
            r"keyattr:2:1:2048:",
            r"keyattr:3:1:2048:",
            "fpr::::",
            "grp:[0]{40}:[0]{40}:[0]{40}:",
        ),
    };
    // FIXME: This seems bad, but still less noisy than using `String` and adding `.to_string()` everywhere
    let signcount = match sign_count {
        0 => r"sigcount:0:::",
        1 => r"sigcount:1:::",
        2 => r"sigcount:2:::",
        3 => r"sigcount:3:::",
        4 => r"sigcount:4:::",
        5 => r"sigcount:5:::",
        6 => r"sigcount:6:::",
        7 => r"sigcount:7:::",
        8 => r"sigcount:8:::",
        9 => r"sigcount:9:::",
        _ => todo!(),
    };

    let fprtimes = r"fprtime:\d*:\d*:\d*:";
    #[cfg(feature = "vpicc")]
    let reader = r"Reader:Virtual PCD \d\d \d\d:AID:D276000124010304[A-Z0-9]*:openpgp-card";
    #[cfg(feature = "dangerous-test-real-card")]
    let reader = concat!(
        "Reader:",
        "((",
        // ID for the internal ccid driver
        env!("OPCARD_DANGEROUS_TEST_CARD_USB_VENDOR"),
        ":",
        env!("OPCARD_DANGEROUS_TEST_CARD_USB_PRODUCT"),
        ":X:0",
        ")|(",
        // ID for the pcscd driver
        r"(Nitrokey ){1,2}3 \[CCID/ICCD Interface\] \d\d \d\d",
        "))",
        ":AID:",
        // AID
        "D276000124010304",
        env!("OPCARD_DANGEROUS_TEST_CARD_PGP_VENDOR"),
        env!("OPCARD_DANGEROUS_TEST_CARD_PGP_SERIAL"),
        "0000",
        ":openpgp-card:",
    );

    [
        reader,
        r"version:0304",
        r"vendor:[a-zA-Z0-9]{4}:.*:",
        r"serial:[a-zA-Z0-9]*:",
        r"name:::",
        r"lang::",
        r"sex:u:",
        r"url::",
        r"login::",
        r"forcepin:1:::",
        first,
        sec,
        third,
        r"maxpinlen:127:127:127:",
        r"pinretry:3:0:3:",
        signcount,
        r"kdf:off:",
        r"uif:0:0:0",
        r"cafpr::::",
        fpr,
        fprtimes,
        grp,
    ]
    .into()
}

#[allow(unused)]
pub fn gpg_inquire_pin() -> Vec<&'static str> {
    [
        r"\[GNUPG:\] INQUIRE_MAXLEN 100",
        r"\[GNUPG:\] GET_HIDDEN passphrase.enter",
    ]
    .into()
}

#[allow(unused)]
pub enum GpgCommand<'a> {
    EditCard,
    CardStatus,
    Encrypt { r: &'a str, i: &'a str, o: &'a str },
    Decrypt { i: &'a str, o: &'a str },
    Sign { i: &'a str, s: &'a str, o: &'a str },
    Verify { i: &'a str },
    Generate,
    EditKey { o: &'a str },
    DeleteSecretKey { o: &'a str },
}

impl GpgCommand<'_> {
    fn command(&self, ctx: &Context) -> Command {
        let mut cmd = Command::new("gpg");
        cmd.args([
            "--command-fd=0",
            "--status-fd=1",
            "--with-colons",
            "--pinentry-mode",
            "loopback",
            "--expert",
            "--no-tty",
            "--no-default-keyring",
        ])
        .arg("--keyring")
        .arg(ctx.keyring())
        .arg("--trustdb")
        .arg(ctx.trustdb())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped());
        match self {
            GpgCommand::EditCard => cmd.arg("--edit-card"),
            GpgCommand::CardStatus => cmd.arg("--card-status"),
            GpgCommand::Encrypt { i, o, r } => {
                cmd.args(["--encrypt", "--output", o, "--recipient", r, i])
            }
            GpgCommand::Decrypt { i, o } => cmd.args(["--decrypt", "--output", o, i]),
            GpgCommand::Sign { i, s, o } => {
                cmd.args(["--sign", "--output", o, "--default-key", s, i])
            }
            GpgCommand::Verify { i } => cmd.args(["--verify", i]),
            GpgCommand::Generate => cmd.args(["--full-gen-key"]),
            GpgCommand::EditKey { o } => cmd.args(["--edit-key", o]),
            GpgCommand::DeleteSecretKey { o } => cmd.args(["--yes", "--delete-secret-keys", o]),
        };
        cmd
    }
}

/// Takes an array of strings that will be passed as input to `gpg --command-fd=0 --status-fd=1 --pinentry-mode loopback --card-edit`
/// and an array of Regex over the output
#[allow(unused)]
pub fn gnupg_test(
    stdin: &[&str],
    stdout: &[&str],
    stderr: &[&str],
    cmd: GpgCommand,
    ctx: &Context,
) {
    let out_re: Vec<Regex> = stdout.iter().map(|s| Regex::new(s).unwrap()).collect();
    let err_re: Vec<Regex> = stderr.iter().map(|s| Regex::new(s).unwrap()).collect();
    let mut gpg = cmd
        .command(ctx)
        .spawn()
        .expect("failed to run gpg --card-status");
    let mut gpg_in = gpg.stdin.take().unwrap();
    let mut gpg_out = gpg.stdout.take().unwrap();
    let mut gpg_err = gpg.stderr.take().unwrap();

    let out_handle = thread::spawn(move || {
        let mut panic_message = None;
        let filter = RegexSet::new(STDOUT_FILTER).unwrap();
        let mut regexes = out_re.into_iter().enumerate();
        let o = BufReader::new(gpg_out);
        for l in o.lines().map(|r| r.unwrap()) {
            println!("STDOUT: {l}");

            if filter.is_match(&l) {
                continue;
            }
            match regexes.next() {
                Some((id, re)) if !re.is_match(&l) => panic_message.get_or_insert_with(|| {
                    let tmp = format!(r#"Expected in stdout {id}: "{re}", got: "{l}""#);
                    println!("FAILED HERE: {tmp}");
                    tmp
                }),
                None => panic_message.get_or_insert_with(|| {
                    let tmp = format!(r#"Expected in stdout: EOL, got: "{l}"#);
                    println!("FAILED HERE: {tmp}");
                    tmp
                }),
                _ => continue,
            };
        }
        if let Some((id, re)) = regexes.next() {
            panic!(r#"Expected in stdout {id}: "{re}", got EOL"#);
        }

        if let Some(m) = panic_message {
            panic!("{m}");
        }
    });

    let err_handle = thread::spawn(move || {
        let mut panic_message = None;
        let filter = RegexSet::new(STDERR_FILTER).unwrap();
        let mut regexes = err_re.into_iter();
        let o = BufReader::new(gpg_err);
        for l in o.lines().map(|r| r.unwrap()) {
            println!("STDERR: {l}");

            if filter.is_match(&l) || l.is_empty() {
                continue;
            }

            match regexes.next() {
                Some(re) if !re.is_match(&l) => panic_message
                    .get_or_insert_with(|| format!(r#"Expected in stderr: "{re}", got: "{l}""#)),
                None => panic_message
                    .get_or_insert_with(|| format!(r#"Expected in stderr: EOL, got: "{l}""#)),
                _ => continue,
            };
        }
        if let Some(re) = regexes.next() {
            panic!(r#"Expected in stderr: "{re}", got EOL"#);
        }

        if let Some(m) = panic_message {
            panic!("{m}");
        }
    });

    for l in stdin {
        println!("STDIN: {l}");
        writeln!(gpg_in, "{l}").unwrap();
        gpg_in.flush().unwrap();
    }
    drop(gpg_in);
    let gpg_ret_code = gpg.wait().unwrap();
    if !gpg_ret_code.success() {
        panic!("Gpg failed with error code {gpg_ret_code}");
    }

    out_handle.join().unwrap();
    err_handle.join().unwrap();
}

fn attr_ec_ask() -> Vec<&'static str> {
    iter::repeat(
        [
            r"\[GNUPG:\] GET_LINE cardedit.genkeys.algo",
            r"\[GNUPG:\] GET_LINE keygen.curve",
        ]
        .into_iter()
        .chain(gpg_inquire_pin()),
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
        .chain(gpg_inquire_pin()),
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

#[allow(unused)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgo {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Cv25519,
    P256,
    P384,
    P521,
    BrainpoolP256R1,
    BrainpoolP384R1,
    BrainpoolP512R1,
    Secp256k1,
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
            Self::BrainpoolP256R1 => Self::_generate_for_key("2", "6", temp_name, temp_email),
            Self::BrainpoolP384R1 => Self::_generate_for_key("2", "7", temp_name, temp_email),
            Self::BrainpoolP512R1 => Self::_generate_for_key("2", "8", temp_name, temp_email),
            Self::Secp256k1 => Self::_generate_for_key("2", "9", temp_name, temp_email),
        }
    }

    fn generate_for_host<'a>(self, temp_name: &'a str, temp_email: &'a str) -> Vec<&'a str> {
        match self {
            Self::Rsa2048 => vec![
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
            Self::Rsa3072 => vec![
                "1",
                "3072",
                "3072",
                "0",
                temp_name,
                temp_email,
                "no comment",
                "",
                "",
            ],
            Self::Rsa4096 => vec![
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
            Self::Cv25519 => vec!["9", "1", "0", temp_name, temp_email, "no comment", "", ""],
            Self::P256 => vec!["9", "3", "0", temp_name, temp_email, "no comment", "", ""],
            Self::P384 => vec!["9", "4", "0", temp_name, temp_email, "no comment", "", ""],
            Self::P521 => vec!["9", "5", "0", temp_name, temp_email, "no comment", "", ""],
            Self::BrainpoolP256R1 => {
                vec!["9", "6", "0", temp_name, temp_email, "no comment", "", ""]
            }
            Self::BrainpoolP384R1 => {
                vec!["9", "7", "0", temp_name, temp_email, "no comment", "", ""]
            }
            Self::BrainpoolP512R1 => {
                vec!["9", "8", "0", temp_name, temp_email, "no comment", "", ""]
            }
            Self::Secp256k1 => {
                vec!["9", "9", "0", temp_name, temp_email, "no comment", "", ""]
            }
        }
    }

    fn generate_for_host_expected_prompt<'a>(self) -> Vec<&'a str> {
        if self.is_ec() {
            vec![
                r"\[GNUPG:\] GET_LINE keygen.algo",
                r"\[GNUPG:\] GET_LINE keygen.curve",
                r"\[GNUPG:\] GET_LINE keygen.valid",
                r"\[GNUPG:\] GET_LINE keygen.name",
                r"\[GNUPG:\] GET_LINE keygen.email",
                r"\[GNUPG:\] GET_LINE keygen.comment",
            ]
        } else {
            vec![
                r"\[GNUPG:\] GET_LINE keygen.algo",
                r"\[GNUPG:\] GET_LINE keygen.size",
                r"\[GNUPG:\] GET_LINE keygen.size",
                r"\[GNUPG:\] GET_LINE keygen.valid",
                r"\[GNUPG:\] GET_LINE keygen.name",
                r"\[GNUPG:\] GET_LINE keygen.email",
                r"\[GNUPG:\] GET_LINE keygen.comment",
            ]
        }
    }

    #[allow(unused)]
    fn is_ec(self) -> bool {
        match self {
            Self::Cv25519
            | Self::P256
            | Self::P384
            | Self::P521
            | Self::BrainpoolP256R1
            | Self::BrainpoolP384R1
            | Self::BrainpoolP512R1
            | Self::Secp256k1 => true,
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => false,
        }
    }

    fn algo_name_generation(self) -> &'static str {
        match self {
            Self::P256 => "nistp256:",
            Self::P384 => "nistp384:",
            Self::P521 => "nistp521:",
            Self::BrainpoolP256R1 => "brainpoolP256r1:23",
            Self::BrainpoolP384R1 => "brainpoolP384r1:23",
            Self::BrainpoolP512R1 => "brainpoolP512r1:23",
            Self::Secp256k1 => "secp256k1:",
            Self::Cv25519 => "ed25519:",
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => ":23",
        }
    }

    fn algo_name(self) -> &'static str {
        match self {
            Self::P256 => "nistp256",
            Self::P384 => "nistp384",
            Self::P521 => "nistp521",
            Self::BrainpoolP256R1 => "brainpoolP256r1",
            Self::BrainpoolP384R1 => "brainpoolP384r1",
            Self::BrainpoolP512R1 => "brainpoolP512r1",
            Self::Secp256k1 => "secp256k1",
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
            Self::BrainpoolP256R1 => "brainpoolP256r1",
            Self::BrainpoolP384R1 => "brainpoolP384r1",
            Self::BrainpoolP512R1 => "brainpoolP512r1",
            Self::Secp256k1 => "secp256k1",
            Self::Cv25519 => "cv25519",
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => ":23",
        }
    }

    fn algorithm_id_signature(self) -> &'static str {
        match self {
            Self::P256
            | Self::P384
            | Self::P521
            | Self::BrainpoolP256R1
            | Self::BrainpoolP384R1
            | Self::BrainpoolP512R1
            | Self::Secp256k1 => "19",
            Self::Cv25519 => "22",
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => "1",
        }
    }

    fn algorithm_name_signature(self) -> &'static str {
        match self {
            Self::P256
            | Self::P384
            | Self::P521
            | Self::BrainpoolP256R1
            | Self::BrainpoolP384R1
            | Self::BrainpoolP512R1
            | Self::Secp256k1 => "ECDSA",
            Self::Cv25519 => "EDDSA",
            Self::Rsa2048 => "RSA key [0-9A-F]{40}",
            Self::Rsa3072 => "RSA key [0-9A-F]{40}",
            Self::Rsa4096 => "RSA key [0-9A-F]{40}",
        }
    }

    fn algorithm_id_encryption(self) -> &'static str {
        match self {
            Self::P256
            | Self::P384
            | Self::P521
            | Self::BrainpoolP256R1
            | Self::BrainpoolP384R1
            | Self::BrainpoolP512R1
            | Self::Secp256k1 => "18",
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
            Self::Cv25519
            | Self::P256
            | Self::P384
            | Self::P521
            | Self::BrainpoolP256R1
            | Self::BrainpoolP384R1
            | Self::BrainpoolP512R1
            | Self::Secp256k1 => {
                let mut ask = attr_ec_ask();
                ask.push(r"\[GNUPG:\] GET_LINE cardedit.prompt");
                ask
            }
        }
    }

    fn keytype(self) -> KeyType {
        match self {
            Self::Rsa2048 => KeyType::Rsa2048,
            Self::Rsa3072 => KeyType::Rsa3072,
            Self::Rsa4096 => KeyType::Rsa4096,
            Self::Cv25519 => KeyType::Cv25519,
            Self::P256 => KeyType::P256,
            Self::P384 => KeyType::P384,
            Self::P521 => KeyType::P521,
            Self::BrainpoolP256R1 => KeyType::BrainpoolP256R1,
            Self::BrainpoolP384R1 => KeyType::BrainpoolP384R1,
            Self::BrainpoolP512R1 => KeyType::BrainpoolP512R1,
            Self::Secp256k1 => KeyType::Secp256k1,
        }
    }

    #[allow(unused)]
    fn keytype_no_aut(self) -> KeyType {
        match self {
            Self::Rsa2048 => KeyType::Rsa2048NoAut,
            Self::Rsa3072 => KeyType::Rsa3072NoAut,
            Self::Rsa4096 => KeyType::Rsa4096NoAut,
            Self::Cv25519 => KeyType::Cv25519NoAut,
            Self::P256 => KeyType::P256NoAut,
            Self::P384 => KeyType::P384NoAut,
            Self::P521 => KeyType::P521NoAut,
            Self::BrainpoolP256R1 => KeyType::BrainpoolP256R1NoAut,
            Self::BrainpoolP384R1 => KeyType::BrainpoolP384R1NoAut,
            Self::BrainpoolP512R1 => KeyType::BrainpoolP512R1NoAut,
            Self::Secp256k1 => KeyType::Secp256k1NoAut,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn gpg_test_common(
    algo: KeyAlgo,
    is_import: bool,
    encrypted_file: &str,
    temp_email: &str,
    temp_name: &str,
    sign_file: &str,
    decrypted_file: &str,
    ctx: &Context,
) {
    gnupg_test(
        &[],
        &[
            r"\[GNUPG:\] BEGIN_ENCRYPTION \d \d",
            r"\[GNUPG:\] END_ENCRYPTION",
        ],
        &[],
        GpgCommand::Encrypt {
            i: "Cargo.toml",
            o: encrypted_file,
            r: temp_email,
        },
        ctx,
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
            gpg_inquire_pin(),
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
        GpgCommand::Decrypt {
            i: encrypted_file,
            o: decrypted_file,
        },
        ctx,
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
            gpg_inquire_pin(),
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
        GpgCommand::Sign {
            i: "Cargo.toml",
            o: sign_file,
            s: temp_email,
        },
        ctx,
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
        GpgCommand::Verify { i: sign_file },
        ctx,
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
            gpg_status(
                if is_import {
                    algo.keytype_no_aut()
                } else {
                    algo.keytype()
                },
                if is_import { 1 } else { 5 },
            ),
            vec![
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_BOOL cardedit.factory-reset.proceed",
                r"\[GNUPG:\] GET_LINE cardedit.factory-reset.really",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
            ],
            gpg_inquire_pin(),
            gpg_status(KeyType::RsaNone, 0),
            vec![r"\[GNUPG:\] GET_LINE cardedit.prompt"],
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[
            r"gpg: OpenPGP card no. [0-9A-F]{32} detected",
            r"gpg: Note: This command destroys all keys stored on the card!",
        ],
        GpgCommand::EditCard,
        ctx,
    );
}

#[allow(unused)]
pub fn gpg_test_import(algo: KeyAlgo) {
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

    let custom_match2 = format!(
        r"uid:u::::::::{temp_name} \(no comment\) <{temp_email}>:::.*,mdc,aead,no-ks-modify:1,p::"
    );

    gnupg_test(
        &[],
        &[
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
            gpg_status(KeyType::RsaNone, 0),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        GpgCommand::CardStatus,
        &ctx,
    );

    gnupg_test(
        &algo.generate_for_host(temp_name, temp_email),
        &[
            algo.generate_for_host_expected_prompt(),
            gpg_inquire_pin(),
            gpg_inquire_pin(),
            vec![
                &format!(
                    r"{}{}{}{}::0:",
                    r"pub:u:\d*:",
                    algo.algorithm_id_signature(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}:::u:::scESC:::\+::",
                    algo.algo_name_generation(),
                ),
                r"fpr:::::::::[0-9A-F]{40}:",
                r"grp:::::::::[0-9A-F]{40}:",
                &custom_match,
                &format!(
                    "{}{}{}{}:",
                    r"sub:u:\d*:",
                    algo.algorithm_id_encryption(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}::::::e:::\+:::?",
                    algo.algo_name_generation_encryption(),
                ),
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
        GpgCommand::Generate,
        &ctx,
    );

    println!("================ FINISHED GENERATING {algo:?} KEYS ================");

    gnupg_test(
        &["key *", "keytocard", "2", DEFAULT_PW3, DEFAULT_PW3, "save"],
        &[
            vec![
                &format!(
                    "{}{}{}",
                    r"sec:u:\d*:",
                    algo.algorithm_id_signature(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc"
                ),
                r"fpr:::::::::[0-9A-F]{40}:",
                &format!(
                    "{}{}{}",
                    r"ssb:u:\d*:",
                    algo.algorithm_id_encryption(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}:0:::::e"
                ),
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                &format!(
                    "{}{}{}",
                    r"sec:u:\d*:",
                    algo.algorithm_id_signature(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc"
                ),
                r"fpr:::::::::[0-9A-F]{40}:",
                &format!(
                    "{}{}{}",
                    r"ssb:u:\d*:",
                    algo.algorithm_id_encryption(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}:0:::::e"
                ),
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-F0-9]*",
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.storekeytype",
            ],
            gpg_inquire_pin(),
            if algo == KeyAlgo::Rsa2048 {
                vec![]
            } else {
                gpg_inquire_pin()
            },
            vec![
                &format!(
                    "{}{}{}",
                    r"sec:u:\d*:",
                    algo.algorithm_id_signature(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc"
                ),
                r"fpr:::::::::[0-9A-F]{40}:",
                &format!(
                    "{}{}{}",
                    r"ssb:u:\d*:",
                    algo.algorithm_id_encryption(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}:0:::::e"
                ),
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
            ],
            if algo == KeyAlgo::Rsa2048 {
                vec![r"\[GNUPG:\] GET_LINE keyedit.prompt"]
            } else {
                vec![]
            },
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        GpgCommand::EditKey { o: temp_email },
        &ctx,
    );

    println!("================ FINISHED IMPORTING {algo:?} KEY ================");

    gnupg_test(
        &["keytocard", "y", "1", DEFAULT_PW3, "save"],
        &[
            vec![
                &format!(
                    "{}{}{}",
                    r"sec:u:\d*:",
                    algo.algorithm_id_signature(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc"
                ),
                r"fpr:::::::::[0-9A-F]{40}:",
                &format!(
                    "{}{}{}",
                    r"ssb:u:\d*:",
                    algo.algorithm_id_encryption(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}:0:::::e"
                ),
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
                r"\[GNUPG:\] GET_BOOL keyedit.keytocard.use_primary",
                r"\[GNUPG:\] CARDCTRL 3 D276000124010304[A-F0-9]*",
                r"\[GNUPG:\] GET_LINE cardedit.genkeys.storekeytype",
            ],
            if algo == KeyAlgo::Rsa2048 {
                vec![]
            } else {
                gpg_inquire_pin()
            },
            vec![
                &format!(
                    "{}{}{}",
                    r"sec:u:\d*:",
                    algo.algorithm_id_signature(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}:0::u:::sc"
                ),
                r"fpr:::::::::[0-9A-F]{40}:",
                &format!(
                    "{}{}{}",
                    r"ssb:u:\d*:",
                    algo.algorithm_id_encryption(),
                    r":[0-9A-F]{16}:[0-9A-F]{10}:0:::::e"
                ),
                r"fpr:::::::::[0-9A-F]{40}:",
                &custom_match2,
                r"\[GNUPG:\] GET_LINE keyedit.prompt",
            ],
            if algo == KeyAlgo::Rsa2048 {
                vec![r"\[GNUPG:\] GET_LINE keyedit.prompt"]
            } else {
                vec![]
            },
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<&str>>(),
        &[],
        GpgCommand::EditKey { o: temp_email },
        &ctx,
    );

    println!("================ FINISHED IMPORTING {algo:?} KEYS ================");

    gpg_test_common(
        algo,
        true,
        encrypted_file,
        temp_email,
        temp_name,
        sign_file,
        decrypted_file,
        &ctx,
    )
}

#[allow(unused)]
pub fn gpg_test(algo: KeyAlgo) {
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
            gpg_status(KeyType::RsaNone, 0),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>(),
        &[],
        GpgCommand::CardStatus,
        &ctx,
    );

    gnupg_test(
        &algo.generate_for_key(temp_name, temp_email),
        &[
            vec![r"\[GNUPG:\] CARDCTRL \d D276000124010304[A-Z0-9]*"],
            gpg_status(KeyType::RsaNone, 0),
            vec![
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
                r"\[GNUPG:\] GET_LINE cardedit.prompt",
            ],
            algo.attr_ask(),
            vec![r"\[GNUPG:\] GET_LINE cardedit.genkeys.backup_enc"],
            gpg_inquire_pin(),
            gpg_inquire_pin(),
            vec![
                r"\[GNUPG:\] GET_LINE keygen.valid",
                r"\[GNUPG:\] GET_LINE keygen.name",
                r"\[GNUPG:\] GET_LINE keygen.email",
                r"\[GNUPG:\] GET_LINE keygen.comment",
                r"\[GNUPG:\] USERID_HINT [0-9A-F]{16} \[\?\]",
                r"\[GNUPG:\] NEED_PASSPHRASE [0-9A-F]{16} [0-9A-F]{16} \d* \d",
            ],
            gpg_inquire_pin(),
            vec![
                &format!(
                    r"{}{}{}{}::0:",
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
        GpgCommand::EditCard,
        &ctx,
    );

    println!("================ FINISHED GENERATING {algo:?} ================");

    gpg_test_common(
        algo,
        false,
        encrypted_file,
        temp_email,
        temp_name,
        sign_file,
        decrypted_file,
        &ctx,
    );
}
