// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(any(feature = "vpicc", feature = "dangerous-test-real-card"))]

use std::{
    io::{BufRead, BufReader, Write},
    mem::drop,
    process::{Command, Stdio},
    thread,
};

#[cfg(feature = "vpicc")]
use std::{sync::mpsc, thread::sleep, time::Duration};

use regex::{Regex, RegexSet};

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
];

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
    let (reader, serial, vendor) = (
        r"Reader:Virtual PCD \d\d \d\d:AID:D276000124010304[A-Z0-9]*:openpgp-card",
        r"vendor:0000:test card:",
        r"serial:00000000:",
    );
    #[cfg(feature = "dangerous-test-real-card")]
    let (reader, serial, vendor) = (
        concat!(
            r"Reader:",
            env!("OPCARD_DANGEROUS_TEST_CARD_USB_VENDOR"),
            ":",
            env!("OPCARD_DANGEROUS_TEST_CARD_USB_PRODUCT"),
            ":X:0:AID:D276000124010304[A-Z0-9]*:openpgp-card"
        ),
        concat!(
            r"vendor:",
            env!("OPCARD_DANGEROUS_TEST_CARD_USB_VENDOR"),
            ":",
            env!("OPCARD_DANGEROUS_TEST_CARD_NAME"),
            ":"
        ),
        concat!(
            r"serial:",
            env!("OPCARD_DANGEROUS_TEST_CARD_USB_PRODUCT"),
            ":"
        ),
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
    fn command(&self) -> Command {
        let mut cmd = Command::new("gpg");
        cmd.args([
            "--command-fd=0",
            "--status-fd=1",
            "--with-colons",
            "--pinentry-mode",
            "loopback",
            "--expert",
            "--no-tty",
        ])
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
pub fn gnupg_test(stdin: &[&str], stdout: &[&str], stderr: &[&str], cmd: GpgCommand) {
    let out_re: Vec<Regex> = stdout.iter().map(|s| Regex::new(s).unwrap()).collect();
    let err_re: Vec<Regex> = stderr.iter().map(|s| Regex::new(s).unwrap()).collect();
    let mut gpg = cmd
        .command()
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
                    .get_or_insert_with(|| format!(r#"Expected in stderr: EOL, got: "{l}"#)),
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
