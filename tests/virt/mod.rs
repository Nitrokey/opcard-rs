// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(feature = "virtual")]

use std::{
    io::{BufRead, BufReader, Write},
    mem::drop,
    process::{Command, Stdio},
    sync::mpsc,
    thread::{self, sleep},
    time::Duration,
};

use regex::{Regex, RegexSet};
use stoppable_thread::spawn;

const STDOUT_FILTER: &[&str] = &[
    r"\[GNUPG:\] KEY_CONSIDERED [0-9A-F]{40} \d",
    r"\[GNUPG:\] GOT_IT",
];

const STDERR_FILTER: &[&str] = &[
    r"gpg: WARNING: unsafe permissions on homedir '.*'",
    r"gpg: keybox '.*' created",
    r"gpg: .*: trustdb created",
    r"gpg: key [0-9A-F]{16} marked as ultimately trusted",
    r"gpg: directory '.*/openpgp-revocs.d' created",
];

pub fn with_vsc<F: FnOnce() -> R, R>(f: F) -> R {
    let mut vpicc = vpicc::connect().expect("failed to connect to vpcd");

    let (tx, rx) = mpsc::channel();
    let handle = spawn(move |stopped| {
        trussed::virt::with_ram_client("opcard", |client| {
            let card = opcard::Card::new(client, opcard::Options::default());
            let mut virtual_card = opcard::VirtualCard::new(card);
            let mut result = Ok(());
            while !stopped.get() && result.is_ok() {
                result = vpicc.poll(&mut virtual_card);
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
pub fn gpg_status() -> Vec<&'static str> {
    [
        r"Reader:Virtual PCD \d\d \d\d:AID:D2760001240103040000000000000000:openpgp-card",
        r"version:0304",
        r"vendor:0000:test card",
        r"serial:00000000",
        r"name:::",
        r"lang::",
        r"sex:u:",
        r"url::",
        r"login::",
        r"forcepin:1:::",
        r"keyattr:1:1:2048:",
        r"keyattr:2:1:2048:",
        r"keyattr:3:1:2048:",
        r"maxpinlen:127:127:127:",
        r"pinretry:3:3:3:",
        r"sigcount:0:::",
        r"kdf:off:",
        r"cafpr::::",
        r"fpr::::",
        r"fprtime:0:0:0:",
        r"grp:0000000000000000000000000000000000000000:0000000000000000000000000000000000000000:0000000000000000000000000000000000000000:"
    ].into()
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
    Encrypt { r: &'a str, i: &'a str, o: &'a str },
    Decrypt { i: &'a str, o: &'a str },
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
            GpgCommand::Encrypt { i, o, r } => {
                cmd.args(["--encrypt", "--output", o, "--recipient", r, i])
            }
            GpgCommand::Decrypt { i, o } => cmd.args(["--decrypt", "--output", o, i]),
        };
        cmd
    }
}

/// Takes an array of strings that will be passed as input to `gpg --command-fd=0 --status-fd=1 --pinentry-mode loopback --card-edit`
/// and an array of Regex over the output
#[allow(unused)]
pub fn gnupg_test(stdin: &[&str], stdout: &[&str], stderr: &[&str], cmd: GpgCommand) {
    let out_re: Vec<Regex> = stdout.into_iter().map(|s| Regex::new(s).unwrap()).collect();
    let err_re: Vec<Regex> = stderr.into_iter().map(|s| Regex::new(s).unwrap()).collect();
    with_vsc(move || {
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

                if filter.is_match(&l) {
                    continue;
                }

                match regexes.next() {
                    Some(re) if !re.is_match(&l) => panic_message.get_or_insert_with(|| {
                        format!(r#"Expected in stderr: "{re}", got: "{l}""#)
                    }),
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
    });
}
