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

use regex::Regex;
use stoppable_thread::spawn;

const KEY_CONSIDERED_FILTER: &str = r"\[GNUPG:\] KEY_CONSIDERED [0-9A-Z]{40} \d";

pub fn with_vsc<F: FnOnce() -> R, R>(f: F) -> R {
    let mut vpicc = vpicc::connect().expect("failed to connect to vpcd");

    let (tx, rx) = mpsc::channel();
    let handle = spawn(move |stopped| {
        trussed::virt::with_ram_client("opcard", |client| {
            let card = opcard::Card::new(
                opcard::backend::Backend::new(client),
                opcard::Options::default(),
            );
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

    sleep(Duration::from_millis(100));

    let result = f();

    handle
        .stop()
        .join()
        .expect("failed to join vpicc thread")
        .expect("failed to run virtual smartcard");
    result
}

#[allow(unused)]
pub fn gpg_status() -> impl Iterator<Item = &'static str> {
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
    ].into_iter()
}

#[allow(unused)]
pub fn gpg_inquire_pin() -> impl Iterator<Item = &'static str> {
    [
        r"\[GNUPG:\] INQUIRE_MAXLEN 100",
        r"\[GNUPG:\] GET_HIDDEN passphrase.enter",
        r"\[GNUPG:\] GOT_IT",
    ]
    .into_iter()
}

/// Takes an array of strings that will be passed as input to `gpg --command-fd=0 --status-fd=1 --pinentry-mode loopback --card-edit`
/// and an array of Regex over the output
#[allow(unused)]
pub fn gnupg_test(
    stdin: &[&str],
    stdout: impl IntoIterator<Item = &'static str>,
    stderr: impl IntoIterator<Item = &'static str>,
) {
    let out_re: Vec<Regex> = stdout.into_iter().map(|s| Regex::new(s).unwrap()).collect();
    let err_re: Vec<Regex> = stderr.into_iter().map(|s| Regex::new(s).unwrap()).collect();
    with_vsc(move || {
        let mut gpg = Command::new("gpg")
            .arg("--command-fd=0")
            .arg("--status-fd=1")
            .arg("--with-colons")
            .arg("--pinentry-mode")
            .arg("loopback")
            .arg("--expert")
            .arg("--card-edit")
            .arg("--no-tty")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
            .expect("failed to run gpg --card-status");
        let mut gpg_in = gpg.stdin.take().unwrap();
        let mut gpg_out = gpg.stdout.take().unwrap();
        let mut gpg_err = gpg.stderr.take().unwrap();

        let out_handle = thread::spawn(move || {
            let mut panic_message = None;
            let key_considered = Regex::new(KEY_CONSIDERED_FILTER).unwrap();
            let mut regexes = out_re.into_iter();
            let o = BufReader::new(gpg_out);
            for l in o.lines().map(|r| r.unwrap()) {
                println!("STDOUT: {l}");

                // KEY_CONSIDERED statuses are variable
                if key_considered.is_match(&l) {
                    continue;
                }
                match regexes.next() {
                    Some(re) if !re.is_match(&l) => panic_message.get_or_insert_with(|| {
                        format!(r#"Expected in stdout: "{re}", got: "{l}""#)
                    }),
                    None => panic_message
                        .get_or_insert_with(|| format!(r#"Expected in stdout: EOL, got: "{l}"#)),
                    _ => continue,
                };
            }
            if let Some(re) = regexes.next() {
                panic!(r#"Expected in stdout: "{re}", got EOL"#);
            }

            if let Some(m) = panic_message {
                panic!("{m}");
            }
        });

        let err_handle = thread::spawn(move || {
            let mut panic_message = None;
            let mut regexes = err_re.into_iter();
            let o = BufReader::new(gpg_err);
            for l in o.lines().map(|r| r.unwrap()) {
                println!("STDERR: {l}");
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
