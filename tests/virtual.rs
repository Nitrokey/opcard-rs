// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(feature = "virtual")]

mod vpicc;

use std::{
    io::{BufRead, BufReader, Read, Write},
    mem::drop,
    process::{Command, Stdio},
    sync::mpsc,
    thread::sleep,
    time::Duration,
};

use regex::Regex;
use stoppable_thread::spawn;
use test_log::test;

#[test]
fn gpg_card_status() {
    let status_regex = Regex::new(
        "\
            Reader ...........: Virtual PCD \\d\\d \\d\\d\n\
            Application ID ...: D2760001240103040000000000000000\n\
            Application type .: OpenPGP\n\
            Version ..........: 3.4\n\
            Manufacturer .....: test card\n\
            Serial number ....: 00000000\n\
            Name of cardholder: \\[not set\\]\n\
            Language prefs ...: \\[not set]\n\
            Salutation .......: \n\
            URL of public key : \\[not set\\]\n\
            Login data .......: \\[not set\\]\n\
            Signature PIN ....: forced\n\
            Key attributes ...: rsa2048 rsa2048 rsa2048\n\
            Max. PIN lengths .: 127 127 127\n\
            PIN retry counter : 3 3 3\n\
            Signature counter : 0\n\
            KDF setting ......: off\n\
            Signature key ....: \\[none\\]\n\
            Encryption key....: \\[none\\]\n\
            Authentication key: \\[none\\]\n\
            General key info..: \\[none\\]\n\
        ",
    )
    .expect("failed to compile regex");

    vpicc::with_vsc(|| {
        let output = Command::new("gpg")
            .arg("--card-status")
            .output()
            .expect("failed to run gpg --card-status");

        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("=== stdout ===");
        println!("{}", stdout);
        println!("=== end stdout ===");

        println!();

        println!("=== stderr ===");
        println!("{}", String::from_utf8_lossy(&output.stderr));
        println!("=== end stderr ===");

        assert!(output.status.success(), "{}", output.status);

        assert!(status_regex.is_match(&stdout), "{}", stdout);
    });

    vpicc::with_vsc(|| {
        let mut gpg = Command::new("gpg")
            .arg("--command-fd=0")
            .arg("--status-fd=1")
            .arg("--pinentry-mode")
            .arg("loopback")
            .arg("--card-edit")
            .stdout(Stdio::piped())
            //.stderr(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
            .expect("failed to run gpg --card-status");
        let mut gpg_in = gpg.stdin.take().unwrap();
        let _gpg_out = gpg.stdout.take().unwrap();
        //let mut gpg_err = gpg.stderr.take().unwrap();
        writeln!(gpg_in, "quit\n").unwrap();
        //assert!(status_regex.is_match(status), "{status}")
    });
}
