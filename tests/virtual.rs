// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(feature = "virtual")]

use std::{process::Command, sync::mpsc, thread::sleep, time::Duration};

use regex::Regex;
use stoppable_thread::spawn;
use test_log::test;

fn with_vsc<F: Fn() -> R, R>(f: F) -> R {
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

#[test]
fn gpg_card_status() {
    with_vsc(|| {
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

        let re = Regex::new(
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
                Key attributes ...: ed25519 cv25519 cv25519\n\
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

        assert!(re.is_match(&stdout), "{}", stdout);
    })
}
