// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(feature = "vpicc")]

mod virt;

use std::process::Command;

use regex::Regex;
use test_log::test;

#[test]
fn gpg_card_status() {
    let status_regex = Regex::new(
        "\
            Reader ...........: Virtual PCD \\d\\d \\d\\d\n\
            Application ID ...: D276000124010304[A-Z0-9]*\n\
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
            PIN retry counter : 3 0 3\n\
            Signature counter : 0\n\
            KDF setting ......: off\n\
            Signature key ....: \\[none\\]\n\
            Encryption key....: \\[none\\]\n\
            Authentication key: \\[none\\]\n\
            General key info..: \\[none\\]\n\
        ",
    )
    .expect("failed to compile regex");

    virt::with_vsc(|| {
        let output = Command::new("gpg")
            .arg("--card-status")
            .output()
            .expect("failed to run gpg --card-status");

        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("=== stdout ===");
        println!("{stdout}");
        println!("=== end stdout ===");

        println!();

        println!("=== stderr ===");
        println!("{}", String::from_utf8_lossy(&output.stderr));
        println!("=== end stderr ===");

        assert!(output.status.success(), "{}", output.status);

        assert!(status_regex.is_match(&stdout), "{}", stdout);
    });
}
