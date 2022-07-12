// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(all(feature = "backend-software", feature = "virtual"))]

use std::{process::Command, sync::mpsc};

use stoppable_thread::spawn;
use test_log::test;

fn with_vsc<F: Fn() -> R, R>(f: F) -> R {
    let backend = opcard::backend::SoftwareBackend::default();
    let card = opcard::Card::new(backend, opcard::Options::default());
    let mut virtual_card = opcard::VirtualCard::new(card);
    let mut vpicc = vpicc::connect().expect("failed to connect to vpcd");

    let (tx, rx) = mpsc::channel();
    let handle = spawn(move |stopped| {
        let mut result = Ok(());
        while !stopped.get() && result.is_ok() {
            result = vpicc.poll(&mut virtual_card);
            if result.is_ok() {
                tx.send(()).expect("failed to send message");
            }
        }
        result
    });

    rx.recv().expect("failed to read message");

    let result = f();

    handle
        .stop()
        .join()
        .expect("failed to join vpicc thread")
        .expect("failed to run virtual smartcard");
    result
}

#[test]
#[ignore]
fn gpg_card_status() {
    with_vsc(|| {
        let output = Command::new("gpg")
            .arg("--card-status")
            .output()
            .expect("failed to run gpg --card-status");

        println!("=== stdout ===");
        println!("{}", String::from_utf8_lossy(&output.stdout));

        println!();

        println!("=== stderr ===");
        println!("{}", String::from_utf8_lossy(&output.stderr));

        assert!(output.status.success(), "{}", output.status);
    })
}
