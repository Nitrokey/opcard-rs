// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(all(feature = "backend-software", feature = "virtual"))]

use std::process::Command;

use stoppable_thread::spawn;
use test_log::test;

fn with_vsc<F: Fn() -> R, R>(f: F) -> R {
    let backend = opcard::backend::SoftwareBackend::default();
    let card = opcard::Card::new(backend, opcard::Options::default());
    let virtual_card = opcard::VirtualCard::new(card);
    let mut vpicc = vpicc::SmartCard::with_card(virtual_card);

    let handle = spawn(move |stopped| {
        let mut connection = vpicc.connect();
        let mut cont = true;
        while !stopped.get() && cont {
            cont = connection.poll();
        }
        connection.shutdown();
    });

    // TODO: detect first communication instead of hardcoded sleep
    std::thread::sleep(std::time::Duration::from_millis(250));

    let result = f();

    handle.stop().join().expect("failed to join vpicc thread");
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
