// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

mod card;

use card::{error_to_retries, with_card};
use opcard::{DEFAULT_ADMIN_PIN, DEFAULT_USER_PIN};

#[test]
fn change() {
    with_card(|mut card| {
        card.with_tx(|mut tx| {
            assert!(tx.verify_pw1_user(b"bad pin").is_err());
            assert_eq!(error_to_retries(tx.check_pw1_user()), Some(2));
            assert!(tx.change_pw1(b"bad pin", b"new pin").is_err());
            assert_eq!(error_to_retries(tx.check_pw1_sign()), Some(1));
            assert!(tx.verify_pw1_user(DEFAULT_USER_PIN).is_ok());
            assert!(tx.verify_pw1_sign(b"new pin").is_err());
            assert_eq!(error_to_retries(tx.check_pw1_sign()), Some(2));
            // new pin too short
            assert!(tx.change_pw1(DEFAULT_USER_PIN, b"").is_err());
            // Pin validation routine didn't run
            assert_eq!(error_to_retries(tx.check_pw1_sign()), Some(2));
            // New pin too long
            assert!(tx.change_pw1(DEFAULT_USER_PIN, &[55; 128]).is_err());
            // The pin validation part still ran
            assert_eq!(error_to_retries(tx.check_pw1_sign()), Some(3));

            // New pin not utf8
            assert!(tx.change_pw1(DEFAULT_USER_PIN, &[0; 8]).is_ok());
            assert!(tx.change_pw1(&[0; 8], &[255; 8]).is_ok());
            assert!(tx.change_pw1(&[255; 8], &[]).is_err());
            assert!(tx.change_pw1(&[255; 8], &[1]).is_err());

            let unicode = "ハローワールド".as_bytes();
            // More than 127 bytes (max supported length)
            assert!(tx.change_pw1(&[255; 8], &[0xcc; 128]).is_err());
            assert!(tx.change_pw1(&[255; 8], &unicode[0..10]).is_ok());
            assert!(tx.verify_pw1_user(&unicode[0..10]).is_ok());
            assert!(tx.change_pw1(&unicode[0..10], b"new pin").is_ok());
            assert!(tx.verify_pw1_user(DEFAULT_USER_PIN).is_err());
            assert_eq!(error_to_retries(tx.check_pw1_sign()), Some(2));
            assert!(tx.verify_pw1_user(b"new pin").is_ok());
        });

        card.with_tx(|mut tx| {
            assert!(tx.change_pw3(b"bad pin2", b"new pin2").is_err());
            assert_eq!(error_to_retries(tx.check_pw3()), Some(2));
            assert!(tx.verify_pw3(b"new pin2").is_err());
            assert_eq!(error_to_retries(tx.check_pw3()), Some(1));
            assert!(tx.change_pw3(DEFAULT_ADMIN_PIN, b"new pin2").is_ok());
            assert_eq!(error_to_retries(tx.check_pw3()), Some(3));

            // Too long
            assert!(tx.change_pw3(b"bad pin2", &[10; 128]).is_err());
            assert_eq!(error_to_retries(tx.check_pw3()), Some(2));

            // New pin not utf8
            assert!(tx.change_pw3(b"new pin2", &[10; 8]).is_ok());
            assert!(tx.change_pw3(&[10; 8], &[255; 8]).is_ok());
            assert!(tx.change_pw3(&[255; 8], &[]).is_err());
            assert!(tx.change_pw3(&[255; 8], &[100]).is_err());

            let unicode = "😀😃😄😁😆".as_bytes();
            // More than 127 bytes (max supported length)
            assert!(tx.change_pw3(&[255; 8], &[0xde; 128]).is_err());
            assert!(tx.change_pw3(&[255; 8], &unicode[0..13]).is_ok());
            assert!(tx.verify_pw3(&unicode[0..13]).is_ok());
            assert!(tx.change_pw3(&unicode[0..13], b"new pin2").is_ok());
            assert!(tx.verify_pw3(b"new pin2").is_ok());
            assert!(tx.verify_pw3(DEFAULT_ADMIN_PIN).is_err());
            assert!(tx.verify_pw3(b"new pin2").is_ok());
        });
    });
}
