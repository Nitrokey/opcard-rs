// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use openpgp_card::StatusBytes;
use test_log::test;

mod card;

use card::{error_to_retries, with_card};
use opcard::{DEFAULT_ADMIN_PIN, DEFAULT_USER_PIN};

macro_rules! assert_checks {
    ($tx:expr, $sign:expr, $user:expr, $admin:expr) => {{
        let sign_expected = $sign;
        let sign_retries = error_to_retries($tx.check_pw1_sign());
        assert_eq!(
            sign_retries, sign_expected,
            "Incorrect sign retries. Expected {:?},  got {:?}",
            sign_expected, sign_retries
        );
        let user_expected = $user;
        let user_retries = error_to_retries($tx.check_pw1_user());
        assert_eq!(
            user_retries, user_expected,
            "Incorrect user retries. Expected {:?},  got {:?}",
            user_expected, user_retries
        );
        let admin_expected = $admin;
        let admin_retries = error_to_retries($tx.check_pw3());
        assert_eq!(
            admin_retries, admin_expected,
            "Incorrect admin retries. Expected {:?},  got {:?}",
            admin_expected, admin_retries
        );
    }};
}

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

            tx.set_resetting_code(&[0; 127]).unwrap();
            tx.set_resetting_code(&[0; 128]).unwrap_err();
        });
        card.reset();
        card.with_tx(|mut tx| {
            tx.reset_retry_counter_pw1(b"123456", Some(&[0; 127]))
                .unwrap();
            assert_checks!(tx, Some(3), Some(3), Some(3));
            tx.verify_pw1_user(b"123456").unwrap();
        });
        card.reset();
        card.with_tx(|mut tx| {
            assert!(tx.reset_retry_counter_pw1(b"new code", None).is_err());
            assert!(tx.verify_pw1_user(b"new code").is_err());
            assert_eq!(
                error_to_retries(tx.reset_retry_counter_pw1(b"new code", Some(b"12345678"))),
                Some(2)
            );
            let short_reset = tx.reset_retry_counter_pw1(b"short", Some(&[0; 127]));
            assert!(
                matches!(
                    short_reset,
                    Err(openpgp_card::Error::CardStatus(
                        StatusBytes::IncorrectParametersCommandDataField
                    ))
                ),
                "Got: {short_reset:?}"
            );
            assert_eq!(
                error_to_retries(tx.reset_retry_counter_pw1(b"new code", Some(b"12345678"))),
                Some(2)
            );
            assert!(tx.verify_pw1_user(b"new code").is_err());
            assert_eq!(
                error_to_retries(tx.reset_retry_counter_pw1(b"new code", Some(b"12345678"))),
                Some(1)
            );
            assert!(tx.verify_pw1_user(b"new code").is_err());
            assert_eq!(
                error_to_retries(tx.reset_retry_counter_pw1(b"new code", Some(b"12345678"))),
                Some(0)
            );
            assert!(tx.verify_pw1_user(b"new code").is_err());
            assert_eq!(
                error_to_retries(tx.reset_retry_counter_pw1(b"new code", Some(b"12345678"))),
                Some(0)
            );
            assert!(tx.verify_pw1_user(b"new code").is_err());
            tx.reset_retry_counter_pw1(b"123456", Some(b"1234567890"))
                .unwrap_err();
            assert!(tx.verify_pw1_user(b"new code").is_err());
        });
    });
}
