// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use openpgp_card::StatusBytes;
use test_log::test;

mod card;

use card::{error_to_retries, with_card, with_tx};

#[test]
fn select() {
    with_tx(|_| ());
}

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
fn verify() {
    with_card(|mut card| {
        card.with_tx(|mut tx| {
            assert_checks!(tx, Some(3), Some(3), Some(3));
            assert!(tx.verify_pw1_sign(b"12345678").is_err());
            assert!(tx.verify_pw1_sign(b"123456\x00").is_err());
            assert_checks!(tx, Some(1), Some(1), Some(3));
            assert!(tx.verify_pw1_sign(b"123456").is_ok());
            assert_checks!(tx, None, Some(3), Some(3));

            // Empty pwd = checking
            assert!(tx.verify_pw1_user(&[]).is_err());
            assert_checks!(tx, None, Some(3), Some(3));

            assert!(tx.verify_pw1_user(&[0]).is_err());
            assert_checks!(tx, None, Some(2), Some(3));
            assert!(tx.verify_pw1_user("ハローワールド".as_bytes()).is_err());
            assert_checks!(tx, None, Some(1), Some(3));
            assert!(tx.verify_pw1_user(b"123456").is_ok());
            assert_checks!(tx, None, None, Some(3));

            assert!(tx.verify_pw3(b"123456").is_err());
            assert_checks!(tx, None, None, Some(2));
            assert!(tx.verify_pw3(&[0; 8]).is_err());
            assert_checks!(tx, None, None, Some(1));
            assert!(tx.verify_pw3(b"12345678").is_ok());
            assert_checks!(tx, None, None, None);
        });
        card.reset();
        card.with_tx(|mut tx| {
            assert_checks!(tx, Some(3), Some(3), Some(3));
            assert!(tx.verify_pw1_sign(b"12345678").is_err());
            assert_checks!(tx, Some(2), Some(2), Some(3));
            assert!(tx.verify_pw1_user(b"12345678").is_err());
            assert_checks!(tx, Some(1), Some(1), Some(3));
            assert!(tx.verify_pw1_sign(b"12345678").is_err());
            assert_checks!(tx, Some(0), Some(0), Some(3));
            assert!(tx.verify_pw1_sign(b"12345678").is_err());
            assert_checks!(tx, Some(0), Some(0), Some(3));
            assert!(tx.verify_pw1_sign(b"123456").is_err());
            assert_checks!(tx, Some(0), Some(0), Some(3));
        });
        card.reset();
        card.with_tx(|mut tx| {
            assert_checks!(tx, Some(0), Some(0), Some(3));
            assert!(tx.verify_pw1_sign(b"123456").is_err());
            assert!(tx.verify_pw1_user(b"123456").is_err());
            assert_checks!(tx, Some(0), Some(0), Some(3));
            assert!(tx.verify_pw3(b"123456").is_err());
            assert!(tx.verify_pw3(b"123456").is_err());
            assert!(tx.verify_pw3(b"123456").is_err());
            assert_checks!(tx, Some(0), Some(0), Some(0));
            assert!(tx.verify_pw3(b"123456").is_err());
            assert_checks!(tx, Some(0), Some(0), Some(0));
            assert!(tx.verify_pw3(b"12345678").is_err());
            assert_checks!(tx, Some(0), Some(0), Some(0));
        });
        card.reset();
        card.with_tx(|mut tx| {
            assert_checks!(tx, Some(0), Some(0), Some(0));
        });
        card.with_tx(|mut tx| {
            tx.factory_reset().unwrap();
            assert_checks!(tx, Some(3), Some(3), Some(3));
            tx.verify_pw3(b"12345678").unwrap();
            tx.set_resetting_code(b"1234567890").unwrap();
            assert!(tx.verify_pw1_user(b"bad code").is_err());
            assert!(tx.verify_pw1_user(b"bad code").is_err());
            assert!(tx.verify_pw1_user(b"bad code").is_err());
            assert_checks!(tx, Some(0), Some(0), None);
            tx.reset_retry_counter_pw1(b"new code", None).unwrap();
            assert_checks!(tx, Some(3), Some(3), None);
            tx.verify_pw1_user(b"new code").unwrap();
            tx.set_resetting_code(&[0; 127]).unwrap();
            tx.set_resetting_code(&[0; 128]).unwrap_err();
        });
        card.reset();
        card.with_tx(|mut tx| {
            assert!(tx.verify_pw1_user(b"bad code").is_err());
            assert!(tx.verify_pw1_user(b"bad code").is_err());
            assert!(tx.verify_pw1_user(b"bad code").is_err());
            assert_checks!(tx, Some(0), Some(0), Some(3));
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
    })
}
