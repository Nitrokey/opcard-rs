// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use openpgp_card::ocard::StatusBytes;
use test_log::test;

mod card;

use card::{error_to_retries, with_card};
use opcard::{DEFAULT_ADMIN_PIN, DEFAULT_USER_PIN};

use crate::card::secret_pin;

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
    if card::dangerous_real_card_enabled() {
        return;
    }

    with_card(|mut card| {
        card.with_tx(|mut tx| {
            assert!(tx.verify_pw1_user(secret_pin(b"bad pin")).is_err());
            assert_eq!(error_to_retries(tx.check_pw1_user()), Some(2));
            assert!(tx
                .change_pw1(secret_pin(b"bad pin"), secret_pin(b"new pin"))
                .is_err());
            assert_eq!(error_to_retries(tx.check_pw1_sign()), Some(1));
            assert!(tx.verify_pw1_user(secret_pin(DEFAULT_USER_PIN)).is_ok());
            assert!(tx.verify_pw1_sign(secret_pin(b"new pin")).is_err());
            assert_eq!(error_to_retries(tx.check_pw1_sign()), Some(2));
            // new pin too short
            assert!(tx
                .change_pw1(secret_pin(DEFAULT_USER_PIN), secret_pin(b""))
                .is_err());
            // Pin validation routine didn't run
            assert_eq!(error_to_retries(tx.check_pw1_sign()), Some(2));
            // New pin too long
            assert!(tx
                .change_pw1(secret_pin(DEFAULT_USER_PIN), secret_pin(&[55; 129]))
                .is_err());
            // The pin validation part still ran
            assert_eq!(error_to_retries(tx.check_pw1_sign()), Some(3));

            // New pin not utf8
            assert!(tx
                .change_pw1(secret_pin(DEFAULT_USER_PIN), secret_pin(&[0; 8]))
                .is_ok());
            assert!(tx
                .change_pw1(secret_pin(&[0; 8]), secret_pin(&[255; 8]))
                .is_ok());
            assert!(tx
                .change_pw1(secret_pin(&[255; 8]), secret_pin(&[]))
                .is_err());
            assert!(tx
                .change_pw1(secret_pin(&[255; 8]), secret_pin(&[1]))
                .is_err());

            let unicode = "ハローワールド".as_bytes();
            // More than 127 bytes (max supported length)
            assert!(tx
                .change_pw1(secret_pin(&[255; 8]), secret_pin(&[0xcc; 129]))
                .is_err());
            assert!(tx
                .change_pw1(secret_pin(&[255; 8]), secret_pin(&unicode[0..10]))
                .is_ok());
            assert!(tx.verify_pw1_user(secret_pin(&unicode[0..10])).is_ok());
            assert!(tx
                .change_pw1(secret_pin(&unicode[0..10]), secret_pin(b"new pin"))
                .is_ok());
            assert!(tx.verify_pw1_user(secret_pin(DEFAULT_USER_PIN)).is_err());
            assert_eq!(error_to_retries(tx.check_pw1_sign()), Some(2));
            assert!(tx.verify_pw1_user(secret_pin(b"new pin")).is_ok());
        });

        card.with_tx(|mut tx| {
            assert!(tx
                .change_pw3(secret_pin(b"bad pin2"), secret_pin(b"new pin2"))
                .is_err());
            assert_eq!(error_to_retries(tx.check_pw3()), Some(2));
            assert!(tx.verify_pw3(secret_pin(b"new pin2")).is_err());
            assert_eq!(error_to_retries(tx.check_pw3()), Some(1));
            assert!(tx
                .change_pw3(secret_pin(DEFAULT_ADMIN_PIN), secret_pin(b"new pin2"))
                .is_ok());
            assert_eq!(error_to_retries(tx.check_pw3()), Some(3));

            // Too long
            assert!(tx
                .change_pw3(secret_pin(b"bad pin2"), secret_pin(&[10; 128]))
                .is_err());
            assert_eq!(error_to_retries(tx.check_pw3()), Some(2));

            // New pin not utf8
            assert!(tx
                .change_pw3(secret_pin(b"new pin2"), secret_pin(&[10; 8]))
                .is_ok());
            assert!(tx
                .change_pw3(secret_pin(&[10; 8]), secret_pin(&[255; 8]))
                .is_ok());
            assert!(tx
                .change_pw3(secret_pin(&[255; 8]), secret_pin(&[]))
                .is_err());
            assert!(tx
                .change_pw3(secret_pin(&[255; 8]), secret_pin(&[100]))
                .is_err());

            let unicode = "😀😃😄😁😆".as_bytes();
            // More than 127 bytes (max supported length)
            assert!(tx
                .change_pw3(secret_pin(&[255; 8]), secret_pin(&[0xde; 129]))
                .is_err());
            assert!(tx
                .change_pw3(secret_pin(&[255; 8]), secret_pin(&unicode[0..13]))
                .is_ok());
            assert!(tx.verify_pw3(secret_pin(&unicode[0..13])).is_ok());
            assert!(tx
                .change_pw3(secret_pin(&unicode[0..13]), secret_pin(b"new pin2"))
                .is_ok());
            assert!(tx.verify_pw3(secret_pin(b"new pin2")).is_ok());
            assert!(tx.verify_pw3(secret_pin(DEFAULT_ADMIN_PIN)).is_err());
            assert!(tx.verify_pw3(secret_pin(b"new pin2")).is_ok());

            tx.set_resetting_code(secret_pin(&[0; 127])).unwrap();
            tx.set_resetting_code(secret_pin(&[0; 128])).unwrap_err();
        });
        card.reset();
        card.with_tx(|mut tx| {
            tx.reset_retry_counter_pw1(secret_pin(b"123456"), Some(secret_pin(&[0; 127])))
                .unwrap();
            assert_checks!(tx, Some(3), Some(3), Some(3));
            tx.verify_pw1_user(secret_pin(b"123456")).unwrap();
        });
        card.reset();
        card.with_tx(|mut tx| {
            assert!(tx
                .reset_retry_counter_pw1(secret_pin(b"new code"), None)
                .is_err());
            assert!(tx.verify_pw1_user(secret_pin(b"new code")).is_err());
            assert_eq!(
                error_to_retries(tx.reset_retry_counter_pw1(
                    secret_pin(b"new code"),
                    Some(secret_pin(b"12345678"))
                )),
                Some(2)
            );
            let short_reset =
                tx.reset_retry_counter_pw1(secret_pin(b"short"), Some(secret_pin(&[0; 127])));
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
                error_to_retries(tx.reset_retry_counter_pw1(
                    secret_pin(b"new code"),
                    Some(secret_pin(b"12345678"))
                )),
                Some(2)
            );
            assert!(tx.verify_pw1_user(secret_pin(b"new code")).is_err());
            assert_eq!(
                error_to_retries(tx.reset_retry_counter_pw1(
                    secret_pin(b"new code"),
                    Some(secret_pin(b"12345678"))
                )),
                Some(1)
            );
            assert!(tx.verify_pw1_user(secret_pin(b"new code")).is_err());
            assert_eq!(
                error_to_retries(tx.reset_retry_counter_pw1(
                    secret_pin(b"new code"),
                    Some(secret_pin(b"12345678"))
                )),
                Some(0)
            );
            assert!(tx.verify_pw1_user(secret_pin(b"new code")).is_err());
            assert_eq!(
                error_to_retries(tx.reset_retry_counter_pw1(
                    secret_pin(b"new code"),
                    Some(secret_pin(b"12345678"))
                )),
                Some(0)
            );
            assert!(tx.verify_pw1_user(secret_pin(b"new code")).is_err());
            tx.reset_retry_counter_pw1(secret_pin(b"123456"), Some(secret_pin(b"1234567890")))
                .unwrap_err();
            assert!(tx.verify_pw1_user(secret_pin(b"new code")).is_err());
        });
    });
}
