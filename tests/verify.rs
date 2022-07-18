// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "backend-software")]

mod card;

use card::with_tx;

use opcard::backend::virtual_platform::CARD;

#[test]
fn select() {
    with_tx(|_| ());
}

fn error_to_retries(err: Result<(), openpgp_card::Error>) -> Option<u8> {
    match err {
        Ok(()) => None,
        Err(openpgp_card::Error::CardStatus(openpgp_card::StatusBytes::PasswordNotChecked(c))) => {
            Some(c)
        }
        Err(e) => panic!("Unexpected error {e}"),
    }
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
    with_tx(|mut tx| {
        assert_checks!(tx, Some(3), Some(3), Some(3));
        assert!(tx.verify_pw1_sign(b"12345678").is_err());
        assert_checks!(tx, Some(2), Some(2), Some(3));
        assert!(tx.verify_pw1_sign(b"123456").is_ok());
        assert_checks!(tx, None, Some(3), Some(3));

        assert!(tx.verify_pw1_user(b"12345678").is_err());
        assert_checks!(tx, None, Some(2), Some(3));
        assert!(tx.verify_pw1_user(b"123456").is_ok());
        assert_checks!(tx, None, None, Some(3));

        assert!(tx.verify_pw3(b"123456").is_err());
        assert_checks!(tx, None, None, Some(2));
        assert!(tx.verify_pw3(b"12345678").is_ok());
        assert_checks!(tx, None, None, None);
    });
    CARD.lock().unwrap().reset();
    with_tx(|mut tx| {
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
    CARD.lock().unwrap().reset();
    with_tx(|mut tx| {
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
    CARD.lock().unwrap().reset();
    with_tx(|mut tx| {
        assert_checks!(tx, Some(0), Some(0), Some(0));
    });
}
