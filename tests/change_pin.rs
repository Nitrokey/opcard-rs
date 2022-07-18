// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "backend-software")]

mod card;

use card::{error_to_retries, with_tx};

#[test]
fn change() {
    with_tx(|mut tx| {
        assert!(tx.verify_pw1_user(b"12345678").is_err());
        assert_eq!(error_to_retries(tx.check_pw1_user()), Some(2));
        assert!(tx.change_pw1(b"12345678", b"654321").is_err());
        assert_eq!(error_to_retries(tx.check_pw1_sign()), Some(1));
        assert!(tx.verify_pw1_user(b"654321").is_err());
        assert_eq!(error_to_retries(tx.check_pw1_sign()), Some(2));
        assert!(tx.verify_pw1_user(b"123456").is_ok());
        assert!(tx.verify_pw1_sign(b"654321").is_err());
        assert_eq!(error_to_retries(tx.check_pw1_sign()), Some(2));
        assert!(tx.change_pw1(b"123456", b"654321").is_ok());
        assert!(tx.verify_pw1_user(b"123456").is_err());
        assert_eq!(error_to_retries(tx.check_pw1_sign()), Some(2));
        assert!(tx.verify_pw1_user(b"654321").is_ok());
    });

    with_tx(|mut tx| {
        assert!(tx.verify_pw3(b"123456").is_err());
        assert_eq!(error_to_retries(tx.check_pw3()), Some(2));
        assert!(tx.change_pw1(b"123456", b"87654321").is_err());
        assert_eq!(error_to_retries(tx.check_pw3()), Some(1));
        assert!(tx.verify_pw3(b"87654321").is_err());
        assert!(tx.verify_pw3(b"12345678").is_ok());
        assert!(tx.verify_pw3(b"87654321").is_err());
        assert!(tx.change_pw1(b"12345678", b"87654321").is_ok());
        assert!(tx.verify_pw3(b"12345678").is_err());
        assert!(tx.verify_pw3(b"87654321").is_ok());
    });
}
