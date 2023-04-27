// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(all(feature = "virt", not(feature = "dangerous-test-real-card")))]

use hex_literal::hex;
mod card;
use test_log::test;

use card::{with_many_tx, with_tx_options};

use opcard::Options;

use openpgp_card::{
    card_do::{ApplicationIdentifier, HistoricalBytes, Lang, Sex, TouchPolicy},
    OpenPgpTransaction,
};

#[test]
fn get_data() {
    let mut options = Options::default();
    options.button_available = false;
    with_tx_options(options.clone(), |mut tx| {
        let appdata = tx.application_related_data().unwrap();
        assert!(appdata.uif_pso_cds().unwrap().is_none());
        assert!(appdata.uif_pso_dec().unwrap().is_none());
        assert!(appdata.uif_pso_aut().unwrap().is_none());
    });
    options.button_available = true;
    with_tx_options(options, |mut tx| {
        assert!(tx.verify_pw3(b"12345678").is_ok());
        tx.set_lang(&[Lang::Value(*b"en")]).unwrap();
        tx.set_sex(Sex::NotApplicable).unwrap();
        tx.set_url(b"This is an URL").unwrap();
        tx.set_name(b"This is a name").unwrap();
        tx.set_cardholder_certificate(vec![1; 127]).unwrap();
        tx.set_ca_fingerprint_1([1u8; 20].into()).unwrap();
        assert_eq!(tx.url().unwrap(), b"This is an URL");
        let appdata = tx.application_related_data().unwrap();
        assert_eq!(
            appdata.application_id().unwrap(),
            ApplicationIdentifier::try_from(
                hex!("D2 76 00 01 24 01 03 04 00 00 00 00 00 00 00 00").as_slice(),
            )
            .unwrap()
        );
        assert_eq!(
            appdata.historical_bytes().unwrap(),
            HistoricalBytes::try_from(hex!("0031F573C00160059000").as_slice()).unwrap()
        );

        let uif_cds = appdata.uif_pso_cds().unwrap().unwrap();
        assert_eq!(uif_cds.touch_policy(), TouchPolicy::Off);
        assert_eq!(format!("{}", uif_cds.features()), "Button");

        let uif_dec = appdata.uif_pso_dec().unwrap().unwrap();
        assert_eq!(uif_dec.touch_policy(), TouchPolicy::Off);
        assert_eq!(format!("{}", uif_dec.features()), "Button");

        let mut uif_aut = appdata.uif_pso_aut().unwrap().unwrap();
        assert_eq!(uif_aut.touch_policy(), TouchPolicy::Off);
        assert_eq!(format!("{}", uif_aut.features()), "Button");

        let mut pw_status_bytes = appdata.pw_status_bytes().unwrap();
        assert!(pw_status_bytes.pw1_cds_valid_once());

        let holderdata = tx.cardholder_related_data().unwrap();
        assert_eq!(holderdata.name().unwrap(), b"This is a name".as_slice());
        assert_eq!(holderdata.sex().unwrap(), Sex::NotApplicable);
        assert_eq!(holderdata.lang().unwrap(), &[Lang::Value(*b"en")]);

        let cardholder_cert = tx.cardholder_certificate().unwrap();
        assert_eq!(cardholder_cert, &[1; 127]);

        uif_aut.set_touch_policy(TouchPolicy::On);
        tx.set_uif_pso_cds(&uif_aut).unwrap();
        tx.set_uif_pso_dec(&uif_aut).unwrap();
        tx.set_uif_pso_aut(&uif_aut).unwrap();
        pw_status_bytes.set_pw1_cds_valid_once(false);
        tx.set_pw_status_bytes(&pw_status_bytes, false).unwrap();
        tx.set_pw_status_bytes(&pw_status_bytes, true).unwrap();

        let appdata = tx.application_related_data().unwrap();
        let uif_cds = appdata.uif_pso_cds().unwrap().unwrap();
        assert_eq!(uif_cds.touch_policy(), TouchPolicy::On);
        assert_eq!(format!("{}", uif_cds.features()), "Button");

        let uif_dec = appdata.uif_pso_dec().unwrap().unwrap();
        assert_eq!(uif_dec.touch_policy(), TouchPolicy::On);
        assert_eq!(format!("{}", uif_dec.features()), "Button");

        let mut uif_aut = appdata.uif_pso_aut().unwrap().unwrap();
        assert_eq!(uif_aut.touch_policy(), TouchPolicy::On);
        assert_eq!(format!("{}", uif_aut.features()), "Button");

        let pw_status_bytes = appdata.pw_status_bytes().unwrap();
        assert!(!pw_status_bytes.pw1_cds_valid_once());

        uif_aut.set_touch_policy(TouchPolicy::Fixed);
        tx.set_uif_pso_cds(&uif_aut).unwrap();
        tx.set_uif_pso_dec(&uif_aut).unwrap();
        tx.set_uif_pso_aut(&uif_aut).unwrap();
        uif_aut.set_touch_policy(TouchPolicy::On);
        tx.set_uif_pso_cds(&uif_aut).unwrap_err();
        tx.set_uif_pso_dec(&uif_aut).unwrap_err();
        tx.set_uif_pso_aut(&uif_aut).unwrap_err();

        let appdata = tx.application_related_data().unwrap();
        let uif_cds = appdata.uif_pso_cds().unwrap().unwrap();
        assert_eq!(uif_cds.touch_policy(), TouchPolicy::Fixed);

        let uif_dec = appdata.uif_pso_dec().unwrap().unwrap();
        assert_eq!(uif_dec.touch_policy(), TouchPolicy::Fixed);

        let uif_aut = appdata.uif_pso_aut().unwrap().unwrap();
        assert_eq!(uif_aut.touch_policy(), TouchPolicy::Fixed);

        for i in 0..3 {
            tx.select_data(i, &[0x7f, 0x21], false).unwrap();
            tx.set_cardholder_certificate(vec![i; 4096]).unwrap();
        }

        tx.select_data(0, &[0x7f, 0x21], false).unwrap();
        assert_eq!(tx.cardholder_certificate().unwrap(), [0; 4096].as_slice());
        assert_eq!(
            tx.next_cardholder_certificate().unwrap(),
            [1; 4096].as_slice()
        );
        assert_eq!(
            tx.next_cardholder_certificate().unwrap(),
            [2; 4096].as_slice()
        );

        for i in 0..3 {
            tx.select_data(i, &[0x7f, 0x21], false).unwrap();
            assert_eq!(tx.cardholder_certificate().unwrap(), [i; 4096].as_slice());
        }
    });
}

#[test]
fn arbitrary() {
    with_many_tx([|mut tx: OpenPgpTransaction<'_>| {
        assert_eq!(tx.private_use_do(1).unwrap(), b"");
        assert_eq!(tx.private_use_do(2).unwrap(), b"");
        assert!(tx.private_use_do(3).is_err());
        assert!(tx.private_use_do(4).is_err());
        tx.verify_pw3(b"12345678").unwrap();
        assert!(tx.private_use_do(3).is_err());
        assert_eq!(tx.private_use_do(4).unwrap(), b"");
        tx.set_private_use_do(2, b"private use 2".to_vec()).unwrap();
        assert_eq!(tx.private_use_do(2).unwrap(), b"private use 2");
        tx.set_private_use_do(4, b"private use 4".to_vec()).unwrap();
        assert_eq!(tx.private_use_do(4).unwrap(), b"private use 4");

        // Check that password change doesn't prevent reading
        tx.change_pw3(b"12345678", b"new admin pin").unwrap();
        tx.verify_pw3(b"new admin pin").unwrap();
        assert_eq!(tx.private_use_do(2).unwrap(), b"private use 2");
        assert_eq!(tx.private_use_do(4).unwrap(), b"private use 4");
    }]);
    with_many_tx([
        |mut tx: OpenPgpTransaction<'_>| {
            assert_eq!(tx.private_use_do(1).unwrap(), b"");
            assert_eq!(tx.private_use_do(2).unwrap(), b"");
            assert!(tx.private_use_do(3).is_err());
            assert!(tx.private_use_do(4).is_err());
            tx.verify_pw1_user(b"123456").unwrap();
            assert_eq!(tx.private_use_do(3).unwrap(), b"");
            assert!(tx.private_use_do(4).is_err());
            tx.set_private_use_do(1, b"private use 1".to_vec()).unwrap();
            assert_eq!(tx.private_use_do(1).unwrap(), b"private use 1");
            tx.set_private_use_do(3, b"private use 3".to_vec()).unwrap();
            assert_eq!(tx.private_use_do(3).unwrap(), b"private use 3");

            // Check that password change doesn't prevent reading
            tx.change_pw1(b"123456", b"new user pin").unwrap();
            tx.verify_pw1_user(b"new user pin").unwrap();
            assert_eq!(tx.private_use_do(1).unwrap(), b"private use 1");
            assert_eq!(tx.private_use_do(3).unwrap(), b"private use 3");

            // Check that password reset code use doesn't prevent reading

            tx.verify_pw3(b"12345678").unwrap();
            tx.reset_retry_counter_pw1(b"pin from PW3", None).unwrap();
            tx.set_resetting_code(b"reseting code").unwrap();
        },
        |mut tx: OpenPgpTransaction<'_>| {
            tx.verify_pw1_user(b"pin from PW3").unwrap();
            assert_eq!(tx.private_use_do(1).unwrap(), b"private use 1");
            assert_eq!(tx.private_use_do(3).unwrap(), b"private use 3");
        },
        |mut tx: OpenPgpTransaction<'_>| {
            tx.reset_retry_counter_pw1(b"pin from RC", Some(b"reseting code"))
                .unwrap();
            tx.verify_pw1_user(b"pin from RC").unwrap();
            assert_eq!(tx.private_use_do(1).unwrap(), b"private use 1");
            assert_eq!(tx.private_use_do(3).unwrap(), b"private use 3");

            tx.change_pw3(b"12345678", b"changed admin pin").unwrap();
            tx.verify_pw3(b"changed admin pin").unwrap();
            tx.reset_retry_counter_pw1(b"pin from changed PW3", None)
                .unwrap();
            tx.set_resetting_code(b"reseting code with changed PW3")
                .unwrap();
        },
        |mut tx: OpenPgpTransaction<'_>| {
            tx.verify_pw1_user(b"pin from changed PW3").unwrap();
            assert_eq!(tx.private_use_do(1).unwrap(), b"private use 1");
            assert_eq!(tx.private_use_do(3).unwrap(), b"private use 3");
        },
        |mut tx: OpenPgpTransaction<'_>| {
            tx.reset_retry_counter_pw1(
                b"pin from RC with changed PW3",
                Some(b"reseting code with changed PW3"),
            )
            .unwrap();
            tx.verify_pw1_user(b"pin from RC with changed PW3").unwrap();
            assert_eq!(tx.private_use_do(1).unwrap(), b"private use 1");
            assert_eq!(tx.private_use_do(3).unwrap(), b"private use 3");
        },
    ]);
}
