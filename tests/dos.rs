// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
use hex_literal::hex;
mod card;
use test_log::test;

use card::with_tx_options;

use opcard::Options;

use openpgp_card::card_do::{ApplicationIdentifier, Lang, Sex, TouchPolicy};

#[test]
fn historical_bytes() {
    let mut options = Options::default();
    options.chaining_supported = true;
    options.extended_len_supported = false;
    with_tx_options(options, |mut tx| {
        let appdata = tx.application_related_data().unwrap();
        let historical_bytes = appdata.historical_bytes().unwrap();
        assert!(historical_bytes
            .card_capabilities()
            .unwrap()
            .command_chaining());
        assert!(!historical_bytes
            .card_capabilities()
            .unwrap()
            .extended_length_information());
        assert!(historical_bytes
            .card_capabilities()
            .unwrap()
            .extended_lc_le());
    });
    options.chaining_supported = false;
    options.extended_len_supported = true;
    with_tx_options(options, |mut tx| {
        let appdata = tx.application_related_data().unwrap();
        let historical_bytes = appdata.historical_bytes().unwrap();
        assert!(!historical_bytes
            .card_capabilities()
            .unwrap()
            .command_chaining());
        assert!(historical_bytes
            .card_capabilities()
            .unwrap()
            .extended_length_information());
        assert!(historical_bytes
            .card_capabilities()
            .unwrap()
            .extended_lc_le());
    });
    options.chaining_supported = false;
    options.extended_len_supported = false;
    with_tx_options(options, |mut tx| {
        let appdata = tx.application_related_data().unwrap();
        let historical_bytes = appdata.historical_bytes().unwrap();
        assert!(!historical_bytes
            .card_capabilities()
            .unwrap()
            .command_chaining());
        assert!(!historical_bytes
            .card_capabilities()
            .unwrap()
            .extended_length_information());
        assert!(historical_bytes
            .card_capabilities()
            .unwrap()
            .extended_lc_le());
    });
}

#[test]
fn get_data() {
    let mut options = Options::default();
    options.button_available = false;
    with_tx_options(options, |mut tx| {
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
        let historical_bytes = appdata.historical_bytes().unwrap();
        assert!(historical_bytes
            .card_capabilities()
            .unwrap()
            .command_chaining());
        assert!(historical_bytes
            .card_capabilities()
            .unwrap()
            .extended_length_information());
        assert!(historical_bytes
            .card_capabilities()
            .unwrap()
            .extended_lc_le());

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
            tx.set_cardholder_certificate(format!("{i}").into())
                .unwrap();
        }

        tx.select_data(0, &[0x7f, 0x21], false).unwrap();
        assert_eq!(tx.cardholder_certificate().unwrap(), "0".as_bytes());
        assert_eq!(tx.next_cardholder_certificate().unwrap(), "1".as_bytes());
        assert_eq!(tx.next_cardholder_certificate().unwrap(), "2".as_bytes());

        for i in 0..3 {
            tx.select_data(i, &[0x7f, 0x21], false).unwrap();
            assert_eq!(
                tx.cardholder_certificate().unwrap(),
                format!("{i}").as_bytes()
            );
        }
    });
}
