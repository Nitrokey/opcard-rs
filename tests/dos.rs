// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
use hex_literal::hex;
mod card;

use card::with_tx;

use openpgp_card::card_do::{ApplicationIdentifier, HistoricalBytes, Lang, Sex, TouchPolicy};

#[test]
fn get_data() {
    with_tx(|mut tx| {
        assert!(tx.url().unwrap().is_empty());
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
            HistoricalBytes::try_from(hex!("0031F573C00160009000").as_slice()).unwrap()
        );

        let uif_cds = appdata.uif_pso_cds().unwrap().unwrap();
        assert_eq!(uif_cds.touch_policy(), TouchPolicy::Off);
        assert_eq!(format!("{}", uif_cds.features()), "Button");

        let uif_dec = appdata.uif_pso_dec().unwrap().unwrap();
        assert_eq!(uif_dec.touch_policy(), TouchPolicy::Off);
        assert_eq!(format!("{}", uif_dec.features()), "Button");

        let uif_aut = appdata.uif_pso_aut().unwrap().unwrap();
        assert_eq!(uif_aut.touch_policy(), TouchPolicy::Off);
        assert_eq!(format!("{}", uif_aut.features()), "Button");

        let holderdata = tx.cardholder_related_data().unwrap();
        // We may want the name to return None when not set. We'll have to see how GPG handles it
        assert_eq!(holderdata.name().unwrap(), b"".as_slice());
        assert_eq!(holderdata.sex().unwrap(), Sex::NotKnown);
        assert_eq!(holderdata.lang().unwrap(), &[Lang::Value(*b"en")]);

        let cardholder_cert = tx.cardholder_certificate().unwrap();
        assert_eq!(cardholder_cert, &[]);
    });
}
