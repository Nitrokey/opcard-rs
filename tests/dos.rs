// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "backend-software")]

use hex_literal::hex;
mod card;

use card::with_tx;

use openpgp_card::card_do::{ApplicationIdentifier, HistoricalBytes, Lang, Sex};

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
        let holderdata = tx.cardholder_related_data().unwrap();
        // We may want the name to return None when not set. We'll have to see how GPG handles it
        assert_eq!(holderdata.name().unwrap(), b"".as_slice());
        assert_eq!(holderdata.sex().unwrap(), Sex::NotKnown);
        assert_eq!(holderdata.lang().unwrap(), &[Lang::Value(*b"en")]);
    });
}
