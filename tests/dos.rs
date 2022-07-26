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
                [
                    0xD2,
                    0x76,
                    0x00,
                    0x01,
                    0x24,
                    0x1,
                    env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or_default(),
                    env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or_default(),
                    0x0,
                    0x0,
                    0x0,
                    0x0,
                    0x0,
                    0x0,
                    0x0,
                    0x0
                ]
                .as_slice()
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
