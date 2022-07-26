// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "backend-software")]

mod card;

use card::{error_to_retries, with_tx};

use opcard::backend::virtual_platform::CARD;

#[test]
fn get_data() {
    with_tx(|mut tx| {
        assert!(tx.url().unwrap().is_empty());
        let appdata = tx.application_related_data().unwrap();
    });
}
