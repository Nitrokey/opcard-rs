// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
pub struct Input {
    pub commands: Vec<Vec<u8>>,
    pub manufacturer: [u8; 2],
    pub serial: [u8; 4],
    pub historical_bytes: Vec<u8>,
    //pub button_available: bool,
}
