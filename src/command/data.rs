// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;

use crate::{
    card::Context,
    command::{GetDataMode, Tag},
    utils::InspectErr,
};

#[derive(Debug)]
enum GetDataTag {
    ApplicationIdentifier,
    ApplicationRelatedData,
    ExtendedCapabilities,
    HistoricalBytes,
    PasswordStatusBytes,
}

impl TryFrom<Tag> for GetDataTag {
    type Error = Status;

    fn try_from(tag: Tag) -> Result<Self, Self::Error> {
        tag.0.try_into()
    }
}

impl TryFrom<u16> for GetDataTag {
    type Error = Status;

    fn try_from(tag: u16) -> Result<Self, Self::Error> {
        // § 4.4.1
        match tag {
            0x004F => Ok(Self::ApplicationIdentifier),
            0x006E => Ok(Self::ApplicationRelatedData),
            0x00C0 => Ok(Self::ExtendedCapabilities),
            0x00C4 => Ok(Self::PasswordStatusBytes),
            0x5F52 => Ok(Self::HistoricalBytes),
            _ => Err(Status::KeyReferenceNotFound),
        }
    }
}

struct PasswordStatus {
    pw1_valid_multiple: bool,
    max_length_pw1: u8,
    max_length_rc: u8,
    max_length_pw3: u8,
    error_counter_pw1: u8,
    error_counter_rc: u8,
    error_counter_pw3: u8,
}

impl From<PasswordStatus> for [u8; 7] {
    fn from(status: PasswordStatus) -> Self {
        [
            if status.pw1_valid_multiple {
                0x01
            } else {
                0x00
            },
            status.max_length_pw1,
            status.max_length_rc,
            status.max_length_pw3,
            status.error_counter_pw1,
            status.error_counter_rc,
            status.error_counter_pw3,
        ]
    }
}

// § 6
// https://cardwerk.com/smart-card-standard-iso7816-4-section-8-historical-bytes/
// TODO: Copied from Nitrokey Pro -- check for NK3
const HISTORICAL_BYTES: &[u8] = b"0031F573C00160009000";

// § 7.2.6
pub fn get_data<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
    mode: GetDataMode,
    tag: Tag,
) -> Result<(), Status> {
    // TODO: curDO pointer
    // TODO: handle overlong data
    if mode != GetDataMode::Even {
        unimplemented!();
    }
    let tag = GetDataTag::try_from(tag)
        .inspect_err_stable(|err| log::warn!("Unsupported data tag {:x?}: {:?}", tag, err))?;
    log::debug!("Returning data for tag {:?}", tag);
    // TODO: remove unwraps
    match tag {
        GetDataTag::ApplicationIdentifier => context.extend_reply(&context.options.aid())?,

        GetDataTag::ApplicationRelatedData => {
            // TODO: extend
            let aid = context.options.aid();
            context.extend_reply(&[0x4F])?;
            context.extend_reply(&[aid.len() as u8])?;
            context.extend_reply(&aid)?;
        }
        // TODO: fix
        GetDataTag::ExtendedCapabilities => {
            context.extend_reply(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])?
        }

        GetDataTag::HistoricalBytes => context.extend_reply(HISTORICAL_BYTES)?,
        GetDataTag::PasswordStatusBytes => {
            // TODO: set correct values
            let status = PasswordStatus {
                pw1_valid_multiple: false,
                max_length_pw1: 32,
                max_length_rc: 32,
                max_length_pw3: 32,
                error_counter_pw1: 3,
                error_counter_rc: 3,
                error_counter_pw3: 3,
            };
            let status: [u8; 7] = status.into();
            context.extend_reply(&status)?;
        }
    }
    Ok(())
}
