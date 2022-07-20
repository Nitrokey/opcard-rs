// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;

use crate::{
    card::Context,
    command::{GetDataMode, Password, Tag},
    utils::InspectErr,
};

/// Public Data objects
#[derive(Debug, Clone, Copy)]
enum GetDataObject {
    ApplicationIdentifier,
    LoginData,
    Url,
    HistoricalBytes,
    CardholderRelatedData,
    ApplicationRelatedData,
    GeneralFeatureManagement,
    PwStatusBytes,
    KeyInformation,
    UifCds,
    UifDec,
    UifAut,
    SecuritSupportTemplate,
    CardholderCertificate,
    ExtendedLengthInformation,
    KdfDo,
    AlgorithmInformation,
    SecureMessagingCertificate,
}

impl TryFrom<Tag> for GetDataObject {
    type Error = Status;

    fn try_from(tag: Tag) -> Result<Self, Self::Error> {
        tag.0.try_into()
    }
}

impl TryFrom<u16> for GetDataObject {
    type Error = Status;

    fn try_from(tag: u16) -> Result<Self, Self::Error> {
        // § 4.4.1
        match tag {
            0x004F => Ok(GetDataObject::ApplicationIdentifier),
            0x005E => Ok(GetDataObject::LoginData),
            0x5F50 => Ok(GetDataObject::Url),
            0x5F52 => Ok(GetDataObject::HistoricalBytes),
            0x0065 => Ok(GetDataObject::CardholderRelatedData),
            0x006E => Ok(GetDataObject::ApplicationRelatedData),
            0x7f74 => Ok(GetDataObject::GeneralFeatureManagement),
            0x00C4 => Ok(GetDataObject::PwStatusBytes),
            0x00DE => Ok(GetDataObject::KeyInformation),
            0x00D6 => Ok(GetDataObject::UifCds),
            0x00D7 => Ok(GetDataObject::UifDec),
            0x00D8 => Ok(GetDataObject::UifAut),
            0x007A => Ok(GetDataObject::SecuritSupportTemplate),
            0x7f21 => Ok(GetDataObject::CardholderCertificate),
            0x7f66 => Ok(GetDataObject::ExtendedLengthInformation),
            0x00F9 => Ok(GetDataObject::KdfDo),
            0x00FA => Ok(GetDataObject::AlgorithmInformation),
            0x00FB => Ok(GetDataObject::SecureMessagingCertificate),

            _ => Err(Status::KeyReferenceNotFound),
        }
    }
}

impl GetDataObject {
    #[allow(unused)]
    pub fn tag(&self) -> &'static [u8] {
        match self {
            GetDataObject::ApplicationIdentifier => &[0x4F],
            GetDataObject::LoginData => &[0x5E],
            GetDataObject::CardholderRelatedData => &[0x65],
            GetDataObject::ApplicationRelatedData => &[0x6E],
            GetDataObject::PwStatusBytes => &[0xC4],
            GetDataObject::KeyInformation => &[0xDE],
            GetDataObject::UifCds => &[0xD6],
            GetDataObject::UifDec => &[0xD7],
            GetDataObject::UifAut => &[0xD8],
            GetDataObject::SecuritSupportTemplate => &[0x7A],
            GetDataObject::KdfDo => &[0xF9],
            GetDataObject::AlgorithmInformation => &[0xFA],
            GetDataObject::SecureMessagingCertificate => &[0xFB],
            GetDataObject::Url => &[0x5F, 0x50],
            GetDataObject::HistoricalBytes => &[0x5F, 0x52],
            GetDataObject::CardholderCertificate => &[0x7f, 0x21],
            GetDataObject::ExtendedLengthInformation => &[0x7f, 0x66],
            GetDataObject::GeneralFeatureManagement => &[0x7f, 0x74],
        }
    }

    /// Returns the pure version of itself. In case of DOs with children, return the list of
    /// chlidren
    pub fn as_pure(&self) -> Result<PureGetDataObject, &'static [PureGetDataObject]> {
        match self {
            GetDataObject::ApplicationIdentifier => Ok(PureGetDataObject::ApplicationIdentifier),
            GetDataObject::LoginData => Ok(PureGetDataObject::LoginData),
            GetDataObject::Url => Ok(PureGetDataObject::Url),
            GetDataObject::HistoricalBytes => Ok(PureGetDataObject::HistoricalBytes),
            GetDataObject::GeneralFeatureManagement => {
                Err(&[PureGetDataObject::GeneralFeatureManagement])
            }
            GetDataObject::PwStatusBytes => Ok(PureGetDataObject::PwStatusBytes),
            GetDataObject::KeyInformation => Ok(PureGetDataObject::KeyInformation),
            GetDataObject::UifCds => Ok(PureGetDataObject::UifCds),
            GetDataObject::UifDec => Ok(PureGetDataObject::UifDec),
            GetDataObject::UifAut => Ok(PureGetDataObject::UifAut),
            GetDataObject::CardholderCertificate => {
                Err(&[PureGetDataObject::CardholderCertificate])
            }
            GetDataObject::ExtendedLengthInformation => {
                Err(&[PureGetDataObject::ExtendedLengthInformation])
            }
            GetDataObject::KdfDo => Err(&[PureGetDataObject::KdfDo]),
            GetDataObject::AlgorithmInformation => Err(&[PureGetDataObject::AlgorithmInformation]),
            GetDataObject::SecureMessagingCertificate => {
                Err(&[PureGetDataObject::SecureMessagingCertificate])
            }
            GetDataObject::CardholderRelatedData => Err(&[
                PureGetDataObject::CardHolderName,
                PureGetDataObject::LanguagePreferences,
                PureGetDataObject::Sex,
            ]),
            GetDataObject::ApplicationRelatedData => Err(&[
                PureGetDataObject::ApplicationIdentifier,
                PureGetDataObject::HistoricalBytes,
                PureGetDataObject::ExtendedLengthInformation,
                PureGetDataObject::GeneralFeatureManagement,
                PureGetDataObject::DiscretionaryDataObjects,
                PureGetDataObject::ExtendedCapabilities,
                PureGetDataObject::AlgorithmAttributesSignature,
                PureGetDataObject::AlgorithmAttributesDecryption,
                PureGetDataObject::AlgorithmAttributesAuthentication,
                PureGetDataObject::PwStatusBytes,
                PureGetDataObject::Fingerprints,
                PureGetDataObject::CAFingerprints,
                PureGetDataObject::KeyGenerationDates,
                PureGetDataObject::KeyInformation,
                PureGetDataObject::UifCds,
                PureGetDataObject::UifDec,
                PureGetDataObject::UifAut,
            ]),
            GetDataObject::SecuritSupportTemplate => {
                Err(&[PureGetDataObject::DigitalSignatureCounter])
            }
        }
    }
}

/// "Pure" data objects that don't have children
///
/// Some may not be in GetDataObject because they're only available as part of a constructed DO (in
/// cursive in 4.4.1)
#[derive(Debug, Clone, Copy)]
enum PureGetDataObject {
    ApplicationIdentifier,
    LoginData,
    Url,
    HistoricalBytes,
    CardHolderName,
    LanguagePreferences,
    Sex,
    GeneralFeatureManagement,
    DiscretionaryDataObjects,
    ExtendedCapabilities,
    AlgorithmAttributesSignature,
    AlgorithmAttributesDecryption,
    AlgorithmAttributesAuthentication,
    PwStatusBytes,
    Fingerprints,
    CAFingerprints,
    KeyGenerationDates,
    KeyInformation,
    UifCds,
    UifDec,
    UifAut,
    DigitalSignatureCounter,
    CardholderCertificate,
    ExtendedLengthInformation,
    KdfDo,
    AlgorithmInformation,
    SecureMessagingCertificate,
}

impl PureGetDataObject {
    /// Returns the tag of the data object (1 or 2 bytes)
    pub fn tag(&self) -> &'static [u8] {
        match self {
            PureGetDataObject::Url => &[0x5F, 0x50],
            PureGetDataObject::HistoricalBytes => &[0x5F, 0x52],
            PureGetDataObject::CardHolderName => &[0x5B],
            PureGetDataObject::LanguagePreferences => &[0x5F, 0x2D],
            PureGetDataObject::Sex => &[0x5F, 0x35],
            PureGetDataObject::GeneralFeatureManagement => &[0x7f, 0x74],
            PureGetDataObject::CardholderCertificate => &[0x7f, 0x21],
            PureGetDataObject::ExtendedLengthInformation => &[0x7f, 0x66],
            PureGetDataObject::DiscretionaryDataObjects => &[0x73],
            PureGetDataObject::ExtendedCapabilities => &[0xC0],
            PureGetDataObject::AlgorithmAttributesSignature => &[0xC1],
            PureGetDataObject::AlgorithmAttributesDecryption => &[0xC2],
            PureGetDataObject::AlgorithmAttributesAuthentication => &[0xC3],
            PureGetDataObject::PwStatusBytes => &[0xC4],
            PureGetDataObject::Fingerprints => &[0xC5],
            PureGetDataObject::CAFingerprints => &[0xC6],
            PureGetDataObject::KeyGenerationDates => &[0xCD],
            PureGetDataObject::KeyInformation => &[0xDE],
            PureGetDataObject::UifCds => &[0xD6],
            PureGetDataObject::UifDec => &[0xD7],
            PureGetDataObject::UifAut => &[0xD8],
            PureGetDataObject::DigitalSignatureCounter => &[0x93],
            PureGetDataObject::KdfDo => &[0xF9],
            PureGetDataObject::AlgorithmInformation => &[0xFA],
            PureGetDataObject::SecureMessagingCertificate => &[0xFB],
            PureGetDataObject::ApplicationIdentifier => &[0x4F],
            PureGetDataObject::LoginData => &[0x5E],
        }
    }

    fn get_pure_data<const R: usize, T: trussed::Client>(
        self,
        mut context: Context<'_, R, T>,
    ) -> Result<(), Status> {
        match self {
            PureGetDataObject::HistoricalBytes => context.extend_reply(HISTORICAL_BYTES)?,
            PureGetDataObject::ApplicationIdentifier => {
                context.extend_reply(&context.options.aid())?
            }
            PureGetDataObject::PwStatusBytes => pw_status_bytes(context)?,
            PureGetDataObject::ExtendedLengthInformation => {
                context.extend_reply(EXTENDED_LENGTH_INFO)?
            }
            _ => {
                log::error!("Unimplemented DO: {self:?}");
                return Err(Status::UnspecifiedNonpersistentExecutionError);
            }
        }
        log::info!("Returning data for tag: {self:?}");
        Ok(())
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
// From [apdu_dispatch](https://github.com/solokeys/apdu-dispatch/blob/644336c38beb8896ce99a0fda23551bd65bb8126/src/lib.rs)
const EXTENDED_LENGTH_INFO: &[u8] = &[0x1D, 0xB9, 0x1D, 0xB9];

// § 7.2.6
pub fn get_data<const R: usize, T: trussed::Client>(
    context: Context<'_, R, T>,
    mode: GetDataMode,
    tag: Tag,
) -> Result<(), Status> {
    // TODO: curDO pointer
    if mode != GetDataMode::Even {
        unimplemented!();
    }
    let object = GetDataObject::try_from(tag)
        .inspect_err_stable(|err| log::warn!("Unsupported data tag {:x?}: {:?}", tag, err))?;
    log::debug!("Returning data for tag {:?}", tag);
    match object.as_pure() {
        Ok(obj) => obj.get_pure_data(context),
        Err(objs) => get_constructed_data(context, objs),
    }
}

fn encode_len<const R: usize>(len: usize, buf: &mut heapless::Vec<u8, R>) -> Result<(), Status> {
    if len <= 0x7f {
        buf.extend_from_slice(&[len as u8])
    } else if len <= 255 {
        buf.extend_from_slice(&[0x81, len as u8])
    } else if len <= 65535 {
        let arr = (len as u16).to_le_bytes();
        buf.extend_from_slice(&[0x82, arr[0], arr[1]])
    } else {
        return Err(Status::UnspecifiedPersistentExecutionError);
    }
    .map_err(|_| {
        log::error!("Buffer full");
        Status::NotEnoughMemory
    })
}

fn get_constructed_data<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
    objects: &'static [PureGetDataObject],
) -> Result<(), Status> {
    let mut buf = heapless::Vec::<u8, R>::new();
    for obj in objects {
        buf.clear();
        let tmp_ctx = Context {
            reply: &mut buf,
            backend: context.backend,
            options: context.options,
            state: context.state,
            data: context.data,
        };
        obj.get_pure_data(tmp_ctx)?;
        context.extend_reply(obj.tag())?;
        encode_len(buf.len(), context.reply)?;
        context.extend_reply(&buf)?;
    }
    Ok(())
}

pub fn pw_status_bytes<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
) -> Result<(), Status> {
    let internal = context
        .backend
        .load_internal(&mut context.state.internal)
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
    let status = PasswordStatus {
        // TODO support true
        pw1_valid_multiple: false,
        max_length_pw1: 8,
        max_length_rc: 8,
        max_length_pw3: 8,
        error_counter_pw1: internal.remaining_tries(Password::Pw1),
        // TODO when implementing RESET RETRY COUNTER
        error_counter_rc: 3,
        error_counter_pw3: internal.remaining_tries(Password::Pw3),
    };
    let status: [u8; 7] = status.into();
    context.extend_reply(&status)
}
