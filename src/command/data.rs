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
enum DataObject {
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

impl TryFrom<Tag> for DataObject {
    type Error = Status;

    fn try_from(tag: Tag) -> Result<Self, Self::Error> {
        tag.0.try_into()
    }
}

impl TryFrom<u16> for DataObject {
    type Error = Status;

    fn try_from(tag: u16) -> Result<Self, Self::Error> {
        // § 4.4.1
        match tag {
            0x004F => Ok(DataObject::ApplicationIdentifier),
            0x005E => Ok(DataObject::LoginData),
            0x5F50 => Ok(DataObject::Url),
            0x5F52 => Ok(DataObject::HistoricalBytes),
            0x0065 => Ok(DataObject::CardholderRelatedData),
            0x006E => Ok(DataObject::ApplicationRelatedData),
            0x7f74 => Ok(DataObject::GeneralFeatureManagement),
            0x00C4 => Ok(DataObject::PwStatusBytes),
            0x00DE => Ok(DataObject::KeyInformation),
            0x00D6 => Ok(DataObject::UifCds),
            0x00D7 => Ok(DataObject::UifDec),
            0x00D8 => Ok(DataObject::UifAut),
            0x007A => Ok(DataObject::SecuritSupportTemplate),
            0x7f21 => Ok(DataObject::CardholderCertificate),
            0x7f66 => Ok(DataObject::ExtendedLengthInformation),
            0x00F9 => Ok(DataObject::KdfDo),
            0x00FA => Ok(DataObject::AlgorithmInformation),
            0x00FB => Ok(DataObject::SecureMessagingCertificate),

            _ => Err(Status::KeyReferenceNotFound),
        }
    }
}

impl DataObject {
    #[allow(unused)]
    pub fn tag(&self) -> &'static [u8] {
        match self {
            DataObject::ApplicationIdentifier => &[0x4F],
            DataObject::LoginData => &[0x5E],
            DataObject::CardholderRelatedData => &[0x65],
            DataObject::ApplicationRelatedData => &[0x6E],
            DataObject::PwStatusBytes => &[0xC4],
            DataObject::KeyInformation => &[0xDE],
            DataObject::UifCds => &[0xD6],
            DataObject::UifDec => &[0xD7],
            DataObject::UifAut => &[0xD8],
            DataObject::SecuritSupportTemplate => &[0x7A],
            DataObject::KdfDo => &[0xF9],
            DataObject::AlgorithmInformation => &[0xFA],
            DataObject::SecureMessagingCertificate => &[0xFB],
            DataObject::Url => &[0x5F, 0x50],
            DataObject::HistoricalBytes => &[0x5F, 0x52],
            DataObject::CardholderCertificate => &[0x7f, 0x21],
            DataObject::ExtendedLengthInformation => &[0x7f, 0x66],
            DataObject::GeneralFeatureManagement => &[0x7f, 0x74],
        }
    }

    /// Returns the pure version of itself. In case of DOs with children, return the list of
    /// chlidren
    pub fn as_pure(&self) -> Result<PureDataObject, &'static [PureDataObject]> {
        match self {
            DataObject::ApplicationIdentifier => Ok(PureDataObject::ApplicationIdentifier),
            DataObject::LoginData => Ok(PureDataObject::LoginData),
            DataObject::Url => Ok(PureDataObject::Url),
            DataObject::HistoricalBytes => Ok(PureDataObject::HistoricalBytes),
            DataObject::GeneralFeatureManagement => {
                Err(&[PureDataObject::GeneralFeatureManagement])
            }
            DataObject::PwStatusBytes => Ok(PureDataObject::PwStatusBytes),
            DataObject::KeyInformation => Ok(PureDataObject::KeyInformation),
            DataObject::UifCds => Ok(PureDataObject::UifCds),
            DataObject::UifDec => Ok(PureDataObject::UifDec),
            DataObject::UifAut => Ok(PureDataObject::UifAut),
            DataObject::CardholderCertificate => Err(&[PureDataObject::CardholderCertificate]),
            DataObject::ExtendedLengthInformation => {
                Err(&[PureDataObject::ExtendedLengthInformation])
            }
            DataObject::KdfDo => Err(&[PureDataObject::KdfDo]),
            DataObject::AlgorithmInformation => Err(&[PureDataObject::AlgorithmInformation]),
            DataObject::SecureMessagingCertificate => {
                Err(&[PureDataObject::SecureMessagingCertificate])
            }
            DataObject::CardholderRelatedData => Err(&[
                PureDataObject::CardHolderName,
                PureDataObject::LanguagePreferences,
                PureDataObject::Sex,
            ]),
            DataObject::ApplicationRelatedData => Err(&[
                PureDataObject::ApplicationIdentifier,
                PureDataObject::HistoricalBytes,
                PureDataObject::ExtendedLengthInformation,
                PureDataObject::GeneralFeatureManagement,
                PureDataObject::DiscretionaryDataObjects,
                PureDataObject::ExtendedCapabilities,
                PureDataObject::AlgorithmAttributesSignature,
                PureDataObject::AlgorithmAttributesDecryption,
                PureDataObject::AlgorithmAttributesAuthentication,
                PureDataObject::PwStatusBytes,
                PureDataObject::Fingerprints,
                PureDataObject::CAFingerprints,
                PureDataObject::KeyGenerationDates,
                PureDataObject::KeyInformation,
                PureDataObject::UifCds,
                PureDataObject::UifDec,
                PureDataObject::UifAut,
            ]),
            DataObject::SecuritSupportTemplate => Err(&[PureDataObject::DigitalSignatureCounter]),
        }
    }
}

/// "Pure" data objects that don't have children
///
/// Some may not be in DataObject because they're only available as part of a constructed DO (in
/// cursive in 4.4.1)
#[derive(Debug, Clone, Copy)]
enum PureDataObject {
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

impl PureDataObject {
    /// Returns the tag of the data object (1 or 2 bytes)
    pub fn tag(&self) -> &'static [u8] {
        match self {
            PureDataObject::Url => &[0x5F, 0x50],
            PureDataObject::HistoricalBytes => &[0x5F, 0x52],
            PureDataObject::CardHolderName => &[0x5B],
            PureDataObject::LanguagePreferences => &[0x5F, 0x2D],
            PureDataObject::Sex => &[0x5F, 0x35],
            PureDataObject::GeneralFeatureManagement => &[0x7f, 0x74],
            PureDataObject::CardholderCertificate => &[0x7f, 0x21],
            PureDataObject::ExtendedLengthInformation => &[0x7f, 0x66],
            PureDataObject::DiscretionaryDataObjects => &[0x73],
            PureDataObject::ExtendedCapabilities => &[0xC0],
            PureDataObject::AlgorithmAttributesSignature => &[0xC1],
            PureDataObject::AlgorithmAttributesDecryption => &[0xC2],
            PureDataObject::AlgorithmAttributesAuthentication => &[0xC3],
            PureDataObject::PwStatusBytes => &[0xC4],
            PureDataObject::Fingerprints => &[0xC5],
            PureDataObject::CAFingerprints => &[0xC6],
            PureDataObject::KeyGenerationDates => &[0xCD],
            PureDataObject::KeyInformation => &[0xDE],
            PureDataObject::UifCds => &[0xD6],
            PureDataObject::UifDec => &[0xD7],
            PureDataObject::UifAut => &[0xD8],
            PureDataObject::DigitalSignatureCounter => &[0x93],
            PureDataObject::KdfDo => &[0xF9],
            PureDataObject::AlgorithmInformation => &[0xFA],
            PureDataObject::SecureMessagingCertificate => &[0xFB],
            PureDataObject::ApplicationIdentifier => &[0x4F],
            PureDataObject::LoginData => &[0x5E],
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
    context: Context<'_, R, T>,
    mode: GetDataMode,
    tag: Tag,
) -> Result<(), Status> {
    // TODO: curDO pointer
    if mode != GetDataMode::Even {
        unimplemented!();
    }
    let object = DataObject::try_from(tag)
        .inspect_err_stable(|err| log::warn!("Unsupported data tag {:x?}: {:?}", tag, err))?;
    log::debug!("Returning data for tag {:?}", tag);
    match object.as_pure() {
        Ok(obj) => get_pure_data(context, obj),
        Err(objs) => get_constructed_data(context, objs),
    }
}

fn get_pure_data<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
    object: PureDataObject,
) -> Result<(), Status> {
    match object {
        PureDataObject::HistoricalBytes => context.extend_reply(HISTORICAL_BYTES)?,
        PureDataObject::ApplicationIdentifier => context.extend_reply(&context.options.aid())?,
        PureDataObject::PwStatusBytes => pw_status_bytes(context)?,
        _ => {
            log::error!("Unimplemented DO: {object:?}");
            return Err(Status::UnspecifiedNonpersistentExecutionError);
        }
    }
    log::info!("Returning data for tag: {object:?}");
    Ok(())
}

fn get_constructed_data<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
    objects: &'static [PureDataObject],
) -> Result<(), Status> {
    let mut buf = heapless::Vec::<u8, 0xff>::new();
    for obj in objects {
        buf.clear();
        let tmp_ctx = Context {
            reply: &mut buf,
            backend: context.backend,
            options: context.options,
            state: context.state,
            data: context.data,
        };
        get_pure_data(tmp_ctx, *obj)?;
        context.extend_reply(obj.tag())?;
        context.extend_reply(&[buf.len() as u8])?;
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
