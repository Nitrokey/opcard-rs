// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;

use crate::{
    card::Context,
    command::{GetDataMode, Password, Tag},
    utils::InspectErr,
};

macro_rules! enum_u16 {
    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident {
            $($var:ident = $num:expr),+
            $(,)*
        }
    ) => {
        $(#[$outer])*
        #[repr(u16)]
        $vis enum $name {
            $(
                $var = $num,
            )*
        }

        impl TryFrom<u16> for $name {
            type Error = Status;
            fn try_from(val: u16) -> ::core::result::Result<Self, Status> {
                match val {
                    $(
                        $num => Ok($name::$var),
                    )*
                    _ => Err(Status::KeyReferenceNotFound)
                }
            }
        }

        impl TryFrom<Tag> for $name {
            type Error = Status;
            fn try_from(val: Tag) -> ::core::result::Result<Self, Status> {
                match val.0 {
                    $(
                        $num => Ok($name::$var),
                    )*
                    _ => Err(Status::KeyReferenceNotFound)
                }
            }
        }

        impl $name {
            $vis fn tag(&self) -> &'static [u8] {
                match self{
                    $(
                         $name::$var => {
                            const BYTES: [u8; 2] = ($name::$var as u16).to_be_bytes();
                            if BYTES[0] == 0 {
                                &BYTES[1..]
                            } else {
                                &BYTES
                            }
                         }
                    )*
                }
            }
        }
    }
}

macro_rules! enum_subset {
    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident: $sup:ident {
            $($var:ident),+
            $(,)*
        }
    ) => {
        $(#[$outer])*
        #[repr(u16)]
        $vis enum $name {
            $(
                $var,
            )*
        }

        impl TryFrom<$sup> for $name
        {
            type Error = Status;
            fn try_from(val: $sup) -> ::core::result::Result<Self, Status> {
                match val {
                    $(
                        $sup::$var => Ok($name::$var),
                    )*
                    _ => Err(Status::KeyReferenceNotFound)
                }
            }
        }

        impl From<$name> for $sup
        {
            fn from(v: $name) -> $sup {
                match v {
                    $(
                        $name::$var => $sup::$var,
                    )*
                }
            }
        }
    }
}

enum_u16! {
    /// All data objects
    #[derive(Debug, Clone, Copy)]
    enum DataObject {
        PrivateUse1 = 0x0101,
        PrivateUse2 = 0x0102,
        PrivateUse3 = 0x0103,
        PrivateUse4 = 0x0104,
        ExtendedHeaderList = 0x004D,
        ApplicationIdentifier = 0x004F,
        LoginData = 0x005E,
        Url = 0x5F50,
        HistoricalBytes = 0x5F52,
        CardHolderRelatedData  = 0x0065,
        CardHolderName = 0x005B,
        LanguagePreferences = 0x5F2D,
        CardHolderSex = 0x5F35,
        ApplicationRelatedData  = 0x006E,
        GeneralFeatureManagement = 0x7f74,
        DiscretionaryDataObjects = 0x0073,
        ExtendedCapabilities = 0x00C0,
        AlgorithmAttributesSignature = 0x00C1,
        AlgorithmAttributesDecryption = 0x00C2,
        AlgorithmAttributesAuthentication = 0x00C3,
        PwStatusBytes = 0x00C4,
        Fingerprints = 0x00C5,
        CAFingerprints = 0x00C6,
        SignFingerprint = 0x00C7,
        DecFingerprint = 0x00C8,
        AuthFingerprint = 0x00C9,
        CaFingerprint1 = 0x00CA,
        CaFingerprint2 = 0x00CB,
        CaFingerprint3 = 0x00CC,
        KeyGenerationDates = 0x00CD,
        SignGenerationDate = 0x00CE,
        DecGenerationDate = 0x00CF,
        AuthGenerationDate = 0x00D0,
        KeyInformation = 0x00DE,
        SMkEnc = 0x00D1,
        SMkMac = 0x00D2,
        ResetingCode = 0x00D3,
        PSOEncDecKey = 0x00D5,
        SMEncMac = 0x00F4,
        UifCds = 0x00D6,
        UifDec = 0x00D7,
        UifAut = 0x00D8,
        SecuritSupportTemplate  = 0x007A,
        DigitalSignatureCounter = 0x0093,
        CardHolderCertificate = 0x7f21,
        ExtendedLengthInformation = 0x7f66,
        KdfDo = 0x00F9,
        AlgorithmInformation = 0x00FA,
        SecureMessagingCertificate = 0x00FB,
    }
}

enum_subset! {
    /// Data objects available via GET DATA
    #[derive(Debug, Clone, Copy)]
    enum GetDataObject: DataObject {
        PrivateUse1,
        PrivateUse2,
        PrivateUse3,
        PrivateUse4,
        ApplicationIdentifier,
        LoginData,
        Url,
        HistoricalBytes,
        CardHolderRelatedData,
        ApplicationRelatedData,
        GeneralFeatureManagement,
        PwStatusBytes,
        KeyInformation,
        UifCds,
        UifDec,
        UifAut,
        SecuritSupportTemplate,
        CardHolderCertificate,
        ExtendedLengthInformation,
        KdfDo,
        AlgorithmInformation,
        SecureMessagingCertificate,
    }
}

enum_subset! {
    /// "Pure" data objects that don't have children
    ///
    /// Distinct from Simple. All Simple DOs are "pure", but some "pure" represent the data (not
    /// prepended with tag and length) of a constructed DO.
    ///
    /// Some may not be in GetDataObject because they're only available as part of a constructed DO (in
    /// cursive in 4.4.1)
    #[derive(Debug, Clone, Copy)]
    enum PureGetDataObject: DataObject {
        PrivateUse1,
        PrivateUse2,
        PrivateUse3,
        PrivateUse4,
        ApplicationIdentifier,
        LoginData,
        Url,
        HistoricalBytes,
        CardHolderName,
        LanguagePreferences,
        CardHolderSex,
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
        CardHolderCertificate,
        ExtendedLengthInformation,
        KdfDo,
        AlgorithmInformation,
        SecureMessagingCertificate,
    }
}

enum GetDataDoType {
    Simple(PureGetDataObject),
    Constructed(&'static [PureGetDataObject]),
}

impl GetDataObject {
    #[allow(unused)]
    pub fn tag(self) -> &'static [u8] {
        let raw: DataObject = self.into();
        raw.tag()
    }

    /// Returns the pure version of itself. In case of DOs with children, return the list of
    /// chlidren
    pub fn simple_or_constructed(&self) -> GetDataDoType {
        match self {
            GetDataObject::PrivateUse1 => GetDataDoType::Simple(PureGetDataObject::PrivateUse1),
            GetDataObject::PrivateUse2 => GetDataDoType::Simple(PureGetDataObject::PrivateUse2),
            GetDataObject::PrivateUse3 => GetDataDoType::Simple(PureGetDataObject::PrivateUse3),
            GetDataObject::PrivateUse4 => GetDataDoType::Simple(PureGetDataObject::PrivateUse4),
            GetDataObject::ApplicationIdentifier => {
                GetDataDoType::Simple(PureGetDataObject::ApplicationIdentifier)
            }
            GetDataObject::LoginData => GetDataDoType::Simple(PureGetDataObject::LoginData),
            GetDataObject::Url => GetDataDoType::Simple(PureGetDataObject::Url),
            GetDataObject::HistoricalBytes => {
                GetDataDoType::Simple(PureGetDataObject::HistoricalBytes)
            }
            GetDataObject::GeneralFeatureManagement => {
                GetDataDoType::Constructed(&[PureGetDataObject::GeneralFeatureManagement])
            }
            GetDataObject::PwStatusBytes => GetDataDoType::Simple(PureGetDataObject::PwStatusBytes),
            GetDataObject::KeyInformation => {
                GetDataDoType::Simple(PureGetDataObject::KeyInformation)
            }
            GetDataObject::UifCds => GetDataDoType::Simple(PureGetDataObject::UifCds),
            GetDataObject::UifDec => GetDataDoType::Simple(PureGetDataObject::UifDec),
            GetDataObject::UifAut => GetDataDoType::Simple(PureGetDataObject::UifAut),
            GetDataObject::CardHolderCertificate => {
                GetDataDoType::Constructed(&[PureGetDataObject::CardHolderCertificate])
            }
            GetDataObject::ExtendedLengthInformation => {
                GetDataDoType::Constructed(&[PureGetDataObject::ExtendedLengthInformation])
            }
            GetDataObject::KdfDo => GetDataDoType::Constructed(&[PureGetDataObject::KdfDo]),
            GetDataObject::AlgorithmInformation => {
                GetDataDoType::Constructed(&[PureGetDataObject::AlgorithmInformation])
            }
            GetDataObject::SecureMessagingCertificate => {
                GetDataDoType::Constructed(&[PureGetDataObject::SecureMessagingCertificate])
            }
            GetDataObject::CardHolderRelatedData => GetDataDoType::Constructed(&[
                PureGetDataObject::CardHolderName,
                PureGetDataObject::LanguagePreferences,
                PureGetDataObject::CardHolderSex,
            ]),
            GetDataObject::ApplicationRelatedData => GetDataDoType::Constructed(&[
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
                GetDataDoType::Constructed(&[PureGetDataObject::DigitalSignatureCounter])
            }
        }
    }
}

impl PureGetDataObject {
    /// Returns the tag of the data object (1 or 2 bytes)
    pub fn tag(self) -> &'static [u8] {
        let raw: DataObject = self.into();
        raw.tag()
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
    let raw_object = DataObject::try_from(tag)
        .inspect_err_stable(|err| log::warn!("Unsupported data tag {:x?}: {:?}", tag, err))?;
    let object = GetDataObject::try_from(raw_object)
        .inspect_err_stable(|err| log::warn!("Unsupported data tag {:x?}: {:?}", tag, err))?;
    log::debug!("Returning data for tag {:?}", tag);
    match object.simple_or_constructed() {
        GetDataDoType::Simple(obj) => obj.get_pure_data(context),
        GetDataDoType::Constructed(objs) => get_constructed_data(context, objs),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags() {
        // Test that tags didn't change after refactor
        assert_eq!(PureGetDataObject::Url.tag(), &[0x5F, 0x50]);
        assert_eq!(PureGetDataObject::HistoricalBytes.tag(), &[0x5F, 0x52]);
        assert_eq!(PureGetDataObject::CardHolderName.tag(), &[0x5B]);
        assert_eq!(PureGetDataObject::LanguagePreferences.tag(), &[0x5F, 0x2D]);
        assert_eq!(PureGetDataObject::CardHolderSex.tag(), &[0x5F, 0x35]);
        assert_eq!(
            PureGetDataObject::GeneralFeatureManagement.tag(),
            &[0x7f, 0x74]
        );
        assert_eq!(
            PureGetDataObject::CardHolderCertificate.tag(),
            &[0x7f, 0x21]
        );
        assert_eq!(
            PureGetDataObject::ExtendedLengthInformation.tag(),
            &[0x7f, 0x66]
        );
        assert_eq!(PureGetDataObject::DiscretionaryDataObjects.tag(), &[0x73]);
        assert_eq!(PureGetDataObject::ExtendedCapabilities.tag(), &[0xC0]);
        assert_eq!(
            PureGetDataObject::AlgorithmAttributesSignature.tag(),
            &[0xC1]
        );
        assert_eq!(
            PureGetDataObject::AlgorithmAttributesDecryption.tag(),
            &[0xC2]
        );
        assert_eq!(
            PureGetDataObject::AlgorithmAttributesAuthentication.tag(),
            &[0xC3]
        );
        assert_eq!(PureGetDataObject::PwStatusBytes.tag(), &[0xC4]);
        assert_eq!(PureGetDataObject::Fingerprints.tag(), &[0xC5]);
        assert_eq!(PureGetDataObject::CAFingerprints.tag(), &[0xC6]);
        assert_eq!(PureGetDataObject::KeyGenerationDates.tag(), &[0xCD]);
        assert_eq!(PureGetDataObject::KeyInformation.tag(), &[0xDE]);
        assert_eq!(PureGetDataObject::UifCds.tag(), &[0xD6]);
        assert_eq!(PureGetDataObject::UifDec.tag(), &[0xD7]);
        assert_eq!(PureGetDataObject::UifAut.tag(), &[0xD8]);
        assert_eq!(PureGetDataObject::DigitalSignatureCounter.tag(), &[0x93]);
        assert_eq!(PureGetDataObject::KdfDo.tag(), &[0xF9]);
        assert_eq!(PureGetDataObject::AlgorithmInformation.tag(), &[0xFA]);
        assert_eq!(PureGetDataObject::SecureMessagingCertificate.tag(), &[0xFB]);
        assert_eq!(PureGetDataObject::ApplicationIdentifier.tag(), &[0x4F]);
        assert_eq!(PureGetDataObject::LoginData.tag(), &[0x5E]);
    }
}
