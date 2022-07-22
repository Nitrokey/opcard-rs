// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;

use crate::{
    card::Context,
    command::{GetDataMode, Password, Tag},
    state::MAX_PIN_LENGTH,
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
            #[allow(unused)]
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

        impl TryFrom<u16> for $name {
            type Error = Status;
            fn try_from(tag: u16) -> ::core::result::Result<Self, Status> {
                let v: $sup = tag.try_into()?;
                match v {
                    $(
                        $sup::$var => Ok($name::$var),
                    )*
                    _ => Err(Status::KeyReferenceNotFound)
                }
            }
        }

        impl TryFrom<Tag> for $name {
            type Error = Status;
            fn try_from(tag: Tag) -> ::core::result::Result<Self, Status> {
                let v: $sup = tag.try_into()?;
                match v {
                    $(
                        $sup::$var => Ok($name::$var),
                    )*
                    _ => Err(Status::KeyReferenceNotFound)
                }
            }
        }

        impl $name {
            #[allow(unused)]
            $vis fn tag(self) -> &'static [u8] {
                let raw: $sup = self.into();
                raw.tag()
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
        KeyGenerationDates,
        CAFingerprints,
        Fingerprints,
        AlgorithmAttributesSignature,
        AlgorithmAttributesDecryption,
        AlgorithmAttributesAuthentication,
        ExtendedCapabilities,
        DiscretionaryDataObjects,
        CardHolderSex,
        LanguagePreferences,
        CardHolderName,
        DigitalSignatureCounter,
    }
}

enum GetDataDoType {
    Simple(GetDataObject),
    Constructed(&'static [GetDataObject]),
}

impl GetDataObject {
    pub fn simple_or_constructed(&self) -> GetDataDoType {
        match self {
            GetDataObject::CardHolderRelatedData => GetDataDoType::Constructed(&[
                GetDataObject::CardHolderName,
                GetDataObject::LanguagePreferences,
                GetDataObject::CardHolderSex,
            ]),
            GetDataObject::ApplicationRelatedData => GetDataDoType::Constructed(&[
                GetDataObject::ApplicationIdentifier,
                GetDataObject::HistoricalBytes,
                GetDataObject::ExtendedLengthInformation,
                GetDataObject::GeneralFeatureManagement,
                GetDataObject::DiscretionaryDataObjects,
            ]),
            GetDataObject::DiscretionaryDataObjects => GetDataDoType::Constructed(&[
                GetDataObject::ExtendedCapabilities,
                GetDataObject::AlgorithmAttributesSignature,
                GetDataObject::AlgorithmAttributesDecryption,
                GetDataObject::AlgorithmAttributesAuthentication,
                GetDataObject::PwStatusBytes,
                GetDataObject::Fingerprints,
                GetDataObject::CAFingerprints,
                GetDataObject::KeyGenerationDates,
                GetDataObject::KeyInformation,
                GetDataObject::UifCds,
                GetDataObject::UifDec,
                GetDataObject::UifAut,
            ]),
            _ => GetDataDoType::Simple(*self),
        }
    }

    fn into_simple(self) -> Result<Self, Status> {
        if let GetDataDoType::Simple(o) = self.simple_or_constructed() {
            Ok(o)
        } else {
            log::error!("Expected a simple object");
            Err(Status::UnspecifiedNonpersistentExecutionError)
        }
    }

    /// Returns `true` if it can be obtain via a GET DATA command with its tag and not as children
    /// of a constructed DO.
    fn is_visible(&self) -> bool {
        !matches!(
            self,
            Self::KeyGenerationDates
                | Self::CAFingerprints
                | Self::Fingerprints
                | Self::AlgorithmAttributesSignature
                | Self::AlgorithmAttributesDecryption
                | Self::AlgorithmAttributesAuthentication
                | Self::ExtendedCapabilities
                | Self::DiscretionaryDataObjects
                | Self::CardHolderSex
                | Self::LanguagePreferences
                | Self::CardHolderName
                | Self::CardHolderCertificate
                | Self::ExtendedLengthInformation
                | Self::DigitalSignatureCounter
        )
    }
    fn reply<const R: usize, T: trussed::Client>(
        self,
        mut context: Context<'_, R, T>,
    ) -> Result<(), Status> {
        match self {
            Self::HistoricalBytes => context.extend_reply(&context.options.historical_bytes)?,
            Self::ApplicationIdentifier => context.extend_reply(&context.options.aid())?,
            Self::PwStatusBytes => pw_status_bytes(context)?,
            Self::ExtendedLengthInformation => context.extend_reply(EXTENDED_LENGTH_INFO)?,
            Self::GeneralFeatureManagement => context.extend_reply(GENERAL_FEATURE_MANAGEMENT)?,
            _ => {
                debug_assert!(
                    self.into_simple().is_ok(),
                    "Called `reply` on a constructed DO: {self:?}"
                );
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

// From [apdu_dispatch](https://github.com/solokeys/apdu-dispatch/blob/644336c38beb8896ce99a0fda23551bd65bb8126/src/lib.rs)
const EXTENDED_LENGTH_INFO: &[u8] = &[0x02, 0x02, 0x1D, 0xB9, 0x02, 0x02, 0x1D, 0xB9];
// § 4.1.3.2 We have a button and a LED
const GENERAL_FEATURE_MANAGEMENT: &[u8] = &[0x81, 0x01, 0b00101000];

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
    if !object.is_visible() {
        log::error!("Get data for children object: {object:?}");
        return Err(Status::IncorrectDataParameter);
    }
    log::debug!("Returning data for tag {:?}", tag);
    match object.simple_or_constructed() {
        GetDataDoType::Simple(obj) => obj.reply(context),
        GetDataDoType::Constructed(objs) => get_constructed_data(context, objs),
    }
}

/// Prepend the length to some data.
///
/// Input:
/// AAAAAAAAAABBBBBBB
///           ↑  
///          offset
///    
/// Output:
///
/// AAAAAAAAAA 7 BBBBBBB
/// (There are seven Bs, the length is encoded as specified in § 4.4.4)
fn prepend_len<const R: usize>(
    buf: &mut heapless::Vec<u8, R>,
    offset: usize,
) -> Result<(), Status> {
    let len = buf.len() - offset;
    if len <= 0x7f {
        let res = buf.extend_from_slice(&[len as u8]);
        buf[offset..].rotate_right(1);
        res
    } else if len <= 255 {
        let res = buf.extend_from_slice(&[0x81, len as u8]);
        buf[offset..].rotate_right(2);
        res
    } else if len <= 65535 {
        let arr = (len as u16).to_be_bytes();
        let res = buf.extend_from_slice(&[0x82, arr[0], arr[1]]);
        buf[offset..].rotate_right(3);
        res
    } else {
        log::error!("Length too long to be encoded");
        return Err(Status::UnspecifiedNonpersistentExecutionError);
    }
    .map_err(|_| {
        log::error!("Reply buffer full");
        Status::UnspecifiedNonpersistentExecutionError
    })
}

fn get_constructed_data<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
    objects: &'static [GetDataObject],
) -> Result<(), Status> {
    for obj in objects {
        context.extend_reply(obj.tag())?;
        let offset = context.reply.len();
        // Copied to avoid moving the context
        // This works because the life of tmp_ctx are smaller that that of context
        let tmp_ctx = Context {
            reply: context.reply,
            backend: context.backend,
            options: context.options,
            state: context.state,
            data: context.data,
        };
        match obj.simple_or_constructed() {
            GetDataDoType::Simple(simple) => simple.reply(tmp_ctx)?,
            GetDataDoType::Constructed(children) => {
                for inner_obj in children {
                    let inner_offset = tmp_ctx.reply.len();
                    let inner_tmp_ctx = Context {
                        reply: tmp_ctx.reply,
                        backend: tmp_ctx.backend,
                        options: tmp_ctx.options,
                        state: tmp_ctx.state,
                        data: tmp_ctx.data,
                    };
                    // We only accept two levels of nesting to avoid recursion
                    inner_obj.into_simple()?.reply(inner_tmp_ctx)?;
                    prepend_len(tmp_ctx.reply, inner_offset)?;
                }
            }
        }
        prepend_len(context.reply, offset)?;
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
        max_length_pw1: MAX_PIN_LENGTH as u8,
        max_length_rc: MAX_PIN_LENGTH as u8,
        max_length_pw3: MAX_PIN_LENGTH as u8,
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
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn tags() {
        // Test that tags didn't change after refactor
        assert_eq!(GetDataObject::Url.tag(), &[0x5F, 0x50]);
        assert_eq!(GetDataObject::HistoricalBytes.tag(), &[0x5F, 0x52]);
        assert_eq!(GetDataObject::CardHolderName.tag(), &[0x5B]);
        assert_eq!(GetDataObject::LanguagePreferences.tag(), &[0x5F, 0x2D]);
        assert_eq!(GetDataObject::CardHolderSex.tag(), &[0x5F, 0x35]);
        assert_eq!(GetDataObject::GeneralFeatureManagement.tag(), &[0x7f, 0x74]);
        assert_eq!(GetDataObject::CardHolderCertificate.tag(), &[0x7f, 0x21]);
        assert_eq!(
            GetDataObject::ExtendedLengthInformation.tag(),
            &[0x7f, 0x66]
        );
        assert_eq!(GetDataObject::DiscretionaryDataObjects.tag(), &[0x73]);
        assert_eq!(GetDataObject::ExtendedCapabilities.tag(), &[0xC0]);
        assert_eq!(GetDataObject::AlgorithmAttributesSignature.tag(), &[0xC1]);
        assert_eq!(GetDataObject::AlgorithmAttributesDecryption.tag(), &[0xC2]);
        assert_eq!(
            GetDataObject::AlgorithmAttributesAuthentication.tag(),
            &[0xC3]
        );
        assert_eq!(GetDataObject::PwStatusBytes.tag(), &[0xC4]);
        assert_eq!(GetDataObject::Fingerprints.tag(), &[0xC5]);
        assert_eq!(GetDataObject::CAFingerprints.tag(), &[0xC6]);
        assert_eq!(GetDataObject::KeyGenerationDates.tag(), &[0xCD]);
        assert_eq!(GetDataObject::KeyInformation.tag(), &[0xDE]);
        assert_eq!(GetDataObject::UifCds.tag(), &[0xD6]);
        assert_eq!(GetDataObject::UifDec.tag(), &[0xD7]);
        assert_eq!(GetDataObject::UifAut.tag(), &[0xD8]);
        assert_eq!(GetDataObject::DigitalSignatureCounter.tag(), &[0x93]);
        assert_eq!(GetDataObject::KdfDo.tag(), &[0xF9]);
        assert_eq!(GetDataObject::AlgorithmInformation.tag(), &[0xFA]);
        assert_eq!(GetDataObject::SecureMessagingCertificate.tag(), &[0xFB]);
        assert_eq!(GetDataObject::ApplicationIdentifier.tag(), &[0x4F]);
        assert_eq!(GetDataObject::LoginData.tag(), &[0x5E]);
    }

    #[test]
    fn prep_length() {
        let mut buf = heapless::Vec::<u8, 1000>::new();
        let offset = buf.len();
        buf.extend_from_slice(&[0; 0]).unwrap();
        prepend_len(&mut buf, offset).unwrap();
        assert_eq!(&buf[offset..], [0]);

        let offset = buf.len();
        buf.extend_from_slice(&[0; 20]).unwrap();
        prepend_len(&mut buf, offset).unwrap();
        let mut expected = vec![20];
        expected.extend_from_slice(&[0; 20]);
        assert_eq!(&buf[offset..], expected,);

        let offset = buf.len();
        buf.extend_from_slice(&[1; 127]).unwrap();
        prepend_len(&mut buf, offset).unwrap();
        let mut expected = vec![127];
        expected.extend_from_slice(&[1; 127]);
        assert_eq!(&buf[offset..], expected);

        let offset = buf.len();
        buf.extend_from_slice(&[2; 128]).unwrap();
        prepend_len(&mut buf, offset).unwrap();
        let mut expected = vec![0x81, 128];
        expected.extend_from_slice(&[2; 128]);
        assert_eq!(&buf[offset..], expected);

        let offset = buf.len();
        buf.extend_from_slice(&[3; 256]).unwrap();
        prepend_len(&mut buf, offset).unwrap();
        let mut expected = vec![0x82, 0x01, 0x00];
        expected.extend_from_slice(&[3; 256]);
        assert_eq!(&buf[offset..], expected);
    }

    #[test]
    fn max_nesting() {
        // Better way to iterate over all possible values of the enum?
        for i in 0..0xffff {
            let o = if let Ok(o) = GetDataObject::try_from(i) {
                o
            } else {
                continue;
            };
            match o.simple_or_constructed() {
                GetDataDoType::Simple(_) => continue,
                GetDataDoType::Constructed(children) => {
                    for child in children {
                        match child.simple_or_constructed() {
                            GetDataDoType::Simple(_) => continue,
                            GetDataDoType::Constructed(inner_children) => {
                                for inner_child in inner_children {
                                    inner_child
                                        .into_simple()
                                        .expect("No more than 2 levels of nested DOs");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
