// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use heapless_bytes::Bytes;
use hex_literal::hex;
use iso7816::Status;

use crate::{
    card::{Context, LoadedContext, Options},
    command::{GetDataMode, Password, PutDataMode, Tag},
    state::{
        ArbitraryDO, KeyOrigin, PermissionRequirement, Sex, State, MAX_GENERIC_LENGTH,
        MAX_GENERIC_LENGTH_BE, MAX_PIN_LENGTH, MIN_LENGTH_RESET_CODE,
    },
    types::*,
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

        #[allow(unused)]
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

            /// Returns an iterator over all of the enum's members
            $vis fn iter_all() -> impl Iterator<Item = Self> {
                [
                    $(
                        $name::$var,
                    )*
                ].into_iter()
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

        #[allow(unused)]
        impl $name {
            $vis fn tag(self) -> &'static [u8] {
                let raw: $sup = self.into();
                raw.tag()
            }

            /// Returns an iterator over all of the enum's members
            $vis fn iter_all() -> impl Iterator<Item = Self> {
                [
                    $(
                        $name::$var,
                    )*
                ].into_iter()
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
        ExtendedHeaderList = 0x3FFF,
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
        ResettingCode = 0x00D3,
        PSOEncDecKey = 0x00D5,
        SMEncMac = 0x00F4,
        UifCds = 0x00D6,
        UifDec = 0x00D7,
        UifAut = 0x00D8,
        SecuritySupportTemplate  = 0x007A,
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
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        SecuritySupportTemplate,
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
            GetDataObject::SecuritySupportTemplate => {
                GetDataDoType::Constructed(&[GetDataObject::DigitalSignatureCounter])
            }
            _ => GetDataDoType::Simple(*self),
        }
    }

    fn into_simple(self) -> Result<Self, Status> {
        if let GetDataDoType::Simple(o) = self.simple_or_constructed() {
            Ok(o)
        } else {
            error!("Expected a simple object");
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
                | Self::ExtendedLengthInformation
                | Self::DigitalSignatureCounter
        )
    }
    fn reply<const R: usize, T: trussed::Client>(
        self,
        mut context: Context<'_, R, T>,
    ) -> Result<(), Status> {
        match self {
            Self::HistoricalBytes => historical_bytes(context)?,
            Self::ApplicationIdentifier => context.reply.expand(&context.options.aid())?,
            Self::PwStatusBytes => pw_status_bytes(context.load_state()?)?,
            Self::ExtendedLengthInformation => context.reply.expand(&EXTENDED_LENGTH_INFO)?,
            Self::ExtendedCapabilities => context.reply.expand(&EXTENDED_CAPABILITIES)?,
            Self::GeneralFeatureManagement => context
                .reply
                .expand(&general_feature_management(context.options))?,
            Self::AlgorithmAttributesSignature => alg_attr_sign(context.load_state()?)?,
            Self::AlgorithmAttributesDecryption => alg_attr_dec(context.load_state()?)?,
            Self::AlgorithmAttributesAuthentication => alg_attr_aut(context.load_state()?)?,
            Self::AlgorithmInformation => algo_info(context)?,
            Self::Fingerprints => fingerprints(context.load_state()?)?,
            Self::CAFingerprints => ca_fingerprints(context.load_state()?)?,
            Self::KeyGenerationDates => keygen_dates(context.load_state()?)?,
            Self::KeyInformation => key_info(context.load_state()?)?,
            Self::UifCds => uif(context.load_state()?, KeyType::Sign)?,
            Self::UifDec => uif(context.load_state()?, KeyType::Dec)?,
            Self::UifAut => uif(context.load_state()?, KeyType::Aut)?,
            Self::CardHolderName => cardholder_name(context.load_state()?)?,
            Self::CardHolderSex => cardholder_sex(context.load_state()?)?,
            Self::LanguagePreferences => language_preferences(context.load_state()?)?,
            Self::Url => get_arbitrary_do(context, ArbitraryDO::Url)?,
            Self::LoginData => get_arbitrary_do(context, ArbitraryDO::LoginData)?,
            Self::DigitalSignatureCounter => signature_counter(context.load_state()?)?,
            Self::KdfDo => get_arbitrary_do(context, ArbitraryDO::KdfDo)?,
            Self::PrivateUse1 => get_arbitrary_do(context, ArbitraryDO::PrivateUse1)?,
            Self::PrivateUse2 => get_arbitrary_do(context, ArbitraryDO::PrivateUse2)?,
            Self::PrivateUse3 => get_arbitrary_do(context, ArbitraryDO::PrivateUse3)?,
            Self::PrivateUse4 => get_arbitrary_do(context, ArbitraryDO::PrivateUse4)?,
            Self::CardHolderCertificate => cardholder_cert(context)?,
            Self::SecureMessagingCertificate => return Err(Status::SecureMessagingNotSupported),
            Self::CardHolderRelatedData
            | Self::ApplicationRelatedData
            | Self::DiscretionaryDataObjects
            | Self::SecuritySupportTemplate => {
                error!("Called `reply` on a constructed DO: {self:?}");
                return Err(Status::UnspecifiedNonpersistentExecutionError);
            }
        }
        info!("Returning data for tag: {self:?}");
        Ok(())
    }
}

fn general_feature_management_byte(options: &Options) -> u8 {
    if options.button_available {
        0x20
    } else {
        0x00
    }
}

fn general_feature_management(options: &Options) -> [u8; 3] {
    [0x81, 0x01, general_feature_management_byte(options)]
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
const EXTENDED_LENGTH_INFO: [u8; 8] = hex!("02 02 1DB9 02 02 1DB9");
const EXTENDED_CAPABILITIES: [u8; 10] = [
    0x3F, //
    0x00, //
    0x00, //
    0x00, // Secure messaging not supported
    MAX_GENERIC_LENGTH_BE[0],
    MAX_GENERIC_LENGTH_BE[1],
    MAX_GENERIC_LENGTH_BE[0],
    MAX_GENERIC_LENGTH_BE[1],
    0x00, // Pin block format 2 supported
    0x01, // Manage security environment (MSE) Command supported
];

const EF_DIR: &[u8] = &hex!(
    "
    61 11
    4F 06 D27600012401 
    50 07 4F70656e504750
"
);

/// See ISO7816-4 § 7.4.2, case where the physical interface does not allow the card to answer to reset
pub fn get_data_odd<const R: usize, T: trussed::Client>(
    mut ctx: Context<'_, R, T>,
) -> Result<(), Status> {
    if ctx.data != &hex!("5C00") {
        warn!("Invalid GET DATA with ODD INS");
        return Err(Status::IncorrectDataParameter);
    }
    ef_dir(ctx.lend())?;
    ef_atr_info(ctx)
}

pub fn ef_dir<const R: usize, T: trussed::Client>(
    mut ctx: Context<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply.expand(EF_DIR)
}

pub fn ef_atr_info<const R: usize, T: trussed::Client>(
    mut ctx: Context<'_, R, T>,
) -> Result<(), Status> {
    historical_bytes(ctx.lend())?;

    ctx.reply
        .expand(GetDataObject::ExtendedLengthInformation.tag())?;
    ctx.reply.append_len(EXTENDED_LENGTH_INFO.len())?;
    ctx.reply.expand(&EXTENDED_LENGTH_INFO)?;

    ctx.reply
        .expand(GetDataObject::GeneralFeatureManagement.tag())?;
    let data = general_feature_management(ctx.options);
    ctx.reply.append_len(data.len())?;
    ctx.reply.expand(&data)
}

// § 7.2.6
pub fn get_data<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
    mode: GetDataMode,
    tag: Tag,
) -> Result<(), Status> {
    if mode == GetDataMode::Odd {
        return get_data_odd(context);
    }

    let object = GetDataObject::try_from(tag).inspect_err_stable(|_err| {
        warn!("Unsupported data tag {:x?}: {:?}", tag, _err);
    })?;
    if !object.is_visible() {
        warn!("Get data for children object: {object:?}");
        return Err(Status::IncorrectDataParameter);
    }
    debug!("Returning data for tag {:?}", tag);
    match object.simple_or_constructed() {
        GetDataDoType::Simple(obj) => obj.reply(context.lend())?,
        GetDataDoType::Constructed(objs) => get_constructed_data(context.lend(), objs)?,
    }

    let cur_do = &mut context.state.runtime.cur_do;
    *cur_do = match cur_do {
        Some((t, occ)) if *t == tag => Some((tag, *occ)),
        _ => Some((tag, Occurrence::First)),
    };
    Ok(())
}

// § 7.2.7
pub fn get_next_data<const R: usize, T: trussed::Client>(
    context: Context<'_, R, T>,
    tag: Tag,
) -> Result<(), Status> {
    let cur_do = &mut context.state.runtime.cur_do;
    *cur_do = match cur_do {
        Some((t, Occurrence::First)) if *t == tag => Some((tag, Occurrence::Second)),
        Some((t, Occurrence::Second)) if *t == tag => Some((tag, Occurrence::Third)),
        _ => return Err(Status::ConditionsOfUseNotSatisfied),
    };
    get_data(context, GetDataMode::Even, tag)
}

fn filtered_objects(
    options: &Options,
    objects: &'static [GetDataObject],
) -> impl Iterator<Item = &'static GetDataObject> {
    let to_filter = if !options.button_available {
        [
            GetDataObject::UifCds,
            GetDataObject::UifDec,
            GetDataObject::UifAut,
        ]
        .as_slice()
    } else {
        [].as_slice()
    };

    objects.iter().filter(move |o| !to_filter.contains(o))
}

fn get_constructed_data<const R: usize, T: trussed::Client>(
    mut ctx: Context<'_, R, T>,
    objects: &'static [GetDataObject],
) -> Result<(), Status> {
    for obj in filtered_objects(ctx.options, objects) {
        ctx.reply.expand(obj.tag())?;
        let offset = ctx.reply.len();
        match obj.simple_or_constructed() {
            GetDataDoType::Simple(simple) => simple.reply(ctx.lend())?,
            GetDataDoType::Constructed(children) => {
                for inner_obj in filtered_objects(ctx.options, children) {
                    ctx.reply.expand(inner_obj.tag())?;
                    let inner_offset = ctx.reply.len();
                    // We only accept two levels of nesting to avoid recursion
                    inner_obj.into_simple()?.reply(ctx.lend())?;
                    ctx.reply.prepend_len(inner_offset)?;
                }
            }
        }
        ctx.reply.prepend_len(offset)?;
    }
    Ok(())
}

pub fn historical_bytes<const R: usize, T: trussed::Client>(
    mut ctx: Context<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply.expand(&ctx.options.historical_bytes)?;
    let lifecycle_idx = ctx.reply.len() - 3;
    ctx.reply[lifecycle_idx] = State::lifecycle(ctx.backend.client_mut()) as u8;
    Ok(())
}

fn cardholder_cert<const R: usize, T: trussed::Client>(
    ctx: Context<'_, R, T>,
) -> Result<(), Status> {
    let occ = match ctx.state.runtime.cur_do {
        Some((t, occ)) if t.0 == DataObject::CardHolderCertificate as u16 => occ,
        _ => Occurrence::First,
    };
    let to_load = match occ {
        Occurrence::First => ArbitraryDO::CardHolderCertAut,
        Occurrence::Second => ArbitraryDO::CardHolderCertDec,
        Occurrence::Third => ArbitraryDO::CardHolderCertSig,
    };
    get_arbitrary_do(ctx, to_load)
}

fn pw_status_bytes<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let status = PasswordStatus {
        pw1_valid_multiple: ctx.state.internal.pw1_valid_multiple(),
        max_length_pw1: MAX_PIN_LENGTH as u8,
        max_length_rc: MAX_PIN_LENGTH as u8,
        max_length_pw3: MAX_PIN_LENGTH as u8,
        error_counter_pw1: ctx.state.internal.remaining_tries(Password::Pw1),
        // TODO when implementing RESET RETRY COUNTER
        error_counter_rc: 3,
        error_counter_pw3: ctx.state.internal.remaining_tries(Password::Pw3),
    };
    let status: [u8; 7] = status.into();
    ctx.reply.expand(&status)
}

fn algo_info<const R: usize, T: trussed::Client>(mut ctx: Context<'_, R, T>) -> Result<(), Status> {
    for alg in SignatureAlgorithm::iter_all() {
        ctx.reply.expand(&[0xC1])?;
        let offset = ctx.reply.len();
        ctx.reply.expand(alg.attributes())?;
        ctx.reply.prepend_len(offset)?;
    }
    for alg in DecryptionAlgorithm::iter_all() {
        ctx.reply.expand(&[0xC2])?;
        let offset = ctx.reply.len();
        ctx.reply.expand(alg.attributes())?;
        ctx.reply.prepend_len(offset)?;
    }
    for alg in AuthenticationAlgorithm::iter_all() {
        ctx.reply.expand(&[0xC3])?;
        let offset = ctx.reply.len();
        ctx.reply.expand(alg.attributes())?;
        ctx.reply.prepend_len(offset)?;
    }
    Ok(())
}

fn alg_attr_sign<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply
        .expand(ctx.state.internal.sign_alg().attributes())?;
    Ok(())
}

fn alg_attr_dec<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply
        .expand(ctx.state.internal.dec_alg().attributes())?;
    Ok(())
}

fn alg_attr_aut<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply
        .expand(ctx.state.internal.aut_alg().attributes())?;
    Ok(())
}

fn fingerprints<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply.expand(&ctx.state.internal.fingerprints().0)?;
    Ok(())
}

fn ca_fingerprints<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply.expand(&ctx.state.internal.ca_fingerprints().0)?;
    Ok(())
}

fn keygen_dates<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply.expand(&ctx.state.internal.keygen_dates().0)?;
    Ok(())
}

fn key_info_byte(data: Option<KeyOrigin>) -> u8 {
    match data {
        None => 0,
        Some(KeyOrigin::Generated) => 1,
        Some(KeyOrigin::Imported) => 2,
    }
}

fn key_info<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    // Key-Ref. : Sig = 1, Dec = 2, Aut = 3 (see §7.2.18)
    ctx.reply.expand(&[
        0x01,
        key_info_byte(ctx.state.internal.key_origin(KeyType::Sign)),
    ])?;
    ctx.reply.expand(&[
        0x02,
        key_info_byte(ctx.state.internal.key_origin(KeyType::Dec)),
    ])?;
    ctx.reply.expand(&[
        0x03,
        key_info_byte(ctx.state.internal.key_origin(KeyType::Aut)),
    ])?;
    Ok(())
}

fn uif<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
    key: KeyType,
) -> Result<(), Status> {
    if !ctx.options.button_available {
        warn!("GET DAT for uif without a button available");
        return Err(Status::FunctionNotSupported);
    }

    let state_byte = ctx.state.internal.uif(key).as_byte();
    let button_byte = general_feature_management_byte(ctx.options);
    ctx.reply.expand(&[state_byte, button_byte])
}

fn cardholder_name<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply.expand(ctx.state.internal.cardholder_name())
}

fn cardholder_sex<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply
        .expand(&[ctx.state.internal.cardholder_sex() as u8])
}

fn language_preferences<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply.expand(ctx.state.internal.language_preferences())
}

fn signature_counter<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    // Counter is only on 3 bytes
    let resp = &ctx.state.internal.sign_count().to_be_bytes()[1..];
    ctx.reply.expand(resp)
}

fn get_arbitrary_do<const R: usize, T: trussed::Client>(
    mut ctx: Context<'_, R, T>,
    obj: ArbitraryDO,
) -> Result<(), Status> {
    match obj.read_permission() {
        PermissionRequirement::User if !ctx.state.runtime.other_verified => {
            return Err(Status::SecurityStatusNotSatisfied);
        }
        PermissionRequirement::Admin if !ctx.state.runtime.admin_verified => {
            return Err(Status::SecurityStatusNotSatisfied);
        }
        _ => {}
    }

    let data = obj
        .load(ctx.backend.client_mut())
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
    ctx.reply.expand(&data)
}

// § 7.2.8
pub fn put_data<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
    mode: PutDataMode,
    tag: Tag,
) -> Result<(), Status> {
    let object = PutDataObject::try_from(tag).inspect_err_stable(|_err| {
        warn!("Unsupported data tag {:x?}: {:?}", tag, _err);
    })?;

    if mode == PutDataMode::Odd && object != PutDataObject::ExtendedHeaderList {
        warn!("Invalid put data object {object:?} for mode {mode:?}");
        return Err(Status::IncorrectP1OrP2Parameter);
    }

    match object.write_perm() {
        PermissionRequirement::Admin if !context.state.runtime.admin_verified => {
            warn!("Put data for admin authorized object: {object:?}");
            return Err(Status::SecurityStatusNotSatisfied);
        }
        PermissionRequirement::User if !context.state.runtime.other_verified => {
            warn!("Put data for user authorized object: {object:?}");
            return Err(Status::SecurityStatusNotSatisfied);
        }
        _ => {}
    }

    debug!("Writing data for tag {:?}", tag);
    object.put_data(context.lend())?;

    let cur_do = &mut context.state.runtime.cur_do;
    *cur_do = match cur_do {
        Some((t, occ)) if *t == tag => Some((tag, *occ)),
        _ => Some((tag, Occurrence::First)),
    };
    Ok(())
}

enum_subset! {
    /// Data objects available for PUT DATA
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum PutDataObject: DataObject {
        PrivateUse1,
        PrivateUse2,
        PrivateUse3,
        PrivateUse4,
        LoginData,
        ExtendedHeaderList,
        Url,
        CardHolderName,
        CardHolderSex,
        LanguagePreferences,
        CardHolderCertificate,
        AlgorithmAttributesSignature,
        AlgorithmAttributesDecryption,
        AlgorithmAttributesAuthentication,
        PwStatusBytes,
        CaFingerprint1,
        CaFingerprint2,
        CaFingerprint3,
        SignFingerprint,
        DecFingerprint,
        AuthFingerprint,
        SignGenerationDate,
        DecGenerationDate,
        AuthGenerationDate,
        ResettingCode,
        PSOEncDecKey,
        UifCds,
        UifDec,
        UifAut,
        KdfDo,
    }
}

impl PutDataObject {
    fn write_perm(&self) -> PermissionRequirement {
        match self {
            Self::PrivateUse2 | Self::PrivateUse4 => PermissionRequirement::User,
            _ => PermissionRequirement::Admin,
        }
    }

    fn put_data<const R: usize, T: trussed::Client>(
        self,
        mut ctx: Context<'_, R, T>,
    ) -> Result<(), Status> {
        match self {
            Self::PrivateUse1 => put_arbitrary_do(ctx, ArbitraryDO::PrivateUse1)?,
            Self::PrivateUse2 => put_arbitrary_do(ctx, ArbitraryDO::PrivateUse2)?,
            Self::PrivateUse3 => put_arbitrary_do(ctx, ArbitraryDO::PrivateUse3)?,
            Self::PrivateUse4 => put_arbitrary_do(ctx, ArbitraryDO::PrivateUse4)?,
            Self::LoginData => put_arbitrary_do(ctx, ArbitraryDO::LoginData)?,
            Self::ExtendedHeaderList => {
                super::private_key_template::put_private_key_template(ctx.load_state()?)?
            }
            Self::Url => put_arbitrary_do(ctx, ArbitraryDO::Url)?,
            Self::KdfDo => put_arbitrary_do(ctx, ArbitraryDO::KdfDo)?,
            Self::SignFingerprint => put_fingerprint(ctx.load_state()?, KeyType::Sign)?,
            Self::DecFingerprint => put_fingerprint(ctx.load_state()?, KeyType::Dec)?,
            Self::AuthFingerprint => put_fingerprint(ctx.load_state()?, KeyType::Aut)?,
            Self::SignGenerationDate => put_keygen_date(ctx.load_state()?, KeyType::Sign)?,
            Self::DecGenerationDate => put_keygen_date(ctx.load_state()?, KeyType::Dec)?,
            Self::AuthGenerationDate => put_keygen_date(ctx.load_state()?, KeyType::Aut)?,
            Self::CardHolderCertificate => put_cardholder_cert(ctx)?,
            Self::AlgorithmAttributesSignature => put_alg_attributes_sign(ctx.load_state()?)?,
            Self::AlgorithmAttributesDecryption => put_alg_attributes_dec(ctx.load_state()?)?,
            Self::AlgorithmAttributesAuthentication => put_alg_attributes_aut(ctx.load_state()?)?,
            Self::CardHolderName => put_cardholder_name(ctx.load_state()?)?,
            Self::CardHolderSex => put_cardholder_sex(ctx.load_state()?)?,
            Self::LanguagePreferences => put_language_prefs(ctx.load_state()?)?,
            Self::PwStatusBytes => put_status_bytes(ctx.load_state()?)?,
            Self::CaFingerprint1 => put_ca_fingerprint(ctx.load_state()?, KeyType::Aut)?,
            Self::CaFingerprint2 => put_ca_fingerprint(ctx.load_state()?, KeyType::Dec)?,
            Self::CaFingerprint3 => put_ca_fingerprint(ctx.load_state()?, KeyType::Sign)?,
            Self::ResettingCode => put_resetting_code(ctx.load_state()?)?,
            Self::PSOEncDecKey => put_enc_dec_key(ctx.load_state()?)?,
            Self::UifCds => put_uif(ctx.load_state()?, KeyType::Sign)?,
            Self::UifDec => put_uif(ctx.load_state()?, KeyType::Dec)?,
            Self::UifAut => put_uif(ctx.load_state()?, KeyType::Aut)?,
        }
        Ok(())
    }
}

fn put_cardholder_cert<const R: usize, T: trussed::Client>(
    ctx: Context<'_, R, T>,
) -> Result<(), Status> {
    let occ = match ctx.state.runtime.cur_do {
        Some((t, occ)) if t.0 == DataObject::CardHolderCertificate as u16 => occ,
        _ => Occurrence::First,
    };
    let to_write = match occ {
        Occurrence::First => ArbitraryDO::CardHolderCertAut,
        Occurrence::Second => ArbitraryDO::CardHolderCertDec,
        Occurrence::Third => ArbitraryDO::CardHolderCertSig,
    };
    put_arbitrary_do(ctx, to_write)
}

fn put_enc_dec_key<const R: usize, T: trussed::Client>(
    _ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    // TODO: implement
    error!("Put data in even mode not yet implemented");
    Err(Status::FunctionNotSupported)
}

fn put_resetting_code<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    if ctx.data.len() < MIN_LENGTH_RESET_CODE || ctx.data.len() > MAX_PIN_LENGTH {
        warn!(
            "Attempt to set invalid size of resetting code: {}",
            ctx.data.len()
        );
        return Err(Status::IncorrectDataParameter);
    }
    ctx.state
        .internal
        .change_pin(ctx.backend.client_mut(), ctx.data, Password::ResetCode)
        .map_err(|_err| {
            error!("Failed to change resetting code: {_err}");
            Status::UnspecifiedNonpersistentExecutionError
        })
}

fn put_uif<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
    key: KeyType,
) -> Result<(), Status> {
    if !ctx.options.button_available {
        warn!("put uif without button support");
        return Err(Status::FunctionNotSupported);
    }

    if ctx.data.len() != 2 {
        warn!("put uif with incorrect length: {}", ctx.data.len());
        return Err(Status::WrongLength);
    }

    if ctx.data[1] != general_feature_management_byte(ctx.options) {
        warn!("Incorrect GFM byte in put_uif");
        return Err(Status::OperationBlocked);
    }

    if ctx.state.internal.uif(key) == Uif::PermanentlyEnabled {
        return Err(Status::OperationBlocked);
    }

    let uif = Uif::try_from(ctx.data[0]).map_err(|_| Status::IncorrectDataParameter)?;
    ctx.state
        .internal
        .set_uif(ctx.backend.client_mut(), uif, key)
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)
}

fn put_status_bytes<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    if ctx.data.len() != 4 && ctx.data.len() != 1 {
        warn!("put status bytes with incorrect length");
        return Err(Status::WrongLength);
    }

    if ctx.data.len() == 4 && ctx.data[1..] != [MAX_PIN_LENGTH as u8; 3] {
        // Don't support changing max pin length and switching to PIN format 2
        return Err(Status::FunctionNotSupported);
    }

    let flag = match ctx.data[0] {
        0 => false,
        1 => true,
        _input => {
            warn!("Incorrect PW status byte {_input:x}");
            return Err(Status::IncorrectDataParameter)?;
        }
    };

    ctx.state
        .internal
        .set_pw1_valid_multiple(flag, ctx.backend.client_mut())
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;

    Ok(())
}

fn put_language_prefs<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let bytes = if ctx.data.len() % 2 == 0 {
        Bytes::from_slice(ctx.data).ok()
    } else {
        None
    };

    let bytes = bytes.ok_or_else(|| {
        warn!(
            "put language pref with incorrect length: {}",
            ctx.data.len()
        );
        Status::WrongLength
    })?;

    ctx.state
        .internal
        .set_language_preferences(bytes, ctx.backend.client_mut())
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)
}

fn put_cardholder_sex<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    if ctx.data.len() != 1 {
        warn!(
            "put CardHolder sex length different than 1 byte: {:x?}",
            ctx.data
        );
        return Err(Status::WrongLength);
    }

    let sex = Sex::try_from(ctx.data[0]).inspect_err_stable(|_| {
        warn!("Incorrect data for Sex: {:x}", ctx.data[0]);
    })?;

    ctx.state
        .internal
        .set_cardholder_sex(sex, ctx.backend.client_mut())
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)
}

fn put_cardholder_name<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let bytes = heapless::Vec::try_from(ctx.data)
        .map_err(|_| {
            warn!(
                "put language pref with incorrect length: {}",
                ctx.data.len()
            );
            Status::WrongLength
        })?
        .into();
    ctx.state
        .internal
        .set_cardholder_name(bytes, ctx.backend.client_mut())
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)
}

fn put_alg_attributes_sign<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let alg = SignatureAlgorithm::try_from(ctx.data).map_err(|_| {
        warn!(
            "PUT DATA for signature attribute for unkown algorithm: {:x?}",
            ctx.data
        );
        Status::IncorrectDataParameter
    })?;

    ctx.state
        .internal
        .set_sign_alg(ctx.backend.client_mut(), alg)
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
}

fn put_alg_attributes_dec<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let alg = DecryptionAlgorithm::try_from(ctx.data).map_err(|_| {
        warn!(
            "PUT DATA for decryption attribute for unkown algorithm: {:x?}",
            ctx.data
        );
        Status::IncorrectDataParameter
    })?;

    ctx.state
        .internal
        .set_dec_alg(ctx.backend.client_mut(), alg)
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
}

fn put_alg_attributes_aut<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let alg = AuthenticationAlgorithm::try_from(ctx.data).map_err(|_| {
        warn!(
            "PUT DATA for authentication attribute for unkown algorithm: {:x?}",
            ctx.data
        );
        Status::IncorrectDataParameter
    })?;

    ctx.state
        .internal
        .set_aut_alg(ctx.backend.client_mut(), alg)
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
}

fn put_arbitrary_do<const R: usize, T: trussed::Client>(
    ctx: Context<'_, R, T>,
    obj: ArbitraryDO,
) -> Result<(), Status> {
    if ctx.data.len() > MAX_GENERIC_LENGTH {
        return Err(Status::WrongLength);
    }
    obj.save(ctx.backend.client_mut(), ctx.data)
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)
}

fn put_fingerprint<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
    for_key: KeyType,
) -> Result<(), Status> {
    if ctx.data.len() != 20 {
        return Err(Status::WrongLength);
    }

    let mut fp = ctx.state.internal.fingerprints();
    fp.key_part_mut(for_key).copy_from_slice(ctx.data);
    ctx.state
        .internal
        .set_fingerprints(ctx.backend.client_mut(), fp)
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
}

fn put_ca_fingerprint<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
    for_key: KeyType,
) -> Result<(), Status> {
    if ctx.data.len() != 20 {
        return Err(Status::WrongLength);
    }
    let mut fp = ctx.state.internal.ca_fingerprints();
    fp.key_part_mut(for_key).copy_from_slice(ctx.data);
    ctx.state
        .internal
        .set_ca_fingerprints(ctx.backend.client_mut(), fp)
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
}

fn put_keygen_date<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
    for_key: KeyType,
) -> Result<(), Status> {
    if ctx.data.len() != 4 {
        return Err(Status::WrongLength);
    }
    let mut dates = ctx.state.internal.keygen_dates();
    dates.key_part_mut(for_key).copy_from_slice(ctx.data);
    ctx.state
        .internal
        .set_keygen_dates(ctx.backend.client_mut(), dates)
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use hex_literal::hex;

    #[test]
    fn tags() {
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

    // See https://www.emvco.com/wp-content/uploads/2017/05/EMV_v4.3_Book_3_Application_Specification_20120607062110791.pdf
    // Annex B1
    #[test]
    fn constructed_tag() {
        // Constructed DOs that don't have any actual nested data and are therefore treated as
        // "simple"
        let filter = [
            GetDataObject::GeneralFeatureManagement,
            GetDataObject::CardHolderCertificate,
            GetDataObject::ExtendedLengthInformation,
            GetDataObject::KdfDo,
            GetDataObject::AlgorithmInformation,
            GetDataObject::SecureMessagingCertificate,
        ];
        for o in GetDataObject::iter_all() {
            if filter.contains(&o) {
                continue;
            }

            let constructed_byte = (o.tag()[0] & 0b00100000) == 0b00100000;
            let contructed_manual = o.into_simple().is_err();
            assert_eq!(
                constructed_byte,
                contructed_manual,
                "Constructed byte and static data do not match for {o:?}, of tag {:x?}",
                o.tag()
            )
        }
    }

    #[test]
    fn max_nesting() {
        for o in GetDataObject::iter_all() {
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

    #[test]
    fn constructed_dos_tlv() {
        trussed::virt::with_ram_client("constructed_dos_tlv", |client| {
            use crate::state::{self, State};
            use crate::tlv::*;
            let mut backend = crate::backend::Backend::new(client);
            let mut reply: heapless::Vec<u8, 1024> = Default::default();
            let runtime = Default::default();
            let internal = state::Internal::test_default();
            let options = Default::default();
            let mut state = State {
                internal: Some(internal),
                runtime,
            };

            let context = Context {
                state: &mut state,
                backend: &mut backend,
                data: &[],
                options: &options,
                reply: crate::card::reply::Reply(&mut reply),
            };

            let mut historical_bytes = options.historical_bytes.clone();
            historical_bytes[7] = 5;

            get_data(
                context,
                GetDataMode::Even,
                Tag(DataObject::ApplicationRelatedData as u16),
            )
            .unwrap();
            let top: &[(DataObject, &[u8])] = &[
                (DataObject::ApplicationIdentifier, &options.aid()),
                (DataObject::HistoricalBytes, &historical_bytes),
                (DataObject::ExtendedLengthInformation, &EXTENDED_LENGTH_INFO),
                (DataObject::GeneralFeatureManagement, &hex!("81 01 20")),
                //(DataObject::DiscretionaryDataObjects, &hex!("")),
            ];

            for (tag, data) in top {
                let res = get_do(&[*tag as u16], &reply).unwrap();
                assert_eq!(res, *data, "got {res:x?}, expected {data:x?}")
            }

            let nested: &[(DataObject, &[u8])] = &[
                (DataObject::ExtendedCapabilities, &EXTENDED_CAPABILITIES),
                (
                    DataObject::AlgorithmAttributesSignature,
                    SignatureAlgorithm::Rsa2k.attributes(),
                ),
                (
                    DataObject::AlgorithmAttributesDecryption,
                    DecryptionAlgorithm::Rsa2k.attributes(),
                ),
                (
                    DataObject::AlgorithmAttributesAuthentication,
                    AuthenticationAlgorithm::Rsa2k.attributes(),
                ),
                (
                    DataObject::PwStatusBytes,
                    &Into::<[u8; 7]>::into(PasswordStatus {
                        pw1_valid_multiple: false,
                        max_length_pw1: 127,
                        max_length_rc: 127,
                        max_length_pw3: 127,
                        error_counter_pw1: 3,
                        error_counter_rc: 3,
                        error_counter_pw3: 3,
                    }),
                ),
                (DataObject::Fingerprints, &[0; 60]),
                (DataObject::CAFingerprints, &[0; 60]),
                (DataObject::KeyGenerationDates, &[0; 12]),
                (DataObject::KeyInformation, &hex!("010002000300")),
                (DataObject::UifDec, &hex!("00 20")),
                (DataObject::UifCds, &hex!("00 20")),
                (DataObject::UifAut, &hex!("00 20")),
            ];
            for (tag, data) in nested {
                let res = get_do(
                    &[DataObject::DiscretionaryDataObjects as u16, *tag as u16],
                    &reply,
                )
                .unwrap();
                assert_eq!(res, *data, "got {res:x?}, expected {data:x?}")
            }
        });
    }

    #[test]
    fn ef_dir_format() {
        use crate::tlv::*;
        assert_eq!(get_do(&[0x61], EF_DIR).unwrap().len() + 2, EF_DIR.len());
        assert_eq!(
            get_do(&[0x61, 0x4F], EF_DIR).unwrap(),
            &hex!("D27600012401")
        );
        assert_eq!(get_do(&[0x61, 0x50], EF_DIR).unwrap(), b"OpenPGP");
    }
}
