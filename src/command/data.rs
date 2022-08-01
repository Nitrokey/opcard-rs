// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use hex_literal::hex;
use iso7816::Status;

use crate::{
    card::{reply::Reply, Context, LoadedContext, Options},
    command::{GetDataMode, Password, PutDataMode, Tag},
    state::{
        ArbitraryDO, PermissionRequirement, MAX_GENERIC_LENGTH, MAX_GENERIC_LENGTH_BE,
        MAX_PIN_LENGTH,
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
            Self::HistoricalBytes => context.reply.expand(&context.options.historical_bytes)?,
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
            Self::CAFingerprints => ca_fingerprints(context)?,
            Self::KeyGenerationDates => keygen_dates(context.load_state()?)?,
            Self::KeyInformation => key_info(context)?,
            Self::UifCds => uif_sign(context.load_state()?)?,
            Self::UifDec => uif_dec(context.load_state()?)?,
            Self::UifAut => uif_aut(context.load_state()?)?,
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
            // TODO revisit with support for GET NEXT DAT/ SELECT DATA
            Self::CardHolderCertificate => {
                get_arbitrary_do(context, ArbitraryDO::CardHolderCertAut)?
            }
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
    let object = GetDataObject::try_from(tag).inspect_err_stable(|_err| {
        warn!("Unsupported data tag {:x?}: {:?}", tag, _err);
    })?;
    if !object.is_visible() {
        warn!("Get data for children object: {object:?}");
        return Err(Status::IncorrectDataParameter);
    }
    debug!("Returning data for tag {:?}", tag);
    match object.simple_or_constructed() {
        GetDataDoType::Simple(obj) => obj.reply(context),
        GetDataDoType::Constructed(objs) => get_constructed_data(context, objs),
    }
}

fn get_constructed_data<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
    objects: &'static [GetDataObject],
) -> Result<(), Status> {
    for obj in objects {
        context.reply.expand(obj.tag())?;
        let offset = context.reply.len();
        // Copied to avoid moving the context
        // This works because the life of tmp_ctx are smaller that that of context
        let mut tmp_ctx = Context {
            reply: Reply(context.reply.0),
            backend: context.backend,
            options: context.options,
            state: context.state,
            data: context.data,
        };
        match obj.simple_or_constructed() {
            GetDataDoType::Simple(simple) => simple.reply(tmp_ctx)?,
            GetDataDoType::Constructed(children) => {
                for inner_obj in children {
                    tmp_ctx.reply.expand(inner_obj.tag())?;
                    let inner_offset = tmp_ctx.reply.len();
                    let inner_tmp_ctx = Context {
                        reply: Reply(tmp_ctx.reply.0),
                        backend: tmp_ctx.backend,
                        options: tmp_ctx.options,
                        state: tmp_ctx.state,
                        data: tmp_ctx.data,
                    };
                    // We only accept two levels of nesting to avoid recursion
                    inner_obj.into_simple()?.reply(inner_tmp_ctx)?;
                    tmp_ctx.reply.prepend_len(inner_offset)?;
                }
            }
        }
        context.reply.prepend_len(offset)?;
    }
    Ok(())
}

pub fn pw_status_bytes<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let status = PasswordStatus {
        // TODO support true
        pw1_valid_multiple: false,
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

pub fn algo_info<const R: usize, T: trussed::Client>(
    mut ctx: Context<'_, R, T>,
) -> Result<(), Status> {
    for alg in SignatureAlgorithms::iter_all() {
        ctx.reply.expand(&[0xC1])?;
        let offset = ctx.reply.len();
        ctx.reply.expand(alg.attributes())?;
        ctx.reply.prepend_len(offset)?;
    }
    for alg in DecryptionAlgorithms::iter_all() {
        ctx.reply.expand(&[0xC2])?;
        let offset = ctx.reply.len();
        ctx.reply.expand(alg.attributes())?;
        ctx.reply.prepend_len(offset)?;
    }
    for alg in AuthenticationAlgorithms::iter_all() {
        ctx.reply.expand(&[0xC3])?;
        let offset = ctx.reply.len();
        ctx.reply.expand(alg.attributes())?;
        ctx.reply.prepend_len(offset)?;
    }
    Ok(())
}

pub fn alg_attr_sign<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply
        .expand(ctx.state.internal.sign_alg().attributes())?;
    Ok(())
}

pub fn alg_attr_dec<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply
        .expand(ctx.state.internal.dec_alg().attributes())?;
    Ok(())
}

pub fn alg_attr_aut<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply
        .expand(ctx.state.internal.aut_alg().attributes())?;
    Ok(())
}

pub fn fingerprints<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply.expand(&ctx.state.internal.fingerprints())?;
    Ok(())
}

pub fn ca_fingerprints<const R: usize, T: trussed::Client>(
    mut ctx: Context<'_, R, T>,
) -> Result<(), Status> {
    // TODO load from state
    ctx.reply.expand(&[0; 60])?;
    Ok(())
}

pub fn keygen_dates<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply.expand(&ctx.state.internal.keygen_dates())?;
    Ok(())
}

pub fn key_info<const R: usize, T: trussed::Client>(
    mut ctx: Context<'_, R, T>,
) -> Result<(), Status> {
    // TODO load from state
    // Key-Ref. : Sig = 1, Dec = 2, Aut = 3 (see §7.2.18)
    ctx.reply.expand(&hex!(
        "
        01 00 // Sign key not present
        02 00 // Dec key not present
        03 00 // Aut key not present
    "
    ))?;
    Ok(())
}

pub fn uif_sign<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let button_byte = general_feature_management_byte(ctx.options);
    let state_byte = ctx.state.internal.uif_sign.as_byte();
    ctx.reply.expand(&[state_byte, button_byte])
}

pub fn uif_dec<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let button_byte = general_feature_management_byte(ctx.options);
    let state_byte = ctx.state.internal.uif_dec.as_byte();
    ctx.reply.expand(&[state_byte, button_byte])
}

pub fn uif_aut<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let button_byte = general_feature_management_byte(ctx.options);
    let state_byte = ctx.state.internal.uif_aut.as_byte();
    ctx.reply.expand(&[state_byte, button_byte])
}

pub fn cardholder_name<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply
        .expand(ctx.state.internal.cardholder_name.as_bytes())
}

pub fn cardholder_sex<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply.expand(&[ctx.state.internal.cardholder_sex as u8])
}

pub fn language_preferences<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    ctx.reply
        .expand(ctx.state.internal.language_preferences.as_bytes())
}

pub fn signature_counter<const R: usize, T: trussed::Client>(
    mut ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    // Counter is only on 3 bytes
    let resp = &ctx.state.internal.sign_count.to_be_bytes()[1..];
    ctx.reply.expand(resp)
}

pub fn get_arbitrary_do<const R: usize, T: trussed::Client>(
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
    context: Context<'_, R, T>,
    mode: PutDataMode,
    tag: Tag,
) -> Result<(), Status> {
    // TODO: curDO pointer
    if mode != PutDataMode::Even {
        unimplemented!();
    }
    let object = PutDataObject::try_from(tag).inspect_err_stable(|_err| {
        warn!("Unsupported data tag {:x?}: {:?}", tag, _err);
    })?;

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
    object.put_data(context)
}

enum_subset! {
    /// Data objects available for PUT DATA
    #[derive(Debug, Clone, Copy)]
    enum PutDataObject: DataObject {
        PrivateUse1,
        PrivateUse2,
        PrivateUse3,
        PrivateUse4,
        LoginData,
        Url,
        HistoricalBytes,
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
        ResetingCode,
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
        ctx: Context<'_, R, T>,
    ) -> Result<(), Status> {
        match self {
            Self::PrivateUse1 => put_arbitrary_do(ctx, ArbitraryDO::PrivateUse1)?,
            Self::PrivateUse2 => put_arbitrary_do(ctx, ArbitraryDO::PrivateUse2)?,
            Self::PrivateUse3 => put_arbitrary_do(ctx, ArbitraryDO::PrivateUse3)?,
            Self::PrivateUse4 => put_arbitrary_do(ctx, ArbitraryDO::PrivateUse4)?,
            Self::LoginData => put_arbitrary_do(ctx, ArbitraryDO::LoginData)?,
            Self::Url => put_arbitrary_do(ctx, ArbitraryDO::Url)?,
            Self::KdfDo => put_arbitrary_do(ctx, ArbitraryDO::KdfDo)?,
            Self::SignFingerprint => put_fingerprint(ctx.load_state()?, KeyType::Sign)?,
            Self::DecFingerprint => put_fingerprint(ctx.load_state()?, KeyType::Confidentiality)?,
            Self::AuthFingerprint => put_fingerprint(ctx.load_state()?, KeyType::Aut)?,
            Self::SignGenerationDate => put_keygen_date(ctx.load_state()?, KeyType::Sign)?,
            Self::DecGenerationDate => {
                put_keygen_date(ctx.load_state()?, KeyType::Confidentiality)?
            }
            Self::AuthGenerationDate => put_keygen_date(ctx.load_state()?, KeyType::Aut)?,
            // TODO support curDo
            Self::CardHolderCertificate => put_arbitrary_do(ctx, ArbitraryDO::CardHolderCertAut)?,
            Self::AlgorithmAttributesSignature => put_alg_attributes_sign(ctx.load_state()?)?,
            Self::AlgorithmAttributesDecryption => put_alg_attributes_dec(ctx.load_state()?)?,
            Self::AlgorithmAttributesAuthentication => put_alg_attributes_aut(ctx.load_state()?)?,
            Self::HistoricalBytes => unimplemented!(),
            Self::CardHolderName => unimplemented!(),
            Self::CardHolderSex => unimplemented!(),
            Self::LanguagePreferences => unimplemented!(),
            Self::PwStatusBytes => unimplemented!(),
            Self::CaFingerprint1 => unimplemented!(),
            Self::CaFingerprint2 => unimplemented!(),
            Self::CaFingerprint3 => unimplemented!(),
            Self::ResetingCode => unimplemented!(),
            Self::PSOEncDecKey => unimplemented!(),
            Self::UifCds => unimplemented!(),
            Self::UifDec => unimplemented!(),
            Self::UifAut => unimplemented!(),
        }
        Ok(())
    }
}
fn put_alg_attributes_sign<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
) -> Result<(), Status> {
    let alg = SignatureAlgorithms::try_from(ctx.data).map_err(|_| {
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
    let alg = DecryptionAlgorithms::try_from(ctx.data).map_err(|_| {
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
    let alg = AuthenticationAlgorithms::try_from(ctx.data).map_err(|_| {
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
    let offset = match for_key {
        KeyType::Sign => 0,
        KeyType::Confidentiality => 20,
        KeyType::Aut => 40,
    };

    let mut fp = ctx.state.internal.fingerprints();
    fp[offset..][..20].copy_from_slice(ctx.data);
    ctx.state
        .internal
        .set_fingerprints(ctx.backend.client_mut(), fp)
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
}

fn put_keygen_date<const R: usize, T: trussed::Client>(
    ctx: LoadedContext<'_, R, T>,
    for_key: KeyType,
) -> Result<(), Status> {
    if ctx.data.len() != 4 {
        return Err(Status::WrongLength);
    }
    let offset = match for_key {
        KeyType::Sign => 0,
        KeyType::Confidentiality => 4,
        KeyType::Aut => 8,
    };
    let mut dates = ctx.state.internal.keygen_dates();
    dates[offset..][..4].copy_from_slice(ctx.data);
    ctx.state
        .internal
        .set_keygen_dates(ctx.backend.client_mut(), dates)
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

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
}
