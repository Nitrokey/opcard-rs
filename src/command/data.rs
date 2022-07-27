// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use hex_literal::hex;
use iso7816::Status;

use crate::{
    card::{Context, Options},
    command::{GetDataMode, Password, Tag},
    state::{ArbitraryDO, PermissionRequirement, MAX_GENERIC_LENGTH_BE, MAX_PIN_LENGTH},
    utils::InspectErr,
};

/// Creates an enum with an `iter_all` associated function giving an iterator over all variants
macro_rules! iterable_enum {
    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident {
            $($var:ident),+
            $(,)*
        }
    ) => {
        $(#[$outer])*
        $vis enum $name {
            $(
                $var,
            )*
        }

        #[allow(unused)]
        impl $name {
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
            Self::ExtendedLengthInformation => context.extend_reply(&EXTENDED_LENGTH_INFO)?,
            Self::ExtendedCapabilities => context.extend_reply(&EXTENDED_CAPABILITIES)?,
            Self::GeneralFeatureManagement => {
                context.extend_reply(general_feature_management(context.options))?
            }
            Self::AlgorithmAttributesSignature => alg_attr_sign(context)?,
            Self::AlgorithmAttributesDecryption => alg_attr_dec(context)?,
            Self::AlgorithmAttributesAuthentication => alg_attr_aut(context)?,
            Self::AlgorithmInformation => algo_info(context)?,
            Self::Fingerprints => fingerprints(context)?,
            Self::CAFingerprints => ca_fingerprints(context)?,
            Self::KeyGenerationDates => keygen_dates(context)?,
            Self::KeyInformation => key_info(context)?,
            Self::UifCds => uid_cds(context)?,
            Self::UifDec => uid_dec(context)?,
            Self::UifAut => uid_aut(context)?,
            Self::CardHolderName => cardholder_name(context)?,
            Self::CardHolderSex => cardholder_sex(context)?,
            Self::LanguagePreferences => language_preferences(context)?,
            Self::Url => arbitrary_do(context, ArbitraryDO::Url)?,
            Self::LoginData => arbitrary_do(context, ArbitraryDO::LoginData)?,
            Self::DigitalSignatureCounter => signature_counter(context)?,
            Self::KdfDo => arbitrary_do(context, ArbitraryDO::KdfDo)?,
            Self::PrivateUse1 => arbitrary_do(context, ArbitraryDO::PrivateUse1)?,
            Self::PrivateUse2 => arbitrary_do(context, ArbitraryDO::PrivateUse2)?,
            Self::PrivateUse3 => arbitrary_do(context, ArbitraryDO::PrivateUse3)?,
            Self::PrivateUse4 => arbitrary_do(context, ArbitraryDO::PrivateUse4)?,
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

iterable_enum! {
    enum SignatureAlgorithms {
        // Part of draft https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/
        Ed255,
        EcDsaP256,
        Rsa2k,
        Rsa4k,
    }
}

impl Default for SignatureAlgorithms {
    fn default() -> Self {
        Self::Rsa2k
    }
}

impl SignatureAlgorithms {
    #[allow(unused)]
    pub fn id(&self) -> u8 {
        self.attributes()[0]
    }

    pub fn attributes(&self) -> &'static [u8] {
        match self {
            Self::Ed255 => &hex!("16 2B 06 01 04 01 DA 47 0F 01"),
            Self::EcDsaP256 => &hex!("13 2A 86 48 CE 3D 03 01 07"),
            Self::Rsa2k => &hex!("
                01
                0800 // Length modulus (in bit): 2048                                                                                                                                        
                0020 // Length exponent (in bit): 32
                00   // 0: Acceptable format is: P and Q
            "),
            Self::Rsa4k => &hex!("
                01
                1000 // Length modulus (in bit): 4096                                                                                                                                        
                0020 // Length exponent (in bit): 32
                00   // 0: Acceptable format is: P and Q
            "),
        }
    }

    #[allow(unused)]
    pub fn oid(&self) -> &'static [u8] {
        &self.attributes()[1..]
    }
}

iterable_enum! {
    enum DecryptionAlgorithms {
        // Part of draft https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/
        X255,
        EcDhP256,
        Rsa2k,
        Rsa4k,
    }
}

impl Default for DecryptionAlgorithms {
    fn default() -> Self {
        Self::Rsa2k
    }
}

impl DecryptionAlgorithms {
    #[allow(unused)]
    pub fn id(&self) -> u8 {
        match self {
            Self::X255 | Self::EcDhP256 => 0x12,
            Self::Rsa2k | Self::Rsa4k => 0x1,
        }
    }

    pub fn attributes(&self) -> &'static [u8] {
        match self {
            Self::X255=> &hex!("12 2B 06 01 04 01 97 55 01 05 01"),
            Self::EcDhP256=> &hex!("12 2A 86 48 CE 3D 03 01 07"),
            Self::Rsa2k => &hex!("
                01
                0800 // Length modulus (in bit): 2048                                                                                                                                        
                0020 // Length exponent (in bit): 32
                00   // 0: Acceptable format is: P and Q
            "),
            Self::Rsa4k => &hex!("
                01
                1000 // Length modulus (in bit): 4096                                                                                                                                        
                0020 // Length exponent (in bit): 32
                00   // 0: Acceptable format is: P and Q
            "),
        }
    }

    #[allow(unused)]
    pub fn oid(&self) -> &'static [u8] {
        &self.attributes()[1..]
    }
}

iterable_enum! {
    enum AuthenticationAlgorithms {
        // Part of draft https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/
        X255,
        EcDhP256,
        Rsa2k,
        Rsa4k,
    }
}

impl Default for AuthenticationAlgorithms {
    fn default() -> Self {
        Self::Rsa2k
    }
}

impl AuthenticationAlgorithms {
    #[allow(unused)]
    pub fn id(&self) -> u8 {
        match self {
            Self::X255 | Self::EcDhP256 => 0x12,
            Self::Rsa2k | Self::Rsa4k => 0x1,
        }
    }

    pub fn attributes(&self) -> &'static [u8] {
        match self {
            Self::X255=> &hex!("12 2B 06 01 04 01 97 55 01 05 01"),
            Self::EcDhP256=> &hex!("12 2A 86 48 CE 3D 03 01 07"),
            Self::Rsa2k => &hex!("
                01
                0800 // Length modulus (in bit): 2048                                                                                                                                        
                0020 // Length exponent (in bit): 32
                00   // 0: Acceptable format is: P and Q
            "),
            Self::Rsa4k => &hex!("
                01
                1000 // Length modulus (in bit): 4096                                                                                                                                        
                0020 // Length exponent (in bit): 32
                00   // 0: Acceptable format is: P and Q
            "),
        }
    }

    #[allow(unused)]
    pub fn oid(&self) -> &'static [u8] {
        &self.attributes()[1..]
    }
}

fn general_feature_management(options: &Options) -> &'static [u8] {
    if options.button_available {
        &hex!("81 01 20")
    } else {
        &hex!("81 01 00")
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
    let object = GetDataObject::try_from(tag)
        .inspect_err_stable(|err| log::warn!("Unsupported data tag {:x?}: {:?}", tag, err))?;
    if !object.is_visible() {
        log::warn!("Get data for children object: {object:?}");
        // Don't return error because GnuPG asks for them anyway
        //return Err(Status::IncorrectDataParameter);
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
        let mut tmp_ctx = Context {
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
                    tmp_ctx.extend_reply(inner_obj.tag())?;
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

pub fn algo_info<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
) -> Result<(), Status> {
    for alg in SignatureAlgorithms::iter_all() {
        context.extend_reply(&[0xC1])?;
        let offset = context.reply.len();
        context.extend_reply(alg.attributes())?;
        prepend_len(context.reply, offset)?;
    }
    for alg in DecryptionAlgorithms::iter_all() {
        context.extend_reply(&[0xC2])?;
        let offset = context.reply.len();
        context.extend_reply(alg.attributes())?;
        prepend_len(context.reply, offset)?;
    }
    for alg in AuthenticationAlgorithms::iter_all() {
        context.extend_reply(&[0xC3])?;
        let offset = context.reply.len();
        context.extend_reply(alg.attributes())?;
        prepend_len(context.reply, offset)?;
    }
    Ok(())
}

pub fn alg_attr_sign<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
) -> Result<(), Status> {
    // TODO load correct algorithm from state
    context.extend_reply(SignatureAlgorithms::default().attributes())?;
    Ok(())
}

pub fn alg_attr_dec<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
) -> Result<(), Status> {
    // TODO load correct algorithm from state
    context.extend_reply(DecryptionAlgorithms::default().attributes())?;
    Ok(())
}

pub fn alg_attr_aut<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
) -> Result<(), Status> {
    // TODO load correct algorithm from state
    context.extend_reply(AuthenticationAlgorithms::default().attributes())?;
    Ok(())
}

pub fn fingerprints<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
) -> Result<(), Status> {
    // TODO load from state
    context.extend_reply(&[0; 60])?;
    Ok(())
}

pub fn ca_fingerprints<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
) -> Result<(), Status> {
    // TODO load from state
    context.extend_reply(&[0; 60])?;
    Ok(())
}

pub fn keygen_dates<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
) -> Result<(), Status> {
    // TODO load from state
    context.extend_reply(&[0; 12])?;
    Ok(())
}

pub fn key_info<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
) -> Result<(), Status> {
    // TODO load from state
    // Key-Ref. : Sig = 1, Dec = 2, Aut = 3 (see §7.2.18)
    context.extend_reply(&hex!(
        "
        01 00 // Sign key not present
        02 00 // Dec key not present
        03 00 // Aut key not present
    "
    ))?;
    Ok(())
}

pub fn uid_cds<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
) -> Result<(), Status> {
    // TODO load correct status from state
    if context.options.button_available {
        context.extend_reply(&hex!("00 20"))
    } else {
        context.extend_reply(&hex!("00 00"))
    }
}

pub fn uid_dec<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
) -> Result<(), Status> {
    // TODO load correct status from state
    if context.options.button_available {
        context.extend_reply(&hex!("00 20"))
    } else {
        context.extend_reply(&hex!("00 00"))
    }
}

pub fn uid_aut<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
) -> Result<(), Status> {
    // TODO load correct status from state
    if context.options.button_available {
        context.extend_reply(&hex!("00 20"))
    } else {
        context.extend_reply(&hex!("00 00"))
    }
}

pub fn cardholder_name<const R: usize, T: trussed::Client>(
    context: Context<'_, R, T>,
) -> Result<(), Status> {
    let internal = context
        .backend
        .load_internal(&mut context.state.internal)
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
    context
        .reply
        .extend_from_slice(internal.cardholder_name.as_bytes())
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
}

pub fn cardholder_sex<const R: usize, T: trussed::Client>(
    context: Context<'_, R, T>,
) -> Result<(), Status> {
    let internal = context
        .backend
        .load_internal(&mut context.state.internal)
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
    context
        .reply
        .extend_from_slice(&[internal.cardholder_sex as u8])
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
}

pub fn language_preferences<const R: usize, T: trussed::Client>(
    context: Context<'_, R, T>,
) -> Result<(), Status> {
    let internal = context
        .backend
        .load_internal(&mut context.state.internal)
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
    context
        .reply
        .extend_from_slice(internal.language_preferences.as_bytes())
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
}

pub fn signature_counter<const R: usize, T: trussed::Client>(
    context: Context<'_, R, T>,
) -> Result<(), Status> {
    let internal = context
        .backend
        .load_internal(&mut context.state.internal)
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;

    // Counter is only on 3 bytes
    let resp = &internal.sign_count.to_be_bytes()[1..];
    context
        .reply
        .extend_from_slice(resp)
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
}

pub fn arbitrary_do<const R: usize, T: trussed::Client>(
    mut context: Context<'_, R, T>,
    obj: ArbitraryDO,
) -> Result<(), Status> {
    match obj.read_permission() {
        PermissionRequirement::User if !context.state.runtime.other_verified => {
            return Err(Status::SecurityStatusNotSatisfied);
        }
        PermissionRequirement::Admin if !context.state.runtime.admin_verified => {
            return Err(Status::SecurityStatusNotSatisfied);
        }
        _ => {}
    }

    let data = obj
        .load(context.backend.client_mut())
        .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
    context.extend_reply(&data)
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
    fn attributes_id() {
        for alg in SignatureAlgorithms::iter_all() {
            assert_eq!(alg.id(), alg.attributes()[0]);
        }

        for alg in DecryptionAlgorithms::iter_all() {
            assert_eq!(alg.id(), alg.attributes()[0]);
        }

        for alg in AuthenticationAlgorithms::iter_all() {
            assert_eq!(alg.id(), alg.attributes()[0]);
        }
    }
}
