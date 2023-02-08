// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use core::mem::swap;

use heapless_bytes::Bytes;
use hex_literal::hex;
use iso7816::Status;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_repr::{Deserialize_repr, Serialize_repr};
use subtle::ConstantTimeEq;

use trussed::api::reply::Metadata;
use trussed::config::MAX_MESSAGE_LENGTH;
use trussed::try_syscall;
use trussed::types::{KeyId, Location, PathBuf};

use crate::command::Password;
use crate::error::Error;
use crate::types::*;
use crate::utils::serde_bytes;

/// Maximum supported length for PW1 and PW3
pub const MAX_PIN_LENGTH: usize = 127;
pub const MIN_LENGTH_RESET_CODE: usize = 8;
pub const MIN_LENGTH_ADMIN_PIN: usize = 8;
pub const MIN_LENGTH_USER_PIN: usize = 6;

/// Default value for PW1
pub const DEFAULT_USER_PIN: &[u8] = b"123456";
/// Default value for PW3
pub const DEFAULT_ADMIN_PIN: &[u8] = b"12345678";

/// Maximum length for generic DOs, limited by the length in trussed `read_file` command.
pub const MAX_GENERIC_LENGTH: usize = MAX_MESSAGE_LENGTH;
/// Big endian encoding of [MAX_GENERIC_LENGTH](MAX_GENERIC_LENGTH)
pub const MAX_GENERIC_LENGTH_BE: [u8; 2] = (MAX_GENERIC_LENGTH as u16).to_be_bytes();

macro_rules! enum_u8 {
    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident {
            $($var:ident = $num:expr),+
            $(,)*
        }
    ) => {
        $(#[$outer])*
        #[repr(u8)]
        $vis enum $name {
            $(
                $var = $num,
            )*
        }

        impl TryFrom<u8> for $name {
            type Error = Status;
            fn try_from(val: u8) -> ::core::result::Result<Self, Status> {
                match val {
                    $(
                        $num => Ok($name::$var),
                    )*
                    _ => Err(Status::KeyReferenceNotFound)
                }
            }
        }
    }
}

macro_rules! concatenated_key_newtype {
    (
        $(#[$outer:meta])*
        $vis:vis struct $name:ident ($inner_vis:vis [u8; $N:literal]);
    ) => {
        $(#[$outer])*
        $vis struct $name($inner_vis [u8; $N]);

        impl Default for $name {
            fn default() -> $name {
                $name([0;$N])
            }
        }

        impl $name {
            pub fn key_part_mut(&mut self, key: KeyType) -> &mut [u8] {
                let offset = self.key_offset(key);
                &mut self.0[offset..][..$N/3]
            }
        }

        // Custom (De)Serialize impls using serde_bytes
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serde_bytes::serialize(&self.0, serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                serde_bytes::deserialize(deserializer).map(|i| $name(i))
            }
        }

    }
}

concatenated_key_newtype! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct Fingerprints(pub [u8; 60]);
}

concatenated_key_newtype! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct CaFingerprints(pub [u8; 60]);
}

concatenated_key_newtype! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct KeyGenDates(pub [u8; 12]);
}

impl Fingerprints {
    fn key_offset(&self, for_key: KeyType) -> usize {
        match for_key {
            KeyType::Sign => 0,
            KeyType::Dec => 20,
            KeyType::Aut => 40,
        }
    }
}

impl KeyGenDates {
    fn key_offset(&self, for_key: KeyType) -> usize {
        match for_key {
            KeyType::Sign => 0,
            KeyType::Dec => 4,
            KeyType::Aut => 8,
        }
    }
}

impl CaFingerprints {
    fn key_offset(&self, for_key: KeyType) -> usize {
        match for_key {
            KeyType::Sign => 40,
            KeyType::Dec => 20,
            KeyType::Aut => 0,
        }
    }
}

/// Life cycle status byte, see § 6
#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub enum LifeCycle {
    Initialization = 0x03,
    Operational = 0x05,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    // Persistent state may not be loaded, or may error when loaded
    pub persistent: Option<Persistent>,
    pub volatile: Volatile,
}

impl State {
    /// Loads the persistent state from flash
    pub fn load<'s, T: trussed::Client>(
        &'s mut self,
        client: &mut T,
    ) -> Result<LoadedState<'s>, Error> {
        // This would be the correct way but it doesn't compile because of
        // https://github.com/rust-lang/rust/issues/47680 (I think)
        //if let Some(persistent) = self.persistent.as_mut() {
        //    Ok(LoadedState {
        //        persistent,
        //        volatile: &mut self.volatile,
        //    })
        //} else {
        //    Ok(LoadedState {
        //        persistent: self.persistent.insert(Persistent::load(client)?),
        //        volatile: &mut self.volatile,
        //    })
        //}

        if self.persistent.is_none() {
            self.persistent = Some(Persistent::load(client)?);
        }

        #[allow(clippy::unwrap_used)]
        Ok(LoadedState {
            persistent: self.persistent.as_mut().unwrap(),
            volatile: &mut self.volatile,
        })
    }

    const LIFECYCLE_PATH: &'static str = "lifecycle.empty";
    fn lifecycle_path() -> PathBuf {
        PathBuf::from(Self::LIFECYCLE_PATH)
    }
    pub fn lifecycle(client: &mut impl trussed::Client) -> LifeCycle {
        match try_syscall!(client.entry_metadata(Location::Internal, Self::lifecycle_path())) {
            Ok(Metadata { metadata: Some(_) }) => LifeCycle::Initialization,
            _ => LifeCycle::Operational,
        }
    }

    pub fn terminate_df(client: &mut impl trussed::Client) -> Result<(), Status> {
        try_syscall!(client.write_file(
            Location::Internal,
            Self::lifecycle_path(),
            Bytes::new(),
            None,
        ))
        .map(|_| {})
        .map_err(|_err| {
            error!("Failed to write lifecycle: {_err:?}");
            Status::UnspecifiedPersistentExecutionError
        })
    }

    pub fn activate_file(client: &mut impl trussed::Client) -> Result<(), Status> {
        try_syscall!(client.remove_file(Location::Internal, Self::lifecycle_path(),)).ok();
        // Errors can happen because of the removal of all files before the call to activate_file
        // so they are silenced
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct LoadedState<'s> {
    pub persistent: &'s mut Persistent,
    pub volatile: &'s mut Volatile,
}

impl<'a> LoadedState<'a> {
    /// Lend the state
    ///
    /// The resulting `LoadedState` has a shorter lifetime than the original one, meaning that it
    /// can be passed by value to other functions and the original state can then be used again
    pub fn lend(&mut self) -> LoadedState {
        LoadedState {
            persistent: self.persistent,
            volatile: self.volatile,
        }
    }
}

enum_u8! {
    #[derive(Clone, Debug, Eq, PartialEq, Copy, Deserialize_repr, Serialize_repr)]
    pub enum Sex {
        NotKnown = 0x30,
        Male = 0x31,
        Female = 0x32,
        NotApplicable = 0x39,
    }
}

impl Default for Sex {
    fn default() -> Sex {
        Sex::NotKnown
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum KeyOrigin {
    /// From GENERATE ASYMETRIC KEYPAIR
    Generated,
    Imported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Persistent {
    user_pin_tries: u8,
    admin_pin_tries: u8,
    reset_code_tries: u8,
    pw1_valid_multiple: bool,
    user_pin: Bytes<MAX_PIN_LENGTH>,
    admin_pin: Bytes<MAX_PIN_LENGTH>,
    reset_code_pin: Option<Bytes<MAX_PIN_LENGTH>>,
    signing_key: Option<(KeyId, KeyOrigin)>,
    confidentiality_key: Option<(KeyId, KeyOrigin)>,
    aut_key: Option<(KeyId, KeyOrigin)>,
    aes_key: Option<KeyId>,
    sign_alg: SignatureAlgorithm,
    dec_alg: DecryptionAlgorithm,
    aut_alg: AuthenticationAlgorithm,
    fingerprints: Fingerprints,
    ca_fingerprints: CaFingerprints,
    keygen_dates: KeyGenDates,

    cardholder_name: Bytes<39>,
    cardholder_sex: Sex,
    language_preferences: Bytes<8>,
    sign_count: u32,
    uif_sign: Uif,
    uif_dec: Uif,
    uif_aut: Uif,
}

impl Persistent {
    const FILENAME: &'static str = "persistent-state.cbor";
    // § 4.3
    const MAX_RETRIES: u8 = 3;

    #[allow(clippy::unwrap_used)]
    fn default() -> Self {
        // § 4.3.1
        let admin_pin = Bytes::from_slice(DEFAULT_ADMIN_PIN).unwrap();
        let user_pin = Bytes::from_slice(DEFAULT_USER_PIN).unwrap();
        Self {
            user_pin_tries: 0,
            admin_pin_tries: 0,
            reset_code_tries: 0,
            reset_code_pin: None,
            pw1_valid_multiple: false,
            admin_pin,
            user_pin,
            cardholder_name: Bytes::new(),
            cardholder_sex: Sex::default(),
            language_preferences: Bytes::new(),
            sign_count: 0,
            signing_key: None,
            confidentiality_key: None,
            aut_key: None,
            aes_key: None,
            sign_alg: SignatureAlgorithm::default(),
            dec_alg: DecryptionAlgorithm::default(),
            aut_alg: AuthenticationAlgorithm::default(),
            fingerprints: Fingerprints::default(),
            ca_fingerprints: CaFingerprints::default(),
            keygen_dates: KeyGenDates::default(),
            uif_sign: Uif::Disabled,
            uif_dec: Uif::Disabled,
            uif_aut: Uif::Disabled,
        }
    }

    #[cfg(test)]
    pub fn test_default() -> Self {
        Self::default()
    }

    fn path() -> PathBuf {
        PathBuf::from(Self::FILENAME)
    }

    pub fn load<T: trussed::Client>(client: &mut T) -> Result<Self, Error> {
        if let Some(data) = load_if_exists(client, Location::Internal, &Self::path())? {
            trussed::cbor_deserialize(&data).map_err(|_err| {
                error!("failed to deserialize persistent state: {_err}");
                Error::Loading
            })
        } else {
            Ok(Self::default())
        }
    }

    pub fn save<T: trussed::Client>(&self, client: &mut T) -> Result<(), Error> {
        let msg = trussed::cbor_serialize_bytes(&self).map_err(|_err| {
            error!("Failed to serialize: {_err}");
            Error::Saving
        })?;
        try_syscall!(client.write_file(Location::Internal, Self::path(), msg, None)).map_err(
            |_err| {
                error!("Failed to store data: {_err:?}");
                Error::Saving
            },
        )?;
        Ok(())
    }

    pub fn remaining_tries(&self, password: Password) -> u8 {
        match password {
            Password::Pw1 => Self::MAX_RETRIES.saturating_sub(self.user_pin_tries),
            Password::Pw3 => Self::MAX_RETRIES.saturating_sub(self.admin_pin_tries),
            Password::ResetCode => Self::MAX_RETRIES.saturating_sub(self.reset_code_tries),
        }
    }

    pub fn is_locked(&self, password: Password) -> bool {
        match password {
            Password::Pw1 => self.user_pin_tries >= Self::MAX_RETRIES,
            Password::Pw3 => self.admin_pin_tries >= Self::MAX_RETRIES,
            Password::ResetCode => self.reset_code_tries >= Self::MAX_RETRIES,
        }
    }

    pub fn decrement_counter<T: trussed::Client>(
        &mut self,
        client: &mut T,
        password: Password,
    ) -> Result<(), Error> {
        if !self.is_locked(password) {
            match password {
                Password::Pw1 => self.user_pin_tries += 1,
                Password::Pw3 => self.admin_pin_tries += 1,
                Password::ResetCode => self.reset_code_tries += 1,
            }
            self.save(client)
        } else {
            Ok(())
        }
    }

    pub fn reset_counter<T: trussed::Client>(
        &mut self,
        client: &mut T,
        password: Password,
    ) -> Result<(), Error> {
        match password {
            Password::Pw1 => self.user_pin_tries = 0,
            Password::Pw3 => self.admin_pin_tries = 0,
            Password::ResetCode => self.reset_code_tries = 0,
        }
        self.save(client)
    }

    fn pin(&self, password: Password) -> Option<&[u8]> {
        match password {
            Password::Pw1 => Some(&self.user_pin),
            Password::Pw3 => Some(&self.admin_pin),
            Password::ResetCode => self.reset_code_pin.as_ref().map(|d| &d[..]),
        }
    }

    pub fn verify_pin<T: trussed::Client>(
        &mut self,
        client: &mut T,
        value: &[u8],
        password: Password,
    ) -> Result<(), Error> {
        if self.is_locked(password) {
            return Err(Error::TooManyTries);
        }

        self.decrement_counter(client, password)?;
        let pin = self.pin(password).ok_or(Error::BadRequest)?;
        if (!value.ct_eq(pin)).into() {
            return Err(Error::InvalidPin);
        }

        self.reset_counter(client, password)?;
        Ok(())
    }

    /// Panics if password is ResetCode, use [reset_code_len](Self::reset_code_len) instead
    pub fn pin_len(&self, password: Password) -> usize {
        match password {
            Password::Pw1 => self.user_pin.len(),
            Password::Pw3 => self.admin_pin.len(),
            Password::ResetCode => unreachable!(),
        }
    }

    /// Returns None if no code has been set
    pub fn reset_code_len(&self) -> Option<usize> {
        self.reset_code_pin.as_ref().map(|d| d.len())
    }

    pub fn change_pin<T: trussed::Client>(
        &mut self,
        client: &mut T,
        value: &[u8],
        password: Password,
    ) -> Result<(), Error> {
        let new_pin = Bytes::from_slice(value).map_err(|_| Error::RequestTooLarge)?;
        let (pin, tries) = match password {
            Password::Pw1 => (&mut self.user_pin, &mut self.user_pin_tries),
            Password::Pw3 => (&mut self.admin_pin, &mut self.admin_pin_tries),
            Password::ResetCode => {
                self.reset_code_pin = Some(Default::default());
                (
                    #[allow(clippy::unwrap_used)]
                    self.reset_code_pin.as_mut().unwrap(),
                    &mut self.reset_code_tries,
                )
            }
        };
        *pin = new_pin;
        *tries = 0;
        self.save(client)
    }

    pub fn remove_reset_code<T: trussed::Client>(&mut self, client: &mut T) -> Result<(), Error> {
        self.reset_code_tries = 0;
        self.reset_code_pin = None;
        self.save(client)
    }

    pub fn sign_alg(&self) -> SignatureAlgorithm {
        self.sign_alg
    }

    pub fn set_sign_alg(
        &mut self,
        client: &mut impl trussed::Client,
        alg: SignatureAlgorithm,
    ) -> Result<(), Error> {
        if self.sign_alg == alg {
            return Ok(());
        }
        self.delete_key(KeyType::Sign, client)?;
        self.sign_alg = alg;
        self.save(client)
    }

    pub fn dec_alg(&self) -> DecryptionAlgorithm {
        self.dec_alg
    }

    pub fn set_dec_alg(
        &mut self,
        client: &mut impl trussed::Client,
        alg: DecryptionAlgorithm,
    ) -> Result<(), Error> {
        if self.dec_alg == alg {
            return Ok(());
        }
        self.delete_key(KeyType::Dec, client)?;
        self.dec_alg = alg;
        self.save(client)
    }

    pub fn aut_alg(&self) -> AuthenticationAlgorithm {
        self.aut_alg
    }

    pub fn set_aut_alg(
        &mut self,
        client: &mut impl trussed::Client,
        alg: AuthenticationAlgorithm,
    ) -> Result<(), Error> {
        if self.aut_alg == alg {
            return Ok(());
        }
        self.delete_key(KeyType::Aut, client)?;
        self.aut_alg = alg;
        self.save(client)
    }

    pub fn fingerprints(&self) -> Fingerprints {
        self.fingerprints
    }

    pub fn set_fingerprints(
        &mut self,
        client: &mut impl trussed::Client,
        data: Fingerprints,
    ) -> Result<(), Error> {
        self.fingerprints = data;
        self.save(client)
    }

    pub fn ca_fingerprints(&self) -> CaFingerprints {
        self.ca_fingerprints
    }

    pub fn set_ca_fingerprints(
        &mut self,
        client: &mut impl trussed::Client,
        data: CaFingerprints,
    ) -> Result<(), Error> {
        self.ca_fingerprints = data;
        self.save(client)
    }

    pub fn keygen_dates(&self) -> KeyGenDates {
        self.keygen_dates
    }

    pub fn set_keygen_dates(
        &mut self,
        client: &mut impl trussed::Client,
        data: KeyGenDates,
    ) -> Result<(), Error> {
        self.keygen_dates = data;
        self.save(client)
    }

    pub fn uif(&self, key: KeyType) -> Uif {
        match key {
            KeyType::Sign => self.uif_sign,
            KeyType::Dec => self.uif_dec,
            KeyType::Aut => self.uif_aut,
        }
    }

    pub fn set_uif(
        &mut self,
        client: &mut impl trussed::Client,
        uif: Uif,
        key: KeyType,
    ) -> Result<(), Error> {
        match key {
            KeyType::Sign => self.uif_sign = uif,
            KeyType::Dec => self.uif_dec = uif,
            KeyType::Aut => self.uif_aut = uif,
        }
        self.save(client)
    }

    pub fn pw1_valid_multiple(&self) -> bool {
        self.pw1_valid_multiple
    }

    pub fn set_pw1_valid_multiple(
        &mut self,
        value: bool,
        client: &mut impl trussed::Client,
    ) -> Result<(), Error> {
        self.pw1_valid_multiple = value;
        self.save(client)
    }

    pub fn cardholder_name(&self) -> &[u8] {
        &self.cardholder_name
    }

    pub fn set_cardholder_name(
        &mut self,
        value: Bytes<39>,
        client: &mut impl trussed::Client,
    ) -> Result<(), Error> {
        self.cardholder_name = value;
        self.save(client)
    }

    pub fn cardholder_sex(&self) -> Sex {
        self.cardholder_sex
    }

    pub fn set_cardholder_sex(
        &mut self,
        value: Sex,
        client: &mut impl trussed::Client,
    ) -> Result<(), Error> {
        self.cardholder_sex = value;
        self.save(client)
    }

    pub fn language_preferences(&self) -> &[u8] {
        &self.language_preferences
    }

    pub fn set_language_preferences(
        &mut self,
        value: Bytes<8>,
        client: &mut impl trussed::Client,
    ) -> Result<(), Error> {
        self.language_preferences = value;
        self.save(client)
    }

    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }

    pub fn increment_sign_count(&mut self, client: &mut impl trussed::Client) -> Result<(), Error> {
        self.sign_count += 1;
        // Sign count is returned on 3 bytes
        if self.sign_count & 0xffffff == 0 {
            self.sign_count = 0xffffff;
        }
        self.save(client)
    }

    pub fn key_id(&self, ty: KeyType) -> Option<KeyId> {
        match ty {
            KeyType::Sign => self.signing_key,
            KeyType::Dec => self.confidentiality_key,
            KeyType::Aut => self.aut_key,
        }
        .map(|(key_id, _)| key_id)
    }

    pub fn key_origin(&self, ty: KeyType) -> Option<KeyOrigin> {
        match ty {
            KeyType::Sign => self.signing_key,
            KeyType::Dec => self.confidentiality_key,
            KeyType::Aut => self.aut_key,
        }
        .map(|(_, origin)| origin)
    }

    /// If the key id was already set, return the old key_id
    pub fn set_key_id(
        &mut self,
        ty: KeyType,
        mut new: Option<(KeyId, KeyOrigin)>,
        client: &mut impl trussed::Client,
    ) -> Result<Option<(KeyId, KeyOrigin)>, Error> {
        match ty {
            KeyType::Sign => {
                self.sign_count = 0;
                swap(&mut self.signing_key, &mut new)
            }
            KeyType::Dec => swap(&mut self.confidentiality_key, &mut new),
            KeyType::Aut => swap(&mut self.aut_key, &mut new),
        }
        self.save(client)?;
        Ok(new)
    }

    pub fn aes_key(&self) -> &Option<KeyId> {
        &self.aes_key
    }

    pub fn set_aes_key_id(
        &mut self,
        mut new: Option<KeyId>,
        client: &mut impl trussed::Client,
    ) -> Result<Option<KeyId>, Error> {
        swap(&mut self.aes_key, &mut new);
        self.save(client)?;
        Ok(new)
    }

    pub fn delete_key(
        &mut self,
        ty: KeyType,
        client: &mut impl trussed::Client,
    ) -> Result<(), Error> {
        let key = match ty {
            KeyType::Sign => self.signing_key.take(),
            KeyType::Dec => self.confidentiality_key.take(),
            KeyType::Aut => self.aut_key.take(),
        };

        if let Some((key_id, _)) = key {
            self.save(client)?;
            try_syscall!(client.delete(key_id)).map_err(|_err| {
                error!("Failed to delete key {_err:?}");
                Error::Saving
            })?;
            self.fingerprints.key_part_mut(ty).copy_from_slice(&[0; 20]);
            self.keygen_dates.key_part_mut(ty).copy_from_slice(&[0; 4]);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRef {
    Dec,
    Aut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRefs {
    // We can't use `KeyType` because the Signing key cannot be reassigned
    pub pso_decipher: KeyRef,
    pub internal_aut: KeyRef,
}

impl Default for KeyRefs {
    fn default() -> KeyRefs {
        KeyRefs {
            pso_decipher: KeyRef::Dec,
            internal_aut: KeyRef::Aut,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Volatile {
    pub sign_verified: bool,
    pub other_verified: bool,
    pub admin_verified: bool,
    pub cur_do: Option<(Tag, Occurrence)>,
    pub keyrefs: KeyRefs,
}

/// DOs that can store arbitrary data from the user
///
/// They are stored each in their own files and are loaded only
/// when necessary to prevent the state from getting too big.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum ArbitraryDO {
    Url,
    KdfDo,
    PrivateUse1,
    PrivateUse2,
    PrivateUse3,
    PrivateUse4,
    LoginData,
    CardHolderCertAut,
    CardHolderCertDec,
    CardHolderCertSig,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum PermissionRequirement {
    None,
    User,
    Admin,
}

impl ArbitraryDO {
    fn path(self) -> PathBuf {
        PathBuf::from(match self {
            Self::Url => "url",
            Self::KdfDo => "kdf_do",
            Self::PrivateUse1 => "private_use_1",
            Self::PrivateUse2 => "private_use_2",
            Self::PrivateUse3 => "private_use_3",
            Self::PrivateUse4 => "private_use_4",
            Self::LoginData => "login_data",
            Self::CardHolderCertAut => "cardholder_cert_aut",
            Self::CardHolderCertDec => "cardholder_cert_dec",
            Self::CardHolderCertSig => "cardholder_cert_sig",
        })
    }

    fn default(self) -> Bytes<MAX_GENERIC_LENGTH> {
        #[allow(clippy::unwrap_used)]
        match self {
            // KDF-DO initialized to NONE
            Self::KdfDo => Bytes::from_slice(&hex!("F9 03 81 01 00")).unwrap(),
            _ => Bytes::new(),
        }
    }

    pub fn read_permission(self) -> PermissionRequirement {
        match self {
            Self::PrivateUse3 => PermissionRequirement::User,
            Self::PrivateUse4 => PermissionRequirement::Admin,
            _ => PermissionRequirement::None,
        }
    }

    pub fn load(
        self,
        client: &mut impl trussed::Client,
    ) -> Result<Bytes<MAX_GENERIC_LENGTH>, Error> {
        load_if_exists(client, Location::Internal, &self.path())
            .map(|data| data.unwrap_or_else(|| self.default()))
    }

    pub fn save(self, client: &mut impl trussed::Client, bytes: &[u8]) -> Result<(), Error> {
        let msg = Bytes::from(heapless::Vec::try_from(bytes).map_err(|_| {
            error!("Buffer full");
            Error::Saving
        })?);
        try_syscall!(client.write_file(Location::Internal, self.path(), msg, None)).map_err(
            |_err| {
                error!("Failed to store data: {_err:?}");
                Error::Saving
            },
        )?;
        Ok(())
    }
}

fn load_if_exists(
    client: &mut impl trussed::Client,
    location: Location,
    path: &PathBuf,
) -> Result<Option<Bytes<MAX_MESSAGE_LENGTH>>, Error> {
    match try_syscall!(client.read_file(location, path.clone())) {
        Ok(r) => Ok(Some(r.data)),
        Err(_) => match try_syscall!(client.entry_metadata(location, path.clone())) {
            Ok(Metadata { metadata: None }) => Ok(None),
            Ok(Metadata {
                metadata: Some(_metadata),
            }) => {
                error!("File {path} exists but couldn't be read: {_metadata:?}");
                Err(Error::Loading)
            }
            Err(_err) => {
                error!("File {path} couldn't be read: {_err:?}");
                Err(Error::Loading)
            }
        },
    }
}
