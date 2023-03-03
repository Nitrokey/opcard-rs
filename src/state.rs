// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use core::mem::swap;

use heapless_bytes::Bytes;
use hex_literal::hex;
use iso7816::Status;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_repr::{Deserialize_repr, Serialize_repr};

use trussed::api::reply::Metadata;
use trussed::config::MAX_MESSAGE_LENGTH;
use trussed::types::{KeyId, Location, PathBuf};
use trussed::{syscall, try_syscall};
use trussed_auth::AuthClient;

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
    pub fn load<'s, T: trussed::Client + AuthClient>(
        &'s mut self,
        client: &mut T,
        storage: Location,
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
            self.persistent = Some(Persistent::load(client, storage)?);
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
    pub fn lifecycle<T: trussed::Client + AuthClient>(
        client: &mut T,
        storage: Location,
    ) -> LifeCycle {
        match try_syscall!(client.entry_metadata(storage, Self::lifecycle_path())) {
            Ok(Metadata { metadata: Some(_) }) => LifeCycle::Initialization,
            _ => LifeCycle::Operational,
        }
    }

    pub fn terminate_df<T: trussed::Client + AuthClient>(
        client: &mut T,
        storage: Location,
    ) -> Result<(), Status> {
        try_syscall!(client.write_file(storage, Self::lifecycle_path(), Bytes::new(), None,))
            .map(|_| {})
            .map_err(|_err| {
                error!("Failed to write lifecycle: {_err:?}");
                Status::UnspecifiedPersistentExecutionError
            })
    }

    pub fn activate_file<T: trussed::Client + AuthClient>(
        client: &mut T,
        storage: Location,
    ) -> Result<(), Status> {
        try_syscall!(client.remove_file(storage, Self::lifecycle_path(),)).ok();
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
    pw1_valid_multiple: bool,
    user_pin_len: u8,
    admin_pin_len: u8,
    reset_code_pin_len: Option<u8>,
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
        Self {
            reset_code_pin_len: None,
            pw1_valid_multiple: false,
            admin_pin_len: DEFAULT_ADMIN_PIN.len() as u8,
            user_pin_len: DEFAULT_USER_PIN.len() as u8,
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
    pub fn test_default<T: trussed::Client + AuthClient>(client: &mut T) -> Result<Self, Error> {
        Self::init_pins(client)?;
        Ok(Self::default())
    }

    fn path() -> PathBuf {
        PathBuf::from(Self::FILENAME)
    }

    fn init_pins<T: trussed::Client + AuthClient>(client: &mut T) -> Result<(), Error> {
        #[allow(clippy::unwrap_used)]
        let default_user_pin = Bytes::from_slice(DEFAULT_USER_PIN).unwrap();
        #[allow(clippy::unwrap_used)]
        let default_admin_pin = Bytes::from_slice(DEFAULT_ADMIN_PIN).unwrap();
        syscall!(client.set_pin(
            Password::Pw1,
            default_user_pin,
            Some(Self::MAX_RETRIES),
            false
        ));
        syscall!(client.set_pin(
            Password::Pw3,
            default_admin_pin,
            Some(Self::MAX_RETRIES),
            false
        ));
        Ok(())
    }
    pub fn load<T: trussed::Client + AuthClient>(
        client: &mut T,
        storage: Location,
    ) -> Result<Self, Error> {
        if let Some(data) = load_if_exists(client, storage, &Self::path())? {
            trussed::cbor_deserialize(&data).map_err(|_err| {
                error!("failed to deserialize persistent state: {_err}");
                Error::Loading
            })
        } else {
            Self::init_pins(client)?;
            Ok(Self::default())
        }
    }

    pub fn save<T: trussed::Client>(&self, client: &mut T, storage: Location) -> Result<(), Error> {
        let msg = trussed::cbor_serialize_bytes(&self).map_err(|_err| {
            error!("Failed to serialize: {_err}");
            Error::Saving
        })?;
        try_syscall!(client.write_file(storage, Self::path(), msg, None)).map_err(|_err| {
            error!("Failed to store data: {_err:?}");
            Error::Saving
        })?;
        Ok(())
    }

    pub fn remaining_tries<T: trussed::Client + AuthClient>(
        &self,
        client: &mut T,
        password: Password,
    ) -> u8 {
        try_syscall!(client.pin_retries(password))
            .map(|r| r.retries.unwrap_or_default())
            .unwrap_or(Self::MAX_RETRIES)
    }

    pub fn is_locked<T: trussed::Client + AuthClient>(
        &self,
        client: &mut T,
        password: Password,
    ) -> bool {
        self.remaining_tries(client, password) == 0
    }

    pub fn verify_pin<T: trussed::Client + AuthClient>(
        &mut self,
        client: &mut T,
        storage: Location,
        value: &[u8],
        password: Password,
    ) -> Result<(), Error> {
        let pin = Bytes::from_slice(value).map_err(|_| {
            warn!("Attempt to verify pin that is too long");
            Error::InvalidPin
        })?;
        let res = try_syscall!(client.check_pin(password, pin.clone()))
            .map_err(|_err| Error::InvalidPin)?;

        if !res.success {
            return Err(Error::InvalidPin);
        }
        // Reset the pin length in case it was incorrect due to the lack of atomicity of operations.
        self.set_pin_len(client, storage, pin.len(), password)?;
        Ok(())
    }

    /// Panics if password is ResetCode, use [reset_code_len](Self::reset_code_len) instead
    pub fn pin_len(&self, password: Password) -> usize {
        match password {
            Password::Pw1 => self.user_pin_len as usize,
            Password::Pw3 => self.admin_pin_len as usize,
            Password::ResetCode => unreachable!(),
        }
    }

    /// Returns None if no code has been set
    pub fn reset_code_len(&self) -> Option<usize> {
        self.reset_code_pin_len.map(Into::into)
    }

    pub fn set_pin<T: trussed::Client + AuthClient>(
        &mut self,
        client: &mut T,
        storage: Location,
        new_value: &[u8],
        password: Password,
    ) -> Result<(), Error> {
        let new_pin = Bytes::from_slice(new_value).map_err(|_| Error::InvalidPin)?;
        syscall!(client.set_pin(password, new_pin.clone(), Some(Self::MAX_RETRIES), false));
        self.set_pin_len(client, storage, new_pin.len(), password)
    }

    pub fn change_pin<T: trussed::Client + AuthClient>(
        &mut self,
        client: &mut T,
        storage: Location,
        old_value: &[u8],
        new_value: &[u8],
        password: Password,
    ) -> Result<(), Error> {
        let new_pin = Bytes::from_slice(new_value).map_err(|_| Error::InvalidPin)?;
        let old_pin = Bytes::from_slice(old_value).map_err(|_| Error::InvalidPin)?;
        try_syscall!(client.change_pin(password, old_pin, new_pin.clone()))
            .map_err(|_| Error::InvalidPin)?;
        self.set_pin_len(client, storage, new_pin.len(), password)
    }

    fn set_pin_len<T: trussed::Client + AuthClient>(
        &mut self,
        client: &mut T,
        storage: Location,
        new_len: usize,
        password: Password,
    ) -> Result<(), Error> {
        match password {
            Password::Pw1 => self.user_pin_len = new_len as u8,
            Password::Pw3 => self.admin_pin_len = new_len as u8,
            Password::ResetCode => self.reset_code_pin_len = Some(new_len as u8),
        }
        self.save(client, storage)
    }

    pub fn remove_reset_code<T: trussed::Client + AuthClient>(
        &mut self,
        client: &mut T,
        storage: Location,
    ) -> Result<(), Error> {
        if self.reset_code_pin_len.is_some() {
            // Possible race condition so we ignore the error
            try_syscall!(client.delete_pin(Password::ResetCode)).ok();
        }
        self.reset_code_pin_len = None;
        self.save(client, storage)
    }

    pub fn sign_alg(&self) -> SignatureAlgorithm {
        self.sign_alg
    }

    pub fn set_sign_alg(
        &mut self,
        client: &mut impl trussed::Client,
        storage: Location,
        alg: SignatureAlgorithm,
    ) -> Result<(), Error> {
        if self.sign_alg == alg {
            return Ok(());
        }
        self.delete_key(KeyType::Sign, client, storage)?;
        self.sign_alg = alg;
        self.save(client, storage)
    }

    pub fn dec_alg(&self) -> DecryptionAlgorithm {
        self.dec_alg
    }

    pub fn set_dec_alg(
        &mut self,
        client: &mut impl trussed::Client,
        storage: Location,
        alg: DecryptionAlgorithm,
    ) -> Result<(), Error> {
        if self.dec_alg == alg {
            return Ok(());
        }
        self.delete_key(KeyType::Dec, client, storage)?;
        self.dec_alg = alg;
        self.save(client, storage)
    }

    pub fn aut_alg(&self) -> AuthenticationAlgorithm {
        self.aut_alg
    }

    pub fn set_aut_alg(
        &mut self,
        client: &mut impl trussed::Client,
        storage: Location,
        alg: AuthenticationAlgorithm,
    ) -> Result<(), Error> {
        if self.aut_alg == alg {
            return Ok(());
        }
        self.delete_key(KeyType::Aut, client, storage)?;
        self.aut_alg = alg;
        self.save(client, storage)
    }

    pub fn fingerprints(&self) -> Fingerprints {
        self.fingerprints
    }

    pub fn set_fingerprints(
        &mut self,
        client: &mut impl trussed::Client,
        storage: Location,
        data: Fingerprints,
    ) -> Result<(), Error> {
        self.fingerprints = data;
        self.save(client, storage)
    }

    pub fn ca_fingerprints(&self) -> CaFingerprints {
        self.ca_fingerprints
    }

    pub fn set_ca_fingerprints(
        &mut self,
        client: &mut impl trussed::Client,
        storage: Location,
        data: CaFingerprints,
    ) -> Result<(), Error> {
        self.ca_fingerprints = data;
        self.save(client, storage)
    }

    pub fn keygen_dates(&self) -> KeyGenDates {
        self.keygen_dates
    }

    pub fn set_keygen_dates(
        &mut self,
        client: &mut impl trussed::Client,
        storage: Location,
        data: KeyGenDates,
    ) -> Result<(), Error> {
        self.keygen_dates = data;
        self.save(client, storage)
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
        storage: Location,
        uif: Uif,
        key: KeyType,
    ) -> Result<(), Error> {
        match key {
            KeyType::Sign => self.uif_sign = uif,
            KeyType::Dec => self.uif_dec = uif,
            KeyType::Aut => self.uif_aut = uif,
        }
        self.save(client, storage)
    }

    pub fn pw1_valid_multiple(&self) -> bool {
        self.pw1_valid_multiple
    }

    pub fn set_pw1_valid_multiple(
        &mut self,
        value: bool,
        client: &mut impl trussed::Client,
        storage: Location,
    ) -> Result<(), Error> {
        self.pw1_valid_multiple = value;
        self.save(client, storage)
    }

    pub fn cardholder_name(&self) -> &[u8] {
        &self.cardholder_name
    }

    pub fn set_cardholder_name(
        &mut self,
        value: Bytes<39>,
        client: &mut impl trussed::Client,
        storage: Location,
    ) -> Result<(), Error> {
        self.cardholder_name = value;
        self.save(client, storage)
    }

    pub fn cardholder_sex(&self) -> Sex {
        self.cardholder_sex
    }

    pub fn set_cardholder_sex(
        &mut self,
        value: Sex,
        client: &mut impl trussed::Client,
        storage: Location,
    ) -> Result<(), Error> {
        self.cardholder_sex = value;
        self.save(client, storage)
    }

    pub fn language_preferences(&self) -> &[u8] {
        &self.language_preferences
    }

    pub fn set_language_preferences(
        &mut self,
        value: Bytes<8>,
        client: &mut impl trussed::Client,
        storage: Location,
    ) -> Result<(), Error> {
        self.language_preferences = value;
        self.save(client, storage)
    }

    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }

    pub fn increment_sign_count(
        &mut self,
        client: &mut impl trussed::Client,
        storage: Location,
    ) -> Result<(), Error> {
        self.sign_count += 1;
        // Sign count is returned on 3 bytes
        if self.sign_count & 0xffffff == 0 {
            self.sign_count = 0xffffff;
        }
        self.save(client, storage)
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
        storage: Location,
    ) -> Result<Option<(KeyId, KeyOrigin)>, Error> {
        match ty {
            KeyType::Sign => {
                self.sign_count = 0;
                swap(&mut self.signing_key, &mut new)
            }
            KeyType::Dec => swap(&mut self.confidentiality_key, &mut new),
            KeyType::Aut => swap(&mut self.aut_key, &mut new),
        }
        self.save(client, storage)?;
        Ok(new)
    }

    pub fn aes_key(&self) -> &Option<KeyId> {
        &self.aes_key
    }

    pub fn set_aes_key_id(
        &mut self,
        mut new: Option<KeyId>,
        client: &mut impl trussed::Client,
        storage: Location,
    ) -> Result<Option<KeyId>, Error> {
        swap(&mut self.aes_key, &mut new);
        self.save(client, storage)?;
        Ok(new)
    }

    pub fn delete_key(
        &mut self,
        ty: KeyType,
        client: &mut impl trussed::Client,
        storage: Location,
    ) -> Result<(), Error> {
        let key = match ty {
            KeyType::Sign => self.signing_key.take(),
            KeyType::Dec => self.confidentiality_key.take(),
            KeyType::Aut => self.aut_key.take(),
        };

        if let Some((key_id, _)) = key {
            self.save(client, storage)?;
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
        storage: Location,
    ) -> Result<Bytes<MAX_GENERIC_LENGTH>, Error> {
        load_if_exists(client, storage, &self.path())
            .map(|data| data.unwrap_or_else(|| self.default()))
    }

    pub fn save(
        self,
        client: &mut impl trussed::Client,
        storage: Location,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let msg = Bytes::from(heapless::Vec::try_from(bytes).map_err(|_| {
            error!("Buffer full");
            Error::Saving
        })?);
        try_syscall!(client.write_file(storage, self.path(), msg, None)).map_err(|_err| {
            error!("Failed to store data: {_err:?}");
            Error::Saving
        })?;
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
