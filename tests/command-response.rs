// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "virt")]

use std::borrow::Cow;

use hex_literal::hex;
use ron::{extensions::Extensions, Options};
use serde::Deserialize;

const LARGE_DATA: [u8; 10 * 1024] = {
    let mut res = [0; 10 * 1024];
    let mut i = 0;
    while i < 10 * 1024 {
        res[i] = i as u8;
        i += 1;
    }
    res
};

#[derive(Deserialize, Debug, PartialEq, Clone, Copy, Default)]
#[repr(u8)]
enum Occurence {
    #[default]
    First = 0,
    Second = 1,
    Third = 2,
}
// iso7816::Status doesn't support serde
#[derive(Deserialize, Debug, PartialEq, Clone, Copy, Default)]
enum Status {
    #[default]
    Success,
    MoreAvailable(u8),
    VerificationFailed,
    RemainingRetries(u8),
    UnspecifiedNonpersistentExecutionError,
    UnspecifiedPersistentExecutionError,
    WrongLength,
    LogicalChannelNotSupported,
    SecureMessagingNotSupported,
    CommandChainingNotSupported,
    SecurityStatusNotSatisfied,
    ConditionsOfUseNotSatisfied,
    OperationBlocked,
    IncorrectDataParameter,
    FunctionNotSupported,
    NotFound,
    NotEnoughMemory,
    IncorrectP1OrP2Parameter,
    KeyReferenceNotFound,
    InstructionNotSupportedOrInvalid,
    ClassNotSupported,
    UnspecifiedCheckingError,
}
#[derive(Debug, Clone, Deserialize)]
enum HexOrStr {
    Hex(String),
    Str(String),
}

impl HexOrStr {
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::Hex(s) => parse_hex(s),
            Self::Str(s) => s.as_bytes().to_vec(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[repr(u16)]
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
    CardHolderRelatedData = 0x0065,
    CardHolderName = 0x005B,
    LanguagePreferences = 0x5F2D,
    CardHolderSex = 0x5F35,
    ApplicationRelatedData = 0x006E,
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
    SecuritySupportTemplate = 0x007A,
    DigitalSignatureCounter = 0x0093,
    CardHolderCertificate = 0x7f21,
    ExtendedLengthInformation = 0x7f66,
    KdfDo = 0x00F9,
    AlgorithmInformation = 0x00FA,
    SecureMessagingCertificate = 0x00FB,
}

fn serialize_len(len: usize) -> heapless::Vec<u8, 3> {
    let mut buf = heapless::Vec::new();
    if let Ok(len) = u8::try_from(len) {
        if len <= 0x7f {
            buf.extend_from_slice(&[len]).ok();
        } else {
            buf.extend_from_slice(&[0x81, len]).ok();
        }
    } else if let Ok(len) = u16::try_from(len) {
        let arr = len.to_be_bytes();
        buf.extend_from_slice(&[0x82, arr[0], arr[1]]).ok();
    }
    buf
}

fn tlv(tag: &[u8], data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::from(tag);
    buf.extend_from_slice(&serialize_len(data.len()));
    buf.extend_from_slice(data);
    buf
}

fn build_command(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: u16) -> Vec<u8> {
    let mut res = vec![cla, ins, p1, p2];
    let lc = data.len();
    let extended = if lc == 0 {
        false
    } else if let Ok(len) = lc.try_into() {
        res.push(len);
        false
    } else {
        let len: u16 = lc.try_into().unwrap();
        res.push(0);
        res.extend_from_slice(&len.to_be_bytes());
        true
    };

    res.extend_from_slice(data);

    if le == 0 {
        return res;
    }

    if let Ok(len) = (le - 1).try_into() {
        let _: u8 = len;
        res.push(len.wrapping_add(1));
    } else if extended {
        res.extend_from_slice(&le.to_be_bytes());
    } else {
        res.push(0);
        res.extend_from_slice(&le.to_be_bytes());
    }

    res
}

impl TryFrom<u16> for Status {
    type Error = u16;
    fn try_from(sw: u16) -> Result<Self, Self::Error> {
        Ok(match sw {
            0x6300 => Self::VerificationFailed,
            sw @ 0x63c0..=0x63cf => Self::RemainingRetries((sw as u8) & 0xf),

            0x6400 => Self::UnspecifiedNonpersistentExecutionError,
            0x6500 => Self::UnspecifiedPersistentExecutionError,

            0x6700 => Self::WrongLength,

            0x6881 => Self::LogicalChannelNotSupported,
            0x6882 => Self::SecureMessagingNotSupported,
            0x6884 => Self::CommandChainingNotSupported,

            0x6982 => Self::SecurityStatusNotSatisfied,
            0x6985 => Self::ConditionsOfUseNotSatisfied,
            0x6983 => Self::OperationBlocked,

            0x6a80 => Self::IncorrectDataParameter,
            0x6a81 => Self::FunctionNotSupported,
            0x6a82 => Self::NotFound,
            0x6a84 => Self::NotEnoughMemory,
            0x6a86 => Self::IncorrectP1OrP2Parameter,
            0x6a88 => Self::KeyReferenceNotFound,

            0x6d00 => Self::InstructionNotSupportedOrInvalid,
            0x6e00 => Self::ClassNotSupported,
            0x6f00 => Self::UnspecifiedCheckingError,

            0x9000 => Self::Success,
            sw @ 0x6100..=0x61FF => Self::MoreAvailable(sw as u8),
            other => return Err(other),
        })
    }
}

#[derive(Deserialize, Debug, Clone, Copy)]
enum KeyType {
    Sign,
    Dec,
    Aut,
}

const ED25519_ATTRIBUTES: &[u8] = hex!("16 2B 06 01 04 01 DA 47 0F 01").as_slice();
const ECDSA_P256_ATTRIBUTES: &[u8] = hex!("13 2A 86 48 CE 3D 03 01 07").as_slice();
const ECDH_P256_ATTRIBUTES: &[u8] = hex!("12 2A 86 48 CE 3D 03 01 07").as_slice();
const X25519_ATTRIBUTES: &[u8] = hex!("12 2B 06 01 04 01 97 55 01 05 01").as_slice();
const RSA_2K_ATTRIBUTES: &[u8] = hex!(
    "01"
    "0800" // Length modulus (in bit): 2048
    "0020" // Length exponent (in bit): 32
    "00"   // import in standard format
)
.as_slice();
const RSA_3K_ATTRIBUTES: &[u8] = hex!(
    "01"
    "0C00" // Length modulus (in bit): 2048
    "0020" // Length exponent (in bit): 32
    "00"   // import in standard format
)
.as_slice();
const RSA_4K_ATTRIBUTES: &[u8] = hex!(
    "01"
    "1000" // Length modulus (in bit): 4096
    "0020" // Length exponent (in bit): 32
    "00"   // import in standard format
)
.as_slice();

#[derive(Deserialize, Debug)]
enum KeyKind {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    X25519,
    Ed25519,
    EcP256,
    DhP256,
    Aes,
}
impl KeyKind {
    pub fn attributes(&self) -> &'static [u8] {
        match self {
            Self::Ed25519 => ED25519_ATTRIBUTES,
            Self::X25519 => X25519_ATTRIBUTES,
            Self::EcP256 => ECDSA_P256_ATTRIBUTES,
            Self::DhP256 => ECDH_P256_ATTRIBUTES,
            Self::Rsa2048 => RSA_2K_ATTRIBUTES,
            Self::Rsa3072 => RSA_3K_ATTRIBUTES,
            Self::Rsa4096 => RSA_4K_ATTRIBUTES,
            Self::Aes => panic!("AES cannot be used outside of decipher"),
        }
    }
    pub fn is_ec(&self) -> bool {
        !matches!(self, Self::Rsa2048 | Self::Rsa4096 | Self::Aes)
    }
    pub fn is_aes(&self) -> bool {
        matches!(self, Self::Aes)
    }
}

impl KeyType {
    fn crt(&self) -> &'static [u8] {
        match self {
            Self::Sign => &[0xB6, 0x00],
            Self::Dec => &[0xB8, 0x00],
            Self::Aut => &[0xA4, 0x00],
        }
    }

    fn attributes_tag(&self) -> u8 {
        match self {
            Self::Sign => 0xC1,
            Self::Dec => 0xC2,
            Self::Aut => 0xC3,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct IoTest {
    name: String,
    cmd_resp: Vec<IoCmd>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
enum OutputMatcher {
    Len(usize),
    // The () at the end are here to workaround a compiler bug. See:
    // https://github.com/rust-lang/rust/issues/89940#issuecomment-1282321806
    And(Cow<'static, [OutputMatcher]>, #[serde(default)] ()),
    Or(Cow<'static, [OutputMatcher]>, #[serde(default)] ()),
    /// HEX data
    Data(Cow<'static, str>),
    Bytes(Cow<'static, [u8]>),
    NonZero,
}

impl Default for OutputMatcher {
    fn default() -> Self {
        MATCH_EMPTY
    }
}

fn parse_hex(data: &str) -> Vec<u8> {
    let tmp: String = data.split_whitespace().collect();
    hex::decode(tmp).unwrap()
}

impl OutputMatcher {
    fn validate(&self, data: &[u8]) -> bool {
        match self {
            Self::NonZero => data.iter().max() != Some(&0),
            Self::Data(expected) => {
                println!("Validating output with {expected}");
                data == parse_hex(expected)
            }
            Self::Bytes(expected) => {
                println!("Validating output with {expected:x?}");
                data == &**expected
            }
            Self::Len(len) => data.len() == *len,
            Self::And(matchers, _) => matchers.iter().filter(|m| !m.validate(data)).count() == 0,
            Self::Or(matchers, _) => matchers.iter().filter(|m| m.validate(data)).count() != 0,
        }
    }
}

#[derive(Deserialize, Debug, Copy, Clone)]
#[repr(u8)]
enum Pin {
    Pw1 = 0x81,
    Pw82 = 0x82,
    Pw3 = 0x83,
}

impl Pin {
    fn default_value(self) -> &'static [u8] {
        match self {
            Pin::Pw1 | Pin::Pw82 => b"123456",
            Pin::Pw3 => b"12345678",
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
enum IoCmd {
    Select,
    IoData {
        input: String,
        #[serde(default)]
        output: OutputMatcher,
        #[serde(default)]
        expected_status: Status,
    },
    Verify {
        pin: Pin,
        /// None means default value
        #[serde(default)]
        value: Option<HexOrStr>,
        #[serde(default)]
        expected_status: Status,
    },
    Change {
        pin: Pin,
        /// None means default value
        #[serde(default)]
        new_value: Option<HexOrStr>,
        /// None means default value
        #[serde(default)]
        old_value: Option<HexOrStr>,
        #[serde(default)]
        expected_status: Status,
    },
    PutData {
        tag: DataObject,
        value: String,
        #[serde(default)]
        occurence: Option<Occurence>,
        /// None means default value
        #[serde(default)]
        expected_status: Status,
    },
    PutLargeData {
        tag: DataObject,
        start: u8,
        len: usize,
        #[serde(default)]
        occurence: Option<Occurence>,
        /// None means default value
        #[serde(default)]
        expected_status: Status,
    },
    GetData {
        tag: DataObject,
        expected_value: String,
        #[serde(default)]
        occurence: Option<Occurence>,
        /// None means default value
        #[serde(default)]
        expected_status: Status,
    },
    GetLargeData {
        tag: DataObject,
        start: u8,
        len: usize,
        #[serde(default)]
        occurence: Option<Occurence>,
        /// None means default value
        #[serde(default)]
        expected_status: Status,
    },
    SelectData {
        tag: DataObject,
        #[serde(default)]
        occurence: Occurence,
        /// None means default value
        #[serde(default)]
        expected_status: Status,
    },
    UnblockPin {
        /// None means use admin pin
        #[serde(default)]
        reset_code: Option<String>,
        #[serde(default)]
        new_value: Option<HexOrStr>,
        #[serde(default)]
        expected_status: Status,
    },
    ImportKey {
        private_key: String,
        #[serde(default)]
        public_key: String,
        #[serde(default)]
        key_type: Option<KeyType>,
        key_kind: KeyKind,
        #[serde(default)]
        expected_status: Status,
    },
    ReadKey {
        key_type: KeyType,
        key_kind: KeyKind,
        public_key: String,
    },
    SetAttributes {
        key_kind: KeyKind,
        key_type: KeyType,
    },
    Sign {
        #[serde(default)]
        input: String,
        #[serde(default)]
        output: String,
        #[serde(default)]
        expected_status: Status,
    },
    Authenticate {
        #[serde(default)]
        input: String,
        #[serde(default)]
        output: String,
        #[serde(default)]
        expected_status: Status,
    },
    Decrypt {
        #[serde(default)]
        input: String,
        #[serde(default)]
        output: String,
        key_kind: KeyKind,
        #[serde(default)]
        expected_status: Status,
    },
    FactoryReset {
        #[serde(default)]
        already_failed: u8,
    },
    GenerateKey {
        key_type: KeyType,
        #[serde(default)]
        expected_status: Status,
    },
}

const MATCH_EMPTY: OutputMatcher = OutputMatcher::Len(0);

impl IoCmd {
    fn run<T: opcard::Client>(&self, card: &mut opcard::Card<T>) {
        match self {
            Self::FactoryReset { already_failed } => Self::run_factory_reset(*already_failed, card),
            Self::Select => Self::run_select(card),
            Self::IoData {
                input,
                output,
                expected_status,
            } => Self::run_iodata(input, output, *expected_status, card),
            Self::Sign {
                input,
                output,
                expected_status,
            } => Self::run_sign(input, output, *expected_status, card),
            Self::Decrypt {
                input,
                output,
                key_kind,
                expected_status,
            } => Self::run_decrypt(input, output, key_kind, *expected_status, card),
            Self::Authenticate {
                input,
                output,
                expected_status,
            } => Self::run_authenticate(input, output, *expected_status, card),
            Self::Verify {
                pin,
                value,
                expected_status,
            } => Self::run_verify(*pin, value, *expected_status, card),
            Self::Change {
                pin,
                old_value,
                new_value,
                expected_status,
            } => Self::run_change(*pin, old_value, new_value, *expected_status, card),
            Self::ImportKey {
                private_key,
                public_key,
                key_type,
                key_kind,
                expected_status,
            } => Self::run_import(
                private_key,
                public_key,
                *key_type,
                key_kind,
                *expected_status,
                card,
            ),
            Self::SetAttributes { key_kind, key_type } => {
                Self::run_set_attributes(key_kind, key_type, card)
            }
            Self::ReadKey {
                key_type,
                key_kind,
                public_key,
            } => Self::run_read_key(key_kind, key_type, public_key, card),
            Self::PutData {
                tag,
                value,
                occurence,
                expected_status,
            } => Self::run_put_data(*tag, occurence, &parse_hex(value), *expected_status, card),
            Self::PutLargeData {
                tag,
                start,
                len,
                occurence,
                expected_status,
            } => Self::run_put_data(
                *tag,
                occurence,
                &LARGE_DATA[*start as usize..][..*len],
                *expected_status,
                card,
            ),
            Self::GetData {
                tag,
                expected_value,
                occurence,
                expected_status,
            } => Self::run_get_data(
                *tag,
                occurence,
                &parse_hex(expected_value),
                *expected_status,
                card,
            ),
            Self::GetLargeData {
                tag,
                start,
                len,
                occurence,
                expected_status,
            } => Self::run_get_data(
                *tag,
                occurence,
                &LARGE_DATA[*start as usize..][..*len],
                *expected_status,
                card,
            ),
            Self::SelectData {
                tag,
                occurence,
                expected_status,
            } => Self::run_select_data(*tag, *occurence, *expected_status, card),
            Self::UnblockPin {
                reset_code,
                new_value,
                expected_status,
            } => Self::run_unblock_pin(reset_code, new_value, *expected_status, card),
            Self::GenerateKey {
                key_type: key,
                expected_status,
            } => Self::run_generate_key(key, *expected_status, card),
        }
    }

    fn run_bytes<T: opcard::Client>(
        input: &[u8],
        output: &OutputMatcher,
        expected_status: Status,
        card: &mut opcard::Card<T>,
    ) {
        println!("Command: {input:x?}");
        let mut rep: heapless::Vec<u8, 7096> = heapless::Vec::new();
        let cmd = iso7816::command::CommandView::try_from(input).unwrap_or_else(|err| {
            panic!("Bad command: {err:?}, for command: {}", hex::encode(input))
        });
        let status: Status = card
            .handle(cmd, &mut rep)
            .err()
            .map(|s| TryFrom::<u16>::try_from(s.into()).unwrap())
            .unwrap_or_default();

        println!("Output: {:?}\nStatus: {status:?}", hex::encode(&rep));

        if !output.validate(&rep) {
            panic!("Bad output. Expected {output:?}");
        }
        if status != expected_status {
            panic!("Bad status. Expected {expected_status:?}");
        }
    }

    fn run_select<T: opcard::Client>(card: &mut opcard::Card<T>) {
        Self::run_bytes(
            &hex!("00 A4 0400 06 D27600012401"),
            &MATCH_EMPTY,
            Status::Success,
            card,
        )
    }

    fn run_factory_reset<T: opcard::Client>(already_failed: u8, card: &mut opcard::Card<T>) {
        for i in 0..(3 - already_failed) {
            Self::run_verify(
                Pin::Pw3,
                &Some(HexOrStr::Str(
                    "Voluntarily bad pin for factory reset".into(),
                )),
                Status::RemainingRetries((3 - already_failed) - i - 1),
                card,
            );
        }
        Self::run_bytes(&hex!("00 E6 00 00"), &MATCH_EMPTY, Status::Success, card);
        Self::run_bytes(&hex!("00 44 00 00"), &MATCH_EMPTY, Status::Success, card);
    }

    fn run_iodata<T: opcard::Client>(
        input: &str,
        output: &OutputMatcher,
        expected_status: Status,
        card: &mut opcard::Card<T>,
    ) {
        Self::run_bytes(&parse_hex(input), output, expected_status, card)
    }

    fn run_put_data<T: opcard::Client>(
        data_object: DataObject,
        occurence: &Option<Occurence>,
        data: &[u8],
        expected_status: Status,
        card: &mut opcard::Card<T>,
    ) {
        if let Some(occ) = occurence {
            Self::run_select_data(data_object, *occ, Status::Success, card);
        }

        let [p1, p2] = (data_object as u16).to_be_bytes();

        let input = build_command(0x00, 0xDA, p1, p2, data, 0);
        Self::run_bytes(&input, &OutputMatcher::Len(0), expected_status, card)
    }

    fn run_get_data<T: opcard::Client>(
        data_object: DataObject,
        occurence: &Option<Occurence>,
        expected_data: &[u8],
        expected_status: Status,
        card: &mut opcard::Card<T>,
    ) {
        if let Some(occ) = occurence {
            Self::run_select_data(data_object, *occ, Status::Success, card);
        }

        let [p1, p2] = (data_object as u16).to_be_bytes();

        let input = build_command(0x00, 0xCA, p1, p2, &[], 0);
        Self::run_bytes(
            &input,
            &OutputMatcher::Bytes(Cow::Owned(expected_data.to_owned())),
            expected_status,
            card,
        )
    }

    fn run_select_data<T: opcard::Client>(
        data_object: DataObject,
        occurence: Occurence,
        expected_status: Status,
        card: &mut opcard::Card<T>,
    ) {
        let [obj1, obj2] = (data_object as u16).to_be_bytes();

        let mut data = Vec::new();
        if obj1 == 0 {
            data.extend_from_slice(&[0x60, 0x03, 0x5C, 0x01, obj2]);
        } else {
            data.extend_from_slice(&[0x60, 0x04, 0x5C, 0x02, obj1, obj2]);
        }

        let input = build_command(0x00, 0xA5, occurence as u8, 4, &data, 0);
        Self::run_bytes(&input, &OutputMatcher::Len(0), expected_status, card)
    }

    fn run_import<T: opcard::Client>(
        private_key: &str,
        public_key: &str,
        key_type: Option<KeyType>,
        key_kind: &KeyKind,
        expected_status: Status,
        card: &mut opcard::Card<T>,
    ) {
        let private_key = parse_hex(private_key);
        let public_key = parse_hex(public_key);
        let mut template;
        if key_kind.is_ec() {
            template = vec![0x92];
            template.extend_from_slice(&serialize_len(private_key.len()));
            template.push(0x99);
            template.extend_from_slice(&serialize_len(public_key.len() + 1));
            let key: Vec<_> = private_key
                .into_iter()
                .chain([0x40])
                .chain(public_key)
                .collect();
            let crt = key_type.unwrap().crt();
            let mut data = Vec::from(crt);
            data.extend_from_slice(&tlv(&[0x7F, 0x48], &template));
            data.extend_from_slice(&tlv(&[0x5F, 0x48], &key));

            let input = build_command(0x00, 0xDB, 0x3F, 0xFF, &tlv(&[0x4d], &data), 0);
            Self::run_bytes(&input, &OutputMatcher::Len(0), expected_status, card)
        } else if key_kind.is_aes() {
            assert!(public_key.is_empty());
            Self::run_put_data(
                DataObject::PSOEncDecKey,
                &None,
                &private_key,
                expected_status,
                card,
            )
        } else {
            todo!()
        }
    }

    fn run_set_attributes<T: opcard::Client>(
        key_kind: &KeyKind,
        key_type: &KeyType,
        card: &mut opcard::Card<T>,
    ) {
        let input = build_command(
            0x00,
            0xDA,
            0x00,
            key_type.attributes_tag(),
            key_kind.attributes(),
            0,
        );
        Self::run_bytes(&input, &OutputMatcher::Len(0), Status::Success, card)
    }

    fn run_verify<T: opcard::Client>(
        pin: Pin,
        value: &Option<HexOrStr>,
        expected_status: Status,
        card: &mut opcard::Card<T>,
    ) {
        let tmp = value.as_ref().map(HexOrStr::as_bytes);
        let value = tmp.as_deref().unwrap_or_else(|| pin.default_value());
        let input = build_command(0x00, 0x20, 0x00, pin as u8, value, 0);
        Self::run_bytes(&input, &MATCH_EMPTY, expected_status, card)
    }
    fn run_change<T: opcard::Client>(
        pin: Pin,
        old_value: &Option<HexOrStr>,
        new_value: &Option<HexOrStr>,
        expected_status: Status,
        card: &mut opcard::Card<T>,
    ) {
        let old_tmp = old_value.as_ref().map(HexOrStr::as_bytes);
        let new_tmp = new_value.as_ref().map(HexOrStr::as_bytes);
        let old_value = old_tmp.as_deref().unwrap_or_else(|| pin.default_value());
        let new_value = new_tmp.as_deref().unwrap_or_else(|| pin.default_value());
        let data = Vec::from_iter(old_value.iter().chain(new_value).copied());
        let input = build_command(0x00, 0x24, 0x00, pin as u8, &data, 0);
        Self::run_bytes(&input, &MATCH_EMPTY, expected_status, card)
    }

    fn run_unblock_pin<T: opcard::Client>(
        reset_code: &Option<String>,
        new_value: &Option<HexOrStr>,
        expected_status: Status,
        card: &mut opcard::Card<T>,
    ) {
        let tmp = new_value.as_ref().map(HexOrStr::as_bytes);
        let new_value = tmp.as_deref().unwrap_or_else(|| Pin::Pw3.default_value());
        match reset_code {
            Some(c) => {
                let mut data = parse_hex(c);
                data.extend_from_slice(new_value);
                Self::run_bytes(
                    &build_command(0x00, 0x2C, 0x00, 0x81, &data, 0),
                    &MATCH_EMPTY,
                    expected_status,
                    card,
                )
            }
            None => Self::run_bytes(
                &build_command(0x00, 0x2C, 0x02, 0x81, new_value, 0),
                &MATCH_EMPTY,
                expected_status,
                card,
            ),
        }
    }

    fn run_generate_key<T: opcard::Client>(
        key_kind: &KeyType,
        expected_status: Status,
        card: &mut opcard::Card<T>,
    ) {
        let input = build_command(
            0x00,
            0x47,
            0x80,
            0x00,
            match key_kind {
                KeyType::Sign => &hex!("B6 00"),
                KeyType::Dec => &hex!("B8 00"),
                KeyType::Aut => &hex!("A4 00"),
            },
            0xFF,
        );
        Self::run_bytes(&input, &OutputMatcher::NonZero, expected_status, card);
    }

    fn run_read_key<T: opcard::Client>(
        key_kind: &KeyKind,
        key_type: &KeyType,
        public_key: &str,
        card: &mut opcard::Card<T>,
    ) {
        let input = build_command(0x00, 0x47, 0x81, 0x00, key_type.crt(), 0);
        let inner = if key_kind.is_ec() {
            let pubk = parse_hex(public_key);
            tlv(&[0x86], &pubk)
        } else {
            parse_hex(public_key)
        };

        let expected_response = tlv(&[0x7F, 0x49], &inner);

        Self::run_bytes(
            &input,
            &OutputMatcher::Bytes(Cow::Owned(expected_response)),
            Status::Success,
            card,
        )
    }

    fn run_sign<T: opcard::Client>(
        input: &str,
        output: &str,
        expected_status: Status,
        card: &mut opcard::Card<T>,
    ) {
        let input = build_command(0x00, 0x2A, 0x9E, 0x9A, &parse_hex(input), 0);
        Self::run_bytes(
            &input,
            &OutputMatcher::Bytes(Cow::Owned(parse_hex(output))),
            expected_status,
            card,
        )
    }

    fn run_authenticate<T: opcard::Client>(
        input: &str,
        output: &str,
        expected_status: Status,
        card: &mut opcard::Card<T>,
    ) {
        let input = build_command(0x00, 0x88, 0x00, 0x00, &parse_hex(input), 0);
        Self::run_bytes(
            &input,
            &OutputMatcher::Bytes(Cow::Owned(parse_hex(output))),
            expected_status,
            card,
        )
    }

    fn run_decrypt<T: opcard::Client>(
        input: &str,
        output: &str,
        key_kind: &KeyKind,
        expected_status: Status,
        card: &mut opcard::Card<T>,
    ) {
        let input = parse_hex(input);
        let mut data;
        if key_kind.is_ec() {
            data = tlv(&[0xA6], &tlv(&[0x7F, 0x49], &tlv(&[0x86], &input)))
        } else if key_kind.is_aes() {
            data = vec![0x02];
            data.extend_from_slice(&input);
        } else {
            data = vec![0x00];
            data.extend_from_slice(&input);
        }

        let input = build_command(0x00, 0x2A, 0x80, 0x86, &data, 0);
        Self::run_bytes(
            &input,
            &OutputMatcher::Bytes(Cow::Owned(parse_hex(output))),
            expected_status,
            card,
        )
    }
}

#[test_log::test]
fn command_response() {
    let data = std::fs::read_to_string("tests/command-response.ron").unwrap();

    let ron = Options::default().with_default_extension(Extensions::IMPLICIT_SOME);
    let tests: Vec<IoTest> = ron.from_str(&data).unwrap();
    for t in tests {
        println!("\n\n===========================================================",);
        println!("Running {}", t.name);
        opcard::virt::with_ram_client("opcard", |client| {
            let mut card = opcard::Card::new(client, opcard::Options::default());
            for io in t.cmd_resp {
                io.run(&mut card);
            }
        });
    }
}
