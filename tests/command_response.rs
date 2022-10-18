// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "virtual")]

use serde::Deserialize;

// iso7816::Status doesn't support serde
#[derive(Deserialize, Debug, PartialEq, Clone, Copy)]
enum Status {
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

impl Default for Status {
    fn default() -> Status {
        Status::Success
    }
}

#[derive(Deserialize, Debug)]
struct IoTest {
    name: String,
    cmd_resp: Vec<IoCmd>,
}

#[derive(Deserialize, Debug)]
enum OutputMatcher {
    And(Vec<OutputMatcher>),
    Or(Vec<OutputMatcher>),
    Len(usize),
    Data(String),
    NonZero,
}

impl Default for OutputMatcher {
    fn default() -> Self {
        OutputMatcher::Len(0)
    }
}

fn parse_hex(data: &str) -> Vec<u8> {
    let tmp: String = data.split_whitespace().collect();
    hex::decode(&tmp).unwrap()
}

impl OutputMatcher {
    fn validate(&self, data: &[u8]) -> bool {
        match self {
            Self::NonZero => data.iter().max() != Some(&0),
            Self::Data(expected) => {
                println!("Validating output with {expected}");
                data == parse_hex(expected)
            }
            Self::Len(len) => data.len() == *len,
            Self::And(matchers) => matchers.iter().filter(|m| !m.validate(data)).count() == 0,
            Self::Or(matchers) => matchers.iter().filter(|m| m.validate(data)).count() != 0,
        }
    }
}

#[derive(Deserialize, Debug)]
enum IoCmd {
    IoData {
        input: String,
        #[serde(default)]
        output: OutputMatcher,
        #[serde(default)]
        expected_status: Status,
    },
}

impl IoCmd {
    fn run<T: trussed::Client>(&self, card: &mut opcard::Card<T>) {
        match self {
            Self::IoData {
                input,
                output,
                expected_status,
            } => Self::run_iodata(&input, &output, *expected_status, card),
        }
    }

    fn run_iodata<T: trussed::Client>(
        input: &str,
        output: &OutputMatcher,
        expected_status: Status,
        card: &mut opcard::Card<T>,
    ) {
        println!("Command: {:?}", input);
        let mut rep: heapless::Vec<u8, 1024> = heapless::Vec::new();
        let cmd: iso7816::Command<1024> = iso7816::Command::try_from(&parse_hex(input))
            .unwrap_or_else(|err| {
                panic!("Bad command: {err:?}, for command: {}", hex::encode(&input))
            });
        let status: Status = card
            .handle(&cmd, &mut rep)
            .err()
            .map(|s| TryFrom::<u16>::try_from(s.into()).unwrap())
            .unwrap_or_default();

        println!("Output: {:?}\nStatus: {status:?}", hex::encode(&rep));

        if !output.validate(&rep) {
            panic!("Bad output. Expected {:?}", output);
        }
        if status != expected_status {
            panic!("Bad status. Expected {:?}", expected_status);
        }
    }
}

#[test_log::test]
fn command_response() {
    let data = std::fs::read_to_string("tests/command_response.ron").unwrap();
    let tests: Vec<IoTest> = ron::from_str(&data).unwrap();
    for t in tests {
        println!("Running {}", t.name);
        trussed::virt::with_ram_client("opcard", |client| {
            let mut card = opcard::Card::new(client, opcard::Options::default());
            for io in t.cmd_resp {
                io.run(&mut card);
            }
        });
    }
}
