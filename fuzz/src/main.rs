// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

use arbitrary::Arbitrary;
use hex_literal::hex;

use std::fs::File;
use std::io::Write;

use opcard_fuzz::Input;

#[derive(Arbitrary, Debug, Clone)]
enum KeyType {
    Sign,
    Dec,
    Aut,
}

/// Command that contain the default pin to help the fuzzer find them
#[derive(Arbitrary, Debug, Clone)]
enum Command {
    ChangeDefaultPw1(Vec<u8>),
    ChangeDefaultPw3(Vec<u8>),
    VerifyPw1,
    VerifyPw1Sign,
    VerifyPw3,
    CheckPw1,
    CheckPw1Sign,
    CheckPw3,
    Generate(KeyType),
    ReadKey(KeyType),
    SetAttrDh256,
    SetAttrEc256Sign,
    SetAttrEc256Aut,
    SetAttrEd25519Sign,
    SetAttrEd25519Aut,
    SetAttrX25519,
    PsoCds(Vec<u8>),
    ActivateFile,
}

impl Command {
    fn as_bytes(&self) -> Vec<u8> {
        match self.clone() {
            Self::VerifyPw1Sign => Vec::from(hex!("00200081 06 313233343536").as_slice()),
            Self::VerifyPw1 => Vec::from(hex!("00200082 06 313233343536").as_slice()),
            Self::VerifyPw3 => Vec::from(hex!("00200083 08 3132333435363738").as_slice()),
            Self::CheckPw1Sign => Vec::from(hex!("0020FF81").as_slice()),
            Self::CheckPw1 => Vec::from(hex!("0020FF82").as_slice()),
            Self::CheckPw3 => Vec::from(hex!("0020FF83").as_slice()),
            Self::ChangeDefaultPw1(mut data) => {
                // Avoid extended length
                data.truncate(129);
                let length = (data.len() + 6) as u8;
                let mut res = Vec::from(hex!("00240081").as_slice());
                res.extend_from_slice([length, 1, 2, 3, 4, 5, 6].as_slice());
                res.extend_from_slice(&data);
                res
            }
            Self::ChangeDefaultPw3(mut data) => {
                // Avoid extended length
                data.truncate(129);
                let length = (data.len() + 8) as u8;
                let mut res = Vec::from(hex!("00240081").as_slice());
                res.extend_from_slice([length, 1, 2, 3, 4, 5, 6, 7, 8].as_slice());
                res.extend_from_slice(&data);
                res
            }
            Self::Generate(KeyType::Sign) => Vec::from(hex!("00478000 02 B600").as_slice()),
            Self::Generate(KeyType::Dec) => Vec::from(hex!("00478000 02 B800").as_slice()),
            Self::Generate(KeyType::Aut) => Vec::from(hex!("00478000 02 A400").as_slice()),
            Self::ReadKey(KeyType::Sign) => Vec::from(hex!("00478100 02 B600").as_slice()),
            Self::ReadKey(KeyType::Dec) => Vec::from(hex!("00478100 02 B800").as_slice()),
            Self::ReadKey(KeyType::Aut) => Vec::from(hex!("00478100 02 A400").as_slice()),
            Self::SetAttrEc256Sign => Vec::from(hex!("00DA00C1 09 132A8648CE3D030107").as_slice()),
            Self::SetAttrDh256 => {
                Vec::from(hex!("00DA00C2 09 12 2A 86 48 CE 3D 03 01 07").as_slice())
            }
            Self::SetAttrEc256Aut => Vec::from(hex!("00DA00C3 09 132A8648CE3D030107").as_slice()),
            Self::SetAttrEd25519Sign => {
                Vec::from(hex!("00DA00C1 0A 162B06010401DA470F01").as_slice())
            }
            Self::SetAttrX25519 => Vec::from(hex!("00DA00C2 0B 122B060104019755010501").as_slice()),
            Self::SetAttrEd25519Aut => {
                Vec::from(hex!("00DA00C3 0A 162B06010401DA470F01").as_slice())
            }
            Self::PsoCds(mut data) => {
                if data.is_empty() {
                    return Vec::from(hex!("002A9E9A").as_slice());
                }
                data.truncate(255);
                let mut res = Vec::from(hex!("002A9E9A").as_slice());
                res.push(data.len() as u8);
                res.extend_from_slice(&data);
                res.push(0);
                res
            }
            Self::ActivateFile => Vec::from(hex!("00 44 0000").as_slice()),
        }
    }
}

fn as_corpus(commands: &[Command]) -> Vec<u8> {
    let mut res = Vec::new();
    for cmd in commands {
        res.push(1);
        for b in cmd.as_bytes() {
            res.push(1);
            res.push(b);
        }
        res.push(0);
    }

    // Serial
    res.push(0);
    res.push(0);

    // Manufacturer
    res.push(0);
    res.push(0);
    res.push(0);
    res.push(0);

    // Historical bytes
    res.push(0);

    let mut unstructured = arbitrary::Unstructured::new(&res);
    let parsed = Input::arbitrary(&mut unstructured).unwrap();
    assert_eq!(commands.len(), parsed.commands.len());
    for (idx, cmd) in commands.into_iter().enumerate() {
        assert_eq!(cmd.as_bytes(), parsed.commands[idx])
    }
    res
}

fn write_corpus(commands: &[Command], file: &str) {
    let mut f = File::create(&format!("corpus/{file}")).unwrap();
    f.write(&as_corpus(commands)).unwrap();
    f.flush().unwrap();
    println!("Wrote {file}");
}

fn main() {
    write_corpus(
        &[
            Command::ActivateFile,
            Command::VerifyPw1,
            Command::VerifyPw1Sign,
            Command::VerifyPw3,
        ],
        "verify",
    );
    write_corpus(
        &[
            Command::ActivateFile,
            Command::VerifyPw3,
            Command::SetAttrEc256Sign,
            Command::Generate(KeyType::Sign),
            Command::VerifyPw1Sign,
            Command::PsoCds(vec![1; 32]),
        ],
        "sign-256",
    );

    write_corpus(
        &[
            Command::ActivateFile,
            Command::VerifyPw3,
            Command::SetAttrEd25519Sign,
            Command::Generate(KeyType::Sign),
            Command::VerifyPw1Sign,
            Command::PsoCds(vec![1; 32]),
        ],
        "sign-25519",
    );

    write_corpus(
        &[
            Command::ActivateFile,
            Command::VerifyPw1Sign,
            Command::SetAttrEd25519Sign,
            Command::SetAttrEd25519Aut,
            Command::SetAttrX25519,
            Command::Generate(KeyType::Sign),
            Command::Generate(KeyType::Dec),
            Command::Generate(KeyType::Aut),
            Command::ReadKey(KeyType::Sign),
            Command::ReadKey(KeyType::Dec),
            Command::ReadKey(KeyType::Aut),
        ],
        "gen-25519",
    );

    write_corpus(
        &[
            Command::ActivateFile,
            Command::VerifyPw1Sign,
            Command::SetAttrEc256Sign,
            Command::SetAttrEc256Aut,
            Command::SetAttrDh256,
            Command::Generate(KeyType::Sign),
            Command::Generate(KeyType::Dec),
            Command::Generate(KeyType::Aut),
            Command::ReadKey(KeyType::Sign),
            Command::ReadKey(KeyType::Dec),
            Command::ReadKey(KeyType::Aut),
        ],
        "gen-256",
    );
    write_corpus(
        &[
            Command::ActivateFile,
            Command::ChangeDefaultPw1(Vec::from(b"234567".as_slice())),
            Command::ChangeDefaultPw3(Vec::from(b"23456789".as_slice())),
        ],
        "change-pw",
    );
    write_corpus(
        &[
            Command::ActivateFile,
            Command::CheckPw1Sign,
            Command::CheckPw1,
            Command::CheckPw3,
        ],
        "check-pw",
    );
}
