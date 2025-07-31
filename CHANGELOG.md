<!--
Copyright (C) 2022 Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# Changelog

## Unreleased

## [v1.6.0][] (2025-07-31)

[v1.6.0]: https://github.com/Nitrokey/opcard-rs/releases/tag/v1.6.0

- Add support for secp256k1.
- Prevent updates to algorithms from chaning their serialization ([#221][]).
- Replace `apdu-dispatch` with `apdu-app`.
- Replace `trussed` with `trussed-core`.
- Update `littlefs2` dependency to v0.5.
- Update `trussed-auth` to v0.4.

[#221]: https://github.com/Nitrokey/opcard-rs/pull/221

## [v1.5.0][] (2024-07-31)

[v1.5.0]: https://github.com/Nitrokey/opcard-rs/releases/tag/v1.5.0

- Add support for more curves ([#207][]):
  - secp384r1 (NIST P-384)
  - secp521r1 (NIST P-521)
  - brainpoolp256r1
  - brainpoolp384r1
  - brainpoolp512r1

[#207]: https://github.com/Nitrokey/opcard-rs/pull/207

## [v1.4.1][] (2024-03-22)

[v1.4.1]: https://github.com/Nitrokey/opcard-rs/releases/tag/v1.4.1

- Bump RSA backend version ([#209][])

[#209]: https://github.com/Nitrokey/opcard-rs/pull/209

## [v1.4.0][] (2024-03-22)

[v1.4.0]: https://github.com/Nitrokey/opcard-rs/releases/tag/v1.4.0

- Use `trussed-chunked` and `trussed-wrap-key-to-file` instead of
  `trussed-staging`, see [trussed-staging#19][].
- Update dependencies:
  - trussed ([#198][])
  - trussed-rsa-backend ([#195][])

[#195]: https://github.com/Nitrokey/opcard-rs/pull/195
[#198]: https://github.com/Nitrokey/opcard-rs/pull/198
[trussed-staging#19]: https://github.com/trussed-dev/trussed-staging/pull/19

## [v1.3.0][] (2023-12-01)

- Use the trussed clear API required for SE050 compatibility ([#187][])

[#187]: https://github.com/Nitrokey/opcard-rs/pull/187

[v1.3.0]: https://github.com/Nitrokey/opcard-rs/releases/tag/v1.3.0

## [v1.2.1][] (2023-11-30)

- Support factory reset through the admin app ([#188][])
- Make RSA key size support a runtime configuration ([#190][])

[#188]: https://github.com/Nitrokey/opcard-rs/pull/188
[#190]: https://github.com/Nitrokey/opcard-rs/pull/190

[v1.2.1]: https://github.com/Nitrokey/opcard-rs/releases/tag/v1.2.1

## [v1.2.0][] (2023-11-08)

### Bugfixes

- Reject all requests over NFC ([#184][])
- Fix missing state save that could lead to a corrupted state ([#170][])
- Fix crash when signing more than 1024 bytes ([#174][])

### Changes

- Add variables.mk file ([#177][])
- Tests: add support for gnupg over pcscd ([#180][])
- Update CI setup ([#175][] and [#183][])
- Update delog dependency ([#181][])
- Fix `sha1collisiondetection ` dependency version ([#179][] and [#182][])

[#184]: https://github.com/Nitrokey/opcard-rs/issues/184
[#182]: https://github.com/Nitrokey/opcard-rs/issues/182
[#179]: https://github.com/Nitrokey/opcard-rs/issues/179
[#181]: https://github.com/Nitrokey/opcard-rs/issues/181
[#183]: https://github.com/Nitrokey/opcard-rs/issues/183
[#175]: https://github.com/Nitrokey/opcard-rs/issues/175
[#180]: https://github.com/Nitrokey/opcard-rs/issues/180
[#180]: https://github.com/Nitrokey/opcard-rs/issues/180
[#177]: https://github.com/Nitrokey/opcard-rs/issues/177
[#170]: https://github.com/Nitrokey/opcard-rs/issues/170
[#174]: https://github.com/Nitrokey/opcard-rs/issues/174

[v1.2.0]: https://github.com/Nitrokey/opcard-rs/releases/tag/v1.2.0

## [v1.1.1][] (2023-07-04)

### Bugfixes

- Do not override existing pins on initialization ([#166][])

[#166]: https://github.com/Nitrokey/opcard-rs/issues/166

[v1.1.1]: https://github.com/Nitrokey/opcard-rs/releases/tag/v1.1.1

## [v1.1.0][] (2023-05-30)

### Bugfixes

- Return status 6285 if SELECT is called in termination state ([#154][])
- Save the new pin length after an RESET RETRY COUNTER call ([#158][])
- Reset the signature counter after key generation and import ([#155][])

[#154]: https://github.com/Nitrokey/opcard-rs/issues/154
[#155]: https://github.com/Nitrokey/opcard-rs/issues/155
[#158]: https://github.com/Nitrokey/opcard-rs/issues/158

[v1.1.0]: https://github.com/Nitrokey/opcard-rs/releases/tag/v1.1.0

## [v1.0.0][] (2023-04-27)

- Add support for larger storage for certificates and private use data objects ([#150][])

### Changes

- Use upstream Trussed ([#149][])
- Use stable serialization helpers instead of postcard directly ([#148][]).
- Add tests for RSA 3072 and make RSA feature-flags more granular ([#143][])

[#143]: https://github.com/Nitrokey/opcard-rs/pull/143
[#148]: https://github.com/Nitrokey/opcard-rs/pull/148
[#149]: https://github.com/Nitrokey/opcard-rs/pull/149
[#150]: https://github.com/Nitrokey/opcard-rs/pull/150

[v1.0.0]: https://github.com/Nitrokey/opcard-rs/releases/tag/v1.0.0

## [v0.4.0][] (2023-02-24)

### Features

- Add support for RSA 3072 bits ([#116][])
- Support use of external storage (#[117][])
- Encrypt data on the external storage ([#134][], [#135][], [#136][], [#137][], [#138][], [#139][], [#127][])

### Changes

- Use `trussed-rsa-backend` ([#116][])
- Use `trussed-auth` for pin authentication ([#125][])

### Developement

- Rename "virtual" to "vpicc" ([#132][])
- Rename `make check` to `make lint` ([#120][])
- Add usbip runner and test against the gnuk test suite ([#105][])

[#132]: https://github.com/Nitrokey/opcard-rs/pull/132
[#125]: https://github.com/Nitrokey/opcard-rs/pull/125
[#120]: https://github.com/Nitrokey/opcard-rs/pull/120
[#117]: https://github.com/Nitrokey/opcard-rs/pull/117
[#116]: https://github.com/Nitrokey/opcard-rs/pull/116
[#105]: https://github.com/Nitrokey/opcard-rs/pull/105
[#134]: https://github.com/Nitrokey/opcard-rs/pull/134
[#135]: https://github.com/Nitrokey/opcard-rs/pull/135
[#136]: https://github.com/Nitrokey/opcard-rs/pull/136
[#137]: https://github.com/Nitrokey/opcard-rs/pull/137
[#138]: https://github.com/Nitrokey/opcard-rs/pull/138
[#139]: https://github.com/Nitrokey/opcard-rs/pull/139
[#127]: https://github.com/Nitrokey/opcard-rs/pull/127


## [v0.3.0][] (2023-02-24)

### Features

- Ensure `gpg` can factory reset the card even when corrupted ([#103][])
- Add mechanism to run tests against a real card ([#97][] and [#108][])

### Bugfixes

- Fix OpenSC compatibility ([#96][])
- Fix crash when attempting to sign large payloads with RSA ([nitrokey/trussed/#11][])

### Developement

- Use fully qualified path to CI base docker image ([#109][])
- Documentation improvements ([#95][], [#98][], [#107][])
- Fix version of patched dependencies ([#101][])

[#95]: https://github.com/Nitrokey/opcard-rs/pull/95
[#96]: https://github.com/Nitrokey/opcard-rs/pull/96
[#97]: https://github.com/Nitrokey/opcard-rs/pull/97
[#98]: https://github.com/Nitrokey/opcard-rs/pull/98
[#101]: https://github.com/Nitrokey/opcard-rs/pull/101
[#103]: https://github.com/Nitrokey/opcard-rs/pull/103
[#107]: https://github.com/Nitrokey/opcard-rs/pull/107
[#108]: https://github.com/Nitrokey/opcard-rs/pull/108
[#109]: https://github.com/Nitrokey/opcard-rs/pull/109
[nitrokey/trussed/#11]: https://github.com/Nitrokey/trussed/pull/11
[v0.3.0]: https://github.com/Nitrokey/opcard-rs/releases/tag/v0.3.0

## [v0.2.0][] (2022-11-18)

### Features

- Support using authentication keys for decryption and vice-versa with MANAGE SECURITY ENVIRONMENT ([#60][])
- Support PIN resets using a resetting code ([#63][])
- Support AES encryption/decryption ([#64][])
- Support RSA 2048 and 4096 bit key usage and generation ([#94][])

### Bugfixes

- Fix the length of the Digital signature counter DO 0x93 ([#76][])
- PSO:CDS: Increment the signature counter ([#78][])
- Fix endianness of curve25519 key import([#89][])

[#64]: https://github.com/Nitrokey/opcard-rs/pull/64
[#60]: https://github.com/Nitrokey/opcard-rs/pull/60
[#63]: https://github.com/Nitrokey/opcard-rs/pull/63
[#76]: https://github.com/Nitrokey/opcard-rs/pull/76
[#78]: https://github.com/Nitrokey/opcard-rs/pull/78
[#89]: https://github.com/Nitrokey/opcard-rs/pull/89
[#94]: https://github.com/Nitrokey/opcard-rs/pull/94

[v0.2.0]: https://github.com/Nitrokey/opcard-rs/compare/v0.1.0...v0.2.0

## [v0.1.0][] (2022-10-12)

This initial release contains support for the basic OpenPGP Card functionality
(key generation, key import, signing, decrypting, card administration) for
Curve25519 and NIST P-256.

[v0.1.0]: https://github.com/Nitrokey/opcard-rs/releases/tag/v0.1.0
