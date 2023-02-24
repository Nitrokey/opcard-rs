<!--
Copyright (C) 2022 Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# Changelog

## [v0.3.0][] (2023-24-02)

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
