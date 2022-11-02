<!--
Copyright (C) 2022 Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# Changelog

## Unreleased

### Features

- Support using authentication keys for decryption and vice-versa with MANAGE SECURITY ENVIRONMENT ([#60][])
- Support PIN resets using a resetting code ([#63][])
- Support AES encryption/decryption ([#64][])

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

## v0.1.0 (2022-10-12)

This initial release contains support for the basic OpenPGP Card functionality
(key generation, key import, signing, decrypting, card administration) for
Curve25519 and NIST P-256.
