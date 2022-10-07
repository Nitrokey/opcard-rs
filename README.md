<!--
Copyright (C) 2022 Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# opcard-rs

`opcard` is a Rust implementation of the [OpenPGP smart card specification
v3.4][spec].

[spec]: https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf

## ⚠️ Security Warning

This is **alpha** software and should currently not be used outside of
testing. Updates may lead to data loss and the security of the keys and PINs
is not guaranteed.

## Features

`opcard` currently supports the basic OpenPGP Card functionality (key generation,
key import, signing, decrypting, card administration) for Curve25519 and NIST
P-256. See the [issues for the v1.0.0 milestone][v1.0.0 milestone] for all
missing features for a first stable release.

[v1.0.0 milestone]: https://github.com/Nitrokey/opcard-rs/milestone/2

## Installation

Currently only available for the Nitrokey 3A Mini.

Download the latest compiled [release](https://github.com/Nitrokey/opcard-rs/releases) ZIP file.
Plug your Nitrokey 3A Mini and use [nitropy](https://docs.nitrokey.com/software/nitropy/) to install it with 
`nitropy nk3 update <path/to/release/zip/file>`

## License

This project is licensed under the [GNU Lesser General Public License (LGPL)
version 3][LGPL-3.0].  Configuration files and examples are licensed under the
[CC0 1.0 license][CC0-1.0].  For more information, see the license header in
each file.  You can find a copy of the license texts in the
[`LICENSES`](./LICENSES) directory.

[LGPL-3.0]: https://opensource.org/licenses/LGPL-3.0
[CC0-1.0]: https://creativecommons.org/publicdomain/zero/1.0/

This project complies with [version 3.0 of the REUSE specification][reuse].

[reuse]: https://reuse.software/practices/3.0/
