<!--
Copyright (C) 2022 Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# opcard-rs

`opcard` is a Rust implementation of the [OpenPGP smart card specification
v3.4][spec].

[spec]: https://github.com/Nitrokey/openpgp-card/raw/master/OpenPGP%20Card%20Specification%203.4.pdf

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

Check out the [user guide](USAGE.md) for more information on what can be done.

## Installation

Currently only available for the Nitrokey 3A Mini.

Download the latest compiled [release](https://github.com/Nitrokey/opcard-rs/releases) ZIP file.
Plug your Nitrokey 3A Mini and use [nitropy](https://docs.nitrokey.com/software/nitropy/) to install it with 
`nitropy nk3 update <path/to/release/zip/file>`


## Bug reports

If you enconter a bug or have a feature request, please inform us on [our forum](https://support.nitrokey.com/).
Please include the output of `gpg --card-status` so for context.


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

## Funding

[<img src="https://nlnet.nl/logo/banner.svg" width="200" alt="Logo NLnet: abstract logo of four people seen from above" hspace="20">](https://nlnet.nl/)
[<img src="https://nlnet.nl/image/logos/NGI0PET_tag.svg" width="200" alt="Logo NGI Zero: letterlogo shaped like a tag" hspace="20">](https://nlnet.nl/NGI0/)

This project was funded through the [NGI0 PET](https://nlnet.nl/PET) Fund, a fund established by [NLnet](https://nlnet.nl/) with financial support from the European Commission's [Next Generation Internet programme](https://ngi.eu/), under the aegis of DG Communications Networks, Content and Technology under grant agreement No 825310.
