<!--
Copyright (C) 2022 Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# opcard-rs

`opcard` is a Rust implementation of the [OpenPGP smart card specification
v3.4][spec] using the [Trussed][] framework for modern cryptographic firmware.
It is developed for the [Nitrokey 3][] but can be used with any device
supporting Trussed.

[spec]: https://github.com/Nitrokey/openpgp-card/raw/master/OpenPGP%20Card%20Specification%203.4.pdf
[Trussed]: https://github.com/trussed-dev/trussed
[Nitrokey 3]: https://github.com/nitrokey/nitrokey-3-firmware

## ⚠️ Security Warning

This is **alpha** software and should currently not be used outside of
testing. Updates may lead to data loss and the security of the keys and PINs
is not guaranteed.

## Features

`opcard` currently supports the basic OpenPGP Card functionality (key generation,
key import, signing, decrypting, card administration).

Here are the currently supported algorithms:

- RSA-2048
- RSA-3072 (no key generation, key import only)
- RSA-4096 (no key generation, key import only)
- EcDSA and ECDH for P256
- EdDSA and ECDH for Curve25519

See the [issues for the v1.0.0 milestone][v1.0.0 milestone] for all missing
features for a first stable release.

[v1.0.0 milestone]: https://github.com/Nitrokey/opcard-rs/milestone/2

Check out the [user guide](USAGE.md) for more information on what can be done.

## Development

Opcard uses [virtualsmartcard](https://frankmorgner.github.io/vsmartcard/) for testing.
`make test` will run `opcard` on the host through virtualsmartcard and test it.

`make dangerous-real-card-test` will instead run the tests against a real card.
The vendor id and serial numbers can be configured with variables:

- `OPCARD_DANGEROUS_TEST_CARD_USB_VENDOR` configures the USB vendor id of the dveice
- `OPCARD_DANGEROUS_TEST_CARD_USB_PRODUCT` configures the USB product id of the dveice
- `OPCARD_DANGEROUS_TEST_CARD_PGP_VENDOR` configures the PGP vendor id of the dveice
- `OPCARD_DANGEROUS_TEST_CARD_PGP_PRODUCT` configures the PGP serial number of the dveice

Be aware that due to conflicts between gpg-agent and `pcscd` (the smartcard daemon), this test suite will start then  stop `pcscd`

```
make dangerous-real-card-test \
  OPCARD_DANGEROUS_TEST_CARD_USB_VENDOR="20A0" \
  OPCARD_DANGEROUS_TEST_CARD_USB_PRODUCT="42B2" \
  OPCARD_DANGEROUS_TEST_CARD_PGP_VENDOR="0000" \
  OPCARD_DANGEROUS_TEST_CARD_PGP_SERIAL="A020DF77" \
  OPCARD_DANGEROUS_TEST_CARD_NAME="test card"
```

## Installation

Download the latest compiled [alpha release](https://github.com/Nitrokey/nitrokey-3-firmware/releases).
Plug your Nitrokey 3 and use [nitropy](https://docs.nitrokey.com/software/nitropy/) to install it with 
`nitropy nk3 update <path/to/release/file>`

## Build Dependencies

`opcard` has these build dependencies:
- clang
- libpcsclite
- nettle
- pkg-config
- Rust toolchain

To run the tests, you also need these tools:
- gnupg
- scdaemon
- vsmartcard (vpcd)

See the [CI Dockerfile](./ci/Dockerfile) for all steps to set up the development environment on Debian-based distributions.

For a complete usb token firmware implementation including Opcard for OpenPGP support, see the [Nitrokey 3 firmware repository](https://github.com/Nitrokey/nitrokey-3-firmware).

## Minimum Supported Rust Version (MSRV)

The minimum supported Rust version (MSRV) for this crate is the most recent stable Rust release.
Older versions may or may not work.
Rust versions older than 1.66.0 cannot be used to build this crate.

## Bug reports

If you encounter a bug or have a feature request, please inform us on [our forum](https://support.nitrokey.com/).
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
