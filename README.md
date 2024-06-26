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

## Usage

See the [Nitrokey 3 documentation][docs].

[docs]: https://docs.nitrokey.com/nitrokey3/

## Features

`opcard` currently supports the basic OpenPGP Card functionality (key generation,
key import, signing, decrypting, card administration).

Here are the currently supported algorithms:

- RSA-2048
- RSA-3072
- RSA-4096
- EcDSA and ECDH for P256
- EdDSA and ECDH for Curve25519

## Development

Opcard uses [virtualsmartcard](https://frankmorgner.github.io/vsmartcard/) for testing.
`make test` will run `opcard` on the host through virtualsmartcard and test it.

`make dangerous-real-card-test` will instead run the tests against a real card.
The vendor id and serial numbers can be configured with variables:


- `OPCARD_DANGEROUS_TEST_CARD_USB_VENDOR` configures the USB vendor ID of the device
- `OPCARD_DANGEROUS_TEST_CARD_USB_PRODUCT` configures the USB product ID of the device

Those can be obtained by `lsusb`. In the line `Bus 003 Device 010: ID 20a0:42b2 Clay Logic Nitrokey 3`, `20a0` is `OPCARD_DANGEROUS_TEST_CARD_USB_VENDOR` and `42b2` is `OPCARD_DANGEROUS_TEST_CARD_USB_PRODUCT`.

- `OPCARD_DANGEROUS_TEST_CARD_PGP_VENDOR` configures the PGP vendor ID of the device
- `OPCARD_DANGEROUS_TEST_CARD_PGP_SERIAL` configures the PGP serial number of the device. 

Those can be obtained by `opgpcard status`. In the line `OpenPGP card 000F:566F86B0 (card version 3.4)`, `000F` is `OPCARD_DANGEROUS_TEST_CARD_PGP_VENDOR` and `566F86B0` is `OPCARD_DANGEROUS_TEST_CARD_PGP_SERIAL`.

Be aware that due to conflicts between `gpg-agent` and `pcscd` (the smartcard daemon), this test suite will start then  stop `pcscd`

```
make dangerous-real-card-test \
  OPCARD_DANGEROUS_TEST_CARD_USB_VENDOR="20A0" \
  OPCARD_DANGEROUS_TEST_CARD_USB_PRODUCT="42B2" \
  OPCARD_DANGEROUS_TEST_CARD_PGP_VENDOR="0000" \
  OPCARD_DANGEROUS_TEST_CARD_PGP_SERIAL="A020DF77" \
  OPCARD_DANGEROUS_TEST_CARD_NAME="test card"
```

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
