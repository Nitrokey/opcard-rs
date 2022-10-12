<!--
Copyright (C) 2022 Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

Opcard User Guide
=================

## Installation

Currently only available for the Nitrokey 3A Mini.

Download the latest compiled [release](https://github.com/Nitrokey/opcard-rs/releases) ZIP file.
Plug your Nitrokey 3A Mini and use [nitropy](https://docs.nitrokey.com/software/nitropy/) to install it with 
`nitropy nk3 update <path/to/release/zip/file>`

## Generating keys

Currently, Opcard only supports curve25519 and P-256 curves.
To edit the card, run `gpg --edit-card --expert` (`--expert` is required for P-256).
GPG should show you information about the card.
Enable adminitration commands with `admin` and edit the key types with `key-attr`.
Select `ECC` (`RSA` support is coming soon) and then choose either `Curve 25519` or `NIST P-256`.

The card will prompt you for the admin password (`12345678` by default).
Continue for all three key types (signature, decryption and authentication).

Finally, you can generate the keys with `generate`. `gpg` will ask you the user pin, `123456` by default.

## Importing existing keys

If you already have curve25519 or P-256 PGP keys, you should be able to import them using `gpg --edit-key <key email>` and then `keytocard`.

## Changing the PIN

Use `gpg --edit-card` to edit the card, then `admin` to enable administration commands, then `passwd` to change either the admin pin or the user pin.

## Changing card data

Use `gpg --edit-card` to edit the card, then `admin` to enable administration commands.
You can then use the commands `login`, `url`, `name`, `lang` and `salutation` to change the card data.