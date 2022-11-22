<!--
Copyright (C) 2022 Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

Opcard User Guide
=================

## ⚠️ Security Warning

This is **alpha** software and should currently not be used outside of
testing. Updates may lead to data loss and the security of the keys and PINs
is not guaranteed.

## Installation

Currently only available for the Nitrokey 3A Mini.

Download the latest compiled [release](https://github.com/Nitrokey/opcard-rs/releases) ZIP file.
Plug your Nitrokey 3A Mini and use [nitropy](https://docs.nitrokey.com/software/nitropy/) to install it with 
`nitropy nk3 update <path/to/release/zip/file>`

## Generating keys

OPcard supports Rsa 2048 and 4096 bits, P-256, X25519 ad Ed25519.
To edit the card, run `gpg --edit-card --expert` (`--expert` is required for P-256).
GPG should show you information about the card:

```
Reader ...........: 20A0:42B2:X:0
Application ID ...: D2760001240103040000000000000000
Application type .: OpenPGP
Version ..........: 3.4
Manufacturer .....: test card
Serial number ....: a010xxxx
Name of cardholder: [not set]
Language prefs ...: [not set]
Salutation .......: 
URL of public key : [not set]
Login data .......: [not set]
Signature PIN ....: forced
Key attributes ...: rsa2048 rsa2048 rsa2048
Max. PIN lengths .: 127 127 127
PIN retry counter : 3 3 3
Signature counter : 0
KDF setting ......: off
Signature key ....: [none]
Encryption key....: [none]
Authentication key: [none]
General key info..: [none]  
```

Enable administration commands with `admin` and edit the key types with `key-attr`.
You can then select `ECC` and choose either `Curve 25519` or `NIST P-256`.

```
gpg/card> admin 
Admin commands are allowed

gpg/card> key-attr 
Changing card key attribute for: Signature key
Please select what kind of key you want:
   (1) RSA
   (2) ECC
Your selection? 2
Please select which elliptic curve you want:
   (1) Curve 25519
   (3) NIST P-256
   (4) NIST P-384
   (5) NIST P-521
   (6) Brainpool P-256
   (7) Brainpool P-384
   (8) Brainpool P-512
   (9) secp256k1
Your selection? 1
```

You can also select `RSA` and keys of size 2048 or 4096.
While opcard supports 4096 bit keys, in practice key generation is extremely slow is therefore disable in the compiled firmware.
You can however still import RSA 4096 bit keys that were generated off-device.

```
gpg/card> admin 
Admin commands are allowed

gpg/card> key-attr 
Changing card key attribute for: Signature key
Please select what kind of key you want:
   (1) RSA
   (2) ECC
Your selection? 1
What keysize do you want? (2048) 2048
```

The card will prompt you for the admin password (`12345678` by default).
Continue for all three key types (signature, decryption and authentication).

Finally, you can generate the keys with `generate`. `gpg` will ask you the admin pin then the user pin (`123456` by default).

```
gpg/card> generate 
Make off-card backup of encryption key? (Y/n) n

Please note that the factory settings of the PINs are
   PIN = '123456'     Admin PIN = '12345678'
You should change them using the command --change-pin

Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 
Key does not expire at all
Is this correct? (y/N) y

GnuPG needs to construct a user ID to identify your key.

Real name: Your name
Email address: email@email.com
Comment: 
You selected this USER-ID:
    "Your name <email@email.com>"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? O
gpg: revocation certificate stored as '/home/user/.gnupg/openpgp-revocs.d/68068E51EC750FBF065441102E8E77A4A63FFC54.rev'
public and secret key created and signed.
```

## Importing existing keys

⚠️ Opcard being alpha software, we do not guarantee that future updates will not lead to data loss. If you import a key to the card, we recommand you also keep a backup with `gpg --export-secret-keys <key email>` and `gpg --export-secret-subkeys <key email>`.


If you already have PGP keys, you should be able to import them using `gpg --edit-key <key email>` and then `keytocard` (**this will delete your key from your computer!**) will move the signing key.
Continue with `key 1` to select the encryption subkey and repeat `keytocard` to move it too.

## Changing the PIN

Use `gpg --edit-card` to edit the card, then `admin` to enable administration commands, then `passwd` to change either the admin pin or the user pin.

## Changing card data

Use `gpg --edit-card` to edit the card, then `admin` to enable administration commands.
You can then use the commands `login`, `url`, `name`, `lang` and `salutation` to change the card data.