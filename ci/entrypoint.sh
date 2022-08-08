#!/bin/sh
# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

set -e
mkdir -p /app/.cache
if [ ! -e "$CARGO_HOME" ]
then
	cp -r /usr/local/cargo $CARGO_HOME
fi
pcscd
exec "$@"
