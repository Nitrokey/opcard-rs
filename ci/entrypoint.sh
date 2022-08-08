#!/bin/sh
# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

set -e
mkdir -p /app/.cache
pcscd
exec "$@"
