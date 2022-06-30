# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

FROM rust:latest

RUN apt update
RUN apt install --yes libclang-dev llvm python3-pip

RUN python3 -m pip install reuse

RUN rustup component add clippy rustfmt

WORKDIR /app
