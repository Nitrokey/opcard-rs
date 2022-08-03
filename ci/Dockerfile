# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

FROM rust:latest

RUN apt update
RUN apt install --yes gnupg scdaemon libclang-dev llvm python3-pip vsmartcard-vpcd pkg-config nettle-dev

RUN python3 -m pip install reuse

RUN rustup component add clippy rustfmt

# initialize cargo cache
RUN cargo search

RUN mkdir -p ~/.gnupg
RUN echo "disable-ccid" > ~/.gnupg/scdaemon.conf

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
