# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

FROM docker.io/rust:bullseye

RUN apt update && apt upgrade --yes
RUN apt install --yes gnupg scdaemon libclang-dev llvm python3-pip vsmartcard-vpcd pkg-config nettle-dev libpcsclite-dev
RUN python3 -m pip install reuse

RUN rustup component add clippy rustfmt && rustup toolchain install nightly
RUN cargo install cargo-tarpaulin cargo-fuzz --profile release && rm -rf "$CARGO_HOME"/registry

RUN mkdir -p ~/.gnupg
RUN echo "disable-ccid" > ~/.gnupg/scdaemon.conf
RUN echo "log-file /app/.cache/scdaemon.log" >> ~/.gnupg/scdaemon.conf

ENV CARGO_HOME=/app/.cache/cargo

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
