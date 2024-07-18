# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

FROM docker.io/archlinux

RUN pacman --noconfirm -Syu gnupg clang llvm python pkgconf nettle pcsclite reuse rustup cargo-tarpaulin cargo-fuzz base-devel git

RUN rustup default stable && rustup component add clippy rustfmt && rustup toolchain install nightly
COPY vsmartcard-0.9-1-x86_64.pkg.tar.zst vsmartcard-0.9-1-x86_64.pkg.tar.zst
RUN pacman --noconfirm -U vsmartcard-0.9-1-x86_64.pkg.tar.zst && rm vsmartcard-0.9-1-x86_64.pkg.tar.zst

RUN mkdir -p ~/.gnupg
RUN echo "disable-ccid" > ~/.gnupg/scdaemon.conf
RUN echo "log-file /app/.cache/scdaemon.log" >> ~/.gnupg/scdaemon.conf

ENV CARGO_HOME=/app/.cache/cargo

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
