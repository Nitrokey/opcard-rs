# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

export RUST_LOG ?= info

.PHONY: check
check:
	cargo check --all-features --all-targets
	cargo check --no-default-features
	cargo clippy --all-features --all-targets -- --deny warnings
	cargo fmt -- --check
	RUSTDOCFLAGS='-Dwarnings' cargo doc --all-features --package opcard
	reuse lint

.PHONY: fix
fix:
	cargo fix --all-features
	cargo fmt

.PHONY: test
test:
	cargo test --features virtual
	cargo test --features virtual --no-fail-fast -- --ignored || true

.PHONY: ci
ci: | check test
