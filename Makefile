# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

.PHONY: check
check:
	cargo check --all-features --all-targets
	cargo check --no-default-features
	cargo clippy --all-features --all-targets -- --deny warnings
	cargo fmt -- --check
	reuse lint

.PHONY: fix
fix:
	cargo fix --all-features
	cargo fmt

.PHONY: test
test:
	RUST_LOG=info cargo test --all-features
	RUST_LOG=info cargo test --all-features -- --ignored || true

.PHONY: ci
ci: check test
