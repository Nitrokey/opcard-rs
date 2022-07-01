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
	cargo test --features backend-software

.PHONY: ci
ci: check test
