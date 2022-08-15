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

.PHONY: fuzz
fuzz: fuzz-corpus
	cargo +nightly fuzz run --jobs $$(nproc) fuzz_target_1 fuzz/corpus

.PHONY: fuzz-check
fuzz-check: fuzz-corpus
	cd fuzz && cargo check --all-targets

.PHONY: fuzz-corpus
fuzz-corpus:
	mkdir -p fuzz/corpus
	cd fuzz && cargo r --bin opcard-fuzz

.PHONY: fuzz-cov
fuzz-cov:
	cargo +nightly fuzz coverage fuzz_target_1 fuzz/corpus
	llvm-cov show --format=html \
		--instr-profile=fuzz/coverage/fuzz_target_1/coverage.profdata \
		fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_target_1 \
		> fuzz_coverage.html

.PHONY: ci
ci: | check test fuzz-check

.PHONY: clean
clean:
	cargo clean
	cd fuzz && cargo clean && rm -rf corpus
	rm -f fuzz_coverage.html
