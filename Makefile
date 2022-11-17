# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

export RUST_LOG ?= info,cargo_tarpaulin=off

FUZZ_JOBS?=$(shell nproc)
FUZZ_DURATION?="0"

.NOTPARALLEL:

.PHONY: check
check:
	cargo check --all-features --all-targets --workspace
	cargo check --no-default-features --all-targets
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
	cargo test --features virtual,rsa2048,rsa4096

.PHONY: fuzz
fuzz: fuzz-corpus
	cargo +nightly fuzz run --jobs ${FUZZ_JOBS} fuzz_target_1 fuzz/corpus -- -max_total_time=${FUZZ_DURATION}

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

.PHONY: tarpaulin
tarpaulin:
	cargo tarpaulin --features virtual -o Html -o Xml

.PHONY: ci
ci: check tarpaulin

.PHONY: clean
clean:
	cargo clean
	cd fuzz && cargo clean && rm -rf corpus
	rm -f fuzz_coverage.html
