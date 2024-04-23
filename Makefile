# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

-include variables.mk

export RUST_LOG ?= info,cargo_tarpaulin=off
export OPCARD_DANGEROUS_TEST_CARD_USB_VENDOR ?= 0000
export OPCARD_DANGEROUS_TEST_CARD_USB_PRODUCT ?= 000000
export OPCARD_DANGEROUS_TEST_CARD_PGP_VENDOR ?= 0000
export OPCARD_DANGEROUS_TEST_CARD_PGP_SERIAL ?= 000000

FUZZ_JOBS?=$(shell nproc)
FUZZ_DURATION?="0"

.NOTPARALLEL:

.PHONY: check
check:
	cargo check --all-features --all-targets --workspace

.PHONY: lint
lint:
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
	cargo test --features vpicc,rsa4096-gen 
	

.PHONY: test
dangerous-real-card-test:
	ps aux | grep pcscd | grep -v grep || sudo pcscd
	cargo test --features rsa2048-gen,rsa4096,dangerous-test-real-card sequoia
	sudo pkill pcscd
	cargo test --features rsa2048-gen,rsa4096-gen,dangerous-test-real-card _hardware

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
	cargo tarpaulin --features vpicc,rsa4096-gen -o Html -o Xml

.PHONY: ci
ci: lint tarpaulin

.PHONY: clean
clean:
	cargo clean
	cd fuzz && cargo clean && rm -rf corpus
	rm -f fuzz_coverage.html

.PHONY: example-vpicc
example-vpicc:
	cargo run --example vpicc --features vpicc,rsa4096-gen

.PHONY: example-usbip
example-usbip:
	cargo run --example usbip --features virt,rsa4096-gen,apdu-dispatch
