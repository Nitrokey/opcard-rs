# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

-include config.mk

TAG := registry.git.nitrokey.com/nitrokey/opcard-rs/opcard-rs-build
DOCKER ?= docker
FUZZ_JOBS?=$(shell nproc)
FUZZ_DURATION?="0"

.PHONY: build
build:
	$(DOCKER) build . --tag $(TAG)

.PHONY: push
push:
	$(DOCKER) push $(TAG)

.PHONY: run
run:
	$(DOCKER) run --interactive --rm --volume "$(PWD)/..:/app" --env RUST_LOG $(TAG) make ci

.PHONY: test
test:
	$(DOCKER) run --interactive --rm --volume "$(PWD)/..:/app" --env RUST_LOG $(TAG) make test
	
.PHONY: fuzz
fuzz:
	$(DOCKER) run --interactive --rm --volume "$(PWD)/..:/app" --env RUST_LOG $(TAG) make fuzz FUZZ_JOBS=${FUZZ_JOBS} FUZZ_DURATION=${FUZZ_DURATION}
