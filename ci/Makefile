# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

TAG := opcard-ci

.PHONY: build
build:
	docker build . --tag $(TAG)

.PHONY: push
push:
	docker push $(TAG)

.PHONY: run
run:
	docker run --interactive --rm --volume "$(PWD)/..:/app" $(TAG) make ci
