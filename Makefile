#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: all test clean lint gosec

all: fulcio
# Ensure Make is run with bash shell as some syntax below is bash-specific
SHELL:=/usr/bin/env bash

SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go")
BIN_DIR := $(abspath $(ROOT_DIR)/bin)

# Set version variables for LDFLAGS
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
GIT_TAG ?= dirty-tag
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

FULCIO_PKG=github.com/sigstore/fulcio/cmd/app
LDFLAGS=-X $(FULCIO_PKG).gitVersion=$(GIT_VERSION) -X $(FULCIO_PKG).gitCommit=$(GIT_HASH) -X $(FULCIO_PKG).gitTreeState=$(GIT_TREESTATE) -X $(FULCIO_PKG).buildDate=$(BUILD_DATE)

KO_PREFIX ?= gcr.io/projectsigstore
export KO_DOCKER_REPO=$(KO_PREFIX)

GHCR_PREFIX ?= ghcr.io/sigstore

FULCIO_YAML ?= fulcio-$(GIT_TAG).yaml

lint: ## Runs golangci-lint
	$(GOBIN)/golangci-lint run -v ./...

gosec: ## Runs gosec
	$(GOBIN)/gosec ./...

fulcio: $(SRCS) ## Build Fulcio for local tests
	go build -trimpath -ldflags "$(LDFLAGS)"

test: ## Runs go test
	go test ./...

clean: ## Clean the workspace
	rm -rf dist
	rm -rf fulcio

up: ## Start docker compose
	docker-compose -f docker-compose.yml build
	docker-compose -f docker-compose.yml up

debug: ## Start docker compose in debug mode
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml build fulcio-server-debug
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml up fulcio-server-debug

## --------------------------------------
## Images with ko
## --------------------------------------

.PHONY: ko-local
ko-local:
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	ko publish --base-import-paths \
		--platform=linux/amd64 --tags $(GIT_VERSION) --tags $(GIT_HASH) --local \
		github.com/sigstore/fulcio

.PHONY: ko-apply
ko-apply:
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) ko apply -Bf config/

.PHONY: ko-apply-ci
ko-apply-ci: ko-apply
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) ko apply -Bf config/test

.PHONY: ko-publish
ko-publish:
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) ko publish .

## --------------------------------------
## Modules
## --------------------------------------

.PHONY: modules
modules: ## Runs go mod to ensure modules are up to date.
	go mod tidy

##################
# help
##################

help: ## Display help
	@awk -F ':|##' \
		'/^[^\t].+?:.*?##/ {\
			printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
		}' $(MAKEFILE_LIST) | sort

include release/release.mk
