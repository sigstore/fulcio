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
DATE_FMT = +'%Y-%m-%dT%H:%M:%SZ'
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

SERVER_PKG=github.com/sigstore/fulcio/cmd/app
SERVER_LDFLAGS="-X $(SERVER_PKG).gitVersion=$(GIT_VERSION) -X $(SERVER_PKG).gitCommit=$(GIT_HASH) -X $(SERVER_PKG).gitTreeState=$(GIT_TREESTATE) -X $(SERVER_PKG).buildDate=$(BUILD_DATE)"
	

lint:
	$(GOBIN)/golangci-lint run -v ./...

gosec:
	$(GOBIN)/gosec ./...

fulcio: $(SRCS)
	go build -trimpath -ldflags $(SERVER_LDFLAGS)

test:
	go test ./...

clean:
	rm -rf dist
	rm -rf fulcio

up:
	docker-compose -f docker-compose.yml build
	docker-compose -f docker-compose.yml up

debug:
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml build fulcio-server-debug
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml up fulcio-server-debug


## --------------------------------------
## Modules
## --------------------------------------

.PHONY: modules
modules: ## Runs go mod to ensure modules are up to date.
	go mod tidy

# --------------------------------------
## Release
## --------------------------------------

.PHONY: dist
dist:
	mkdir -p dist
	docker run -it -v $(PWD):/go/src/sigstore/fulcio -w /go/src/sigstore/fulcio golang:1.16.6 /bin/bash -c "GOOS=linux GOARCH=amd64 go build -trimpath -o dist/fulcio-server-linux-amd64"

