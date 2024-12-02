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

SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go"|grep -v pkg/generated) $(GENSRC)
TOOLS_DIR := hack/tools
TOOLS_BIN_DIR := $(abspath $(TOOLS_DIR)/bin)
BIN_DIR := $(abspath $(ROOT_DIR)/bin)

GO_MODULE=$(shell head -1 go.mod | cut -f2 -d ' ')

GENSRC = pkg/generated/protobuf/%.go %.swagger.json
PROTOBUF_DEPS = $(shell find . -iname "*.proto" | grep -v "third_party")

# Set version variables for LDFLAGS
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
GIT_TAG ?= dirty-tag
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)

FULCIO_VERSION_PKG=sigs.k8s.io/release-utils/version
LDFLAGS=-X $(FULCIO_VERSION_PKG).gitVersion=$(GIT_VERSION)

KO_PREFIX ?= gcr.io/projectsigstore
export KO_DOCKER_REPO=$(KO_PREFIX)

GHCR_PREFIX ?= ghcr.io/sigstore

FULCIO_YAML ?= fulcio-$(GIT_TAG).yaml

# It should be blank for default builds
FORMATED_LABEL ?=

GITHUB_RUN_NUMBER ?= "local"

FULL_TAG := "0.$(shell date +%Y%m%d).$(GITHUB_RUN_NUMBER)-ref.$(GIT_VERSION)"

# Binaries
PROTOC-GEN-GO := $(TOOLS_BIN_DIR)/protoc-gen-go
PROTOC-GEN-GO-GRPC := $(TOOLS_BIN_DIR)/protoc-gen-go-grpc
PROTOC-GEN-GRPC-GATEWAY := $(TOOLS_BIN_DIR)/protoc-gen-grpc-gateway
PROTOC-GEN-OPENAPIV2 := $(TOOLS_BIN_DIR)/protoc-gen-openapiv2
PROTOC-API-LINTER := $(TOOLS_BIN_DIR)/api-linter

$(GENSRC): $(PROTOC-GEN-GO) $(PROTOC-GEN-GO-GRPC) $(PROTOC-GEN-GRPC-GATEWAY) $(PROTOC-API-LINTER) $(PROTOC-GEN-OPENAPIV2) $(PROTOBUF_DEPS)
	mkdir -p pkg/generated/protobuf
	$(PROTOC-API-LINTER) -I third_party/googleapis/ -I . $(PROTOBUF_DEPS) #--set-exit-status # TODO: add strict checking
	protoc --plugin=protoc-gen-go=$(TOOLS_BIN_DIR)/protoc-gen-go \
	       --go_opt=module=$(GO_MODULE) --go_out=. \
	       --plugin=protoc-gen-go-grpc=$(TOOLS_BIN_DIR)/protoc-gen-go-grpc \
	       --go-grpc_opt=module=$(GO_MODULE) --go-grpc_out=. \
	       --plugin=protoc-gen-grpc-gateway=$(TOOLS_BIN_DIR)/protoc-gen-grpc-gateway \
	       --grpc-gateway_opt=module=$(GO_MODULE) --grpc-gateway_opt=logtostderr=true --grpc-gateway_out=. \
	       --plugin=protoc-gen-openapiv2=$(TOOLS_BIN_DIR)/protoc-gen-openapiv2 \
	       --openapiv2_out . \
		   -I third_party/googleapis/ -I . $(PROTOBUF_DEPS)

lint: ## Runs golangci-lint
	$(GOBIN)/golangci-lint run -v ./...

gosec: ## Runs gosec
	$(GOBIN)/gosec ./...

gen: $(GENSRC)

fulcio: $(SRCS) ## Build Fulcio for local tests
	go build -trimpath -ldflags "$(LDFLAGS)"

test: ## Runs go test
	go test ./...

clean: ## Clean the workspace
	rm -rf dist
	rm -rf fulcio

clean-gen: clean
	rm -rf $(shell find pkg/generated -iname "*.go") *.swagger.json

up: ## Start docker compose
	docker-compose -f docker-compose.yml build
	docker-compose -f docker-compose.yml up

debug: ## Start docker compose in debug mode
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml build fulcio-server-debug
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml up fulcio-server-debug

## --------------------------------------
## Tooling Binaries
## --------------------------------------

$(PROTOC-GEN-GO): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR); go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/protoc-gen-go google.golang.org/protobuf/cmd/protoc-gen-go

$(PROTOC-GEN-GO-GRPC): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR); go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/protoc-gen-go-grpc google.golang.org/grpc/cmd/protoc-gen-go-grpc

$(PROTOC-GEN-GRPC-GATEWAY): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR); go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/protoc-gen-grpc-gateway github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway

$(PROTOC-GEN-OPENAPIV2): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR); go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/protoc-gen-openapiv2 github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2

$(PROTOC-API-LINTER): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR); go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/api-linter github.com/googleapis/api-linter/cmd/api-linter

## --------------------------------------
## Images with ko
## --------------------------------------

.PHONY: ko
ko:
	# fulcio
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KO_DOCKER_REPO=$(KO_PREFIX)/fulcio ko resolve $(FORMATED_LABEL) --bare \
		--platform=linux/amd64 --tags $(GIT_VERSION) --tags $(GIT_HASH) --tags $(FULL_TAG) \
		--image-refs fulcioImagerefs --filename config/ > $(FULCIO_YAML)

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

.PHONY: sign-keyless-ci
sign-keyless-ci: ko
	cosign sign --yes -a GIT_HASH=$(GIT_HASH) $(KO_DOCKER_REPO)/fulcio:$(GIT_HASH)

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
