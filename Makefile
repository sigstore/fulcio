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

.PHONY: all test clean lint gosec cert-maker ldflags

all: fulcio
# Ensure Make is run with bash shell as some syntax below is bash-specific
SHELL:=/usr/bin/env bash

SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go"|grep -v pkg/generated) $(GENSRC)
TOOLS_DIR_GO_MOD := hack/tools/go.mod


GO_MODULE=$(shell head -1 go.mod | cut -f2 -d ' ')

GENSRC = pkg/generated/protobuf/%.go %.swagger.json
PROTOBUF_DEPS = $(shell find . -iname "*.proto" | grep -v "third_party")

# Set version variables for LDFLAGS
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = clean
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = dirty
endif

FULCIO_VERSION_PKG=sigs.k8s.io/release-utils/version
LDFLAGS=-buildid= -X $(FULCIO_VERSION_PKG).gitVersion=$(GIT_VERSION) \
                  -X $(FULCIO_VERSION_PKG).gitCommit=$(GIT_HASH) \
                  -X $(FULCIO_VERSION_PKG).gitTreeState=$(GIT_TREESTATE) \
                  -X $(FULCIO_VERSION_PKG).buildDate=$(BUILD_DATE)
SERVER_LDFLAGS=$(LDFLAGS)

KO_PREFIX ?= ghcr.io/sigstore
export KO_DOCKER_REPO=$(KO_PREFIX)
KO_DEFAULTBASEIMAGE ?= gcr.io/distroless/static-debian13:nonroot
export KO_DEFAULTBASEIMAGE

ifdef INSECURE_REGISTRY
KO_FLAGS += --insecure-registry
endif

ZIZMOR ?= $(shell grep FROM Dockerfile.zizmor | cut -d' ' -f 2)

$(GENSRC): $(PROTOBUF_DEPS) $(TOOLS_DIR_GO_MOD)
	mkdir -p pkg/generated/protobuf
	$$(go tool -modfile=$(TOOLS_DIR_GO_MOD) -n api-linter) -I third_party/googleapis/ -I . $(PROTOBUF_DEPS) #--set-exit-status # TODO: add strict checking
	protoc --plugin=protoc-gen-go=$$(go tool -modfile=$(TOOLS_DIR_GO_MOD) -n protoc-gen-go) \
	       --go_opt=module=$(GO_MODULE) --go_out=. \
	       --plugin=protoc-gen-go-grpc=$$(go tool -modfile=$(TOOLS_DIR_GO_MOD) -n protoc-gen-go-grpc) \
	       --go-grpc_opt=module=$(GO_MODULE) --go-grpc_out=. \
	       --plugin=protoc-gen-grpc-gateway=$$(go tool -modfile=$(TOOLS_DIR_GO_MOD) -n protoc-gen-grpc-gateway) \
	       --grpc-gateway_opt=module=$(GO_MODULE) --grpc-gateway_opt=logtostderr=true --grpc-gateway_out=. \
	       --plugin=protoc-gen-openapiv2=$$(go tool -modfile=$(TOOLS_DIR_GO_MOD) -n protoc-gen-openapiv2) \
	       --openapiv2_out . \
		   -I third_party/googleapis/ -I . $(PROTOBUF_DEPS)

lint: ## Runs golangci-lint and zizmor
	docker run -t --rm -v $(PWD):/app -w /app \
		--user $(shell id -u):$(shell id -g) \
		-v $(shell go env GOCACHE):/.cache/go-build -e GOCACHE=/.cache/go-build \
		-v $(shell go env GOMODCACHE):/go/pkg/mod -e GOMODCACHE=/go/pkg/mod \
		-v ~/.cache/golangci-lint:/.cache/golangci-lint -e GOLANGCI_LINT_CACHE=/.cache/golangci-lint \
		$(shell awk -F '[ @]' '/FROM golangci\/golangci-lint/{print $$2; exit}' Dockerfile.golangci-lint) golangci-lint run -v ./...
	docker run -t --rm -v $(PWD):/source $(ZIZMOR) /source

gosec: ## Runs gosec
	$(GOBIN)/gosec ./...

gen: $(GENSRC)

ldflags: ## Print LDFLAGS for builds
	@echo $(SERVER_LDFLAGS)

fulcio: $(SRCS) ## Build Fulcio for local tests
	go build -trimpath -ldflags "$(LDFLAGS)" ./...

cert-maker: ## Build the Fulcio Certificate Maker tool
	go build -trimpath -ldflags "$(LDFLAGS)" -o certificate-maker ./cmd/certificate_maker

test: ## Runs go test
	go test ./...

clean: ## Clean the workspace
	rm -rf dist
	rm -rf fulcio
	rm -rf fulcioImagerefs
	rm -rf certificate-maker
	rm -rf root.pem
	rm -rf intermediate.pem
	rm -rf leaf.pem

clean-gen: clean
	rm -rf $(shell find pkg/generated -iname "*.go") *.swagger.json

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
ko-local: ## Build container images locally using ko
	KO_DOCKER_REPO=ko.local ko publish --base-import-paths \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) --image-refs fulcioImagerefs \
		github.com/sigstore/fulcio

.PHONY: ko-apply
ko-apply:
	ko apply $(KO_FLAGS) -Bf config/

.PHONY: ko-apply-ci
ko-apply-ci: ko-apply
	ko apply $(KO_FLAGS) -Bf config/test

.PHONY: ko-publish
ko-publish:
	ko publish $(KO_FLAGS) .

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
