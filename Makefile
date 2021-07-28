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

GENSRC = pkg/generated/models/%.go pkg/generated/restapi/%.go
OPENAPIDEPS = openapi.yaml
SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go"|grep -v pkg/generated) pkg/generated/restapi/configure_fulcio_server.go $(GENSRC)
TOOLS_DIR := hack/tools
TOOLS_BIN_DIR := $(abspath $(TOOLS_DIR)/bin)
BIN_DIR := $(abspath $(ROOT_DIR)/bin)

# Binaries
SWAGGER := $(TOOLS_BIN_DIR)/swagger

$(GENSRC): $(SWAGGER) $(OPENAPIDEPS)
	$(SWAGGER) generate server -f openapi.yaml -q -r COPYRIGHT.txt -t pkg/generated --exclude-main -A fulcio_server --exclude-spec --flag-strategy=pflag -P github.com/coreos/go-oidc/v3/oidc.IDToken

# this exists to override pattern match rule above since this file is in the generated directory but should not be treated as generated code
pkg/generated/restapi/configure_fulcio_server.go: $(OPENAPIDEPS)
	

lint:
	$(GOBIN)/golangci-lint run -v ./...

gosec:
	$(GOBIN)/gosec ./...

fulcio: $(SRCS)
	go build

test:
	go test ./...

clean:
	rm -rf dist
	rm -rf hack/tools/bin
	rm -rf fulcio

up:
	docker-compose -f docker-compose.yml build
	docker-compose -f docker-compose.yml up

debug:
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml build fulcio-server-debug
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml up fulcio-server-debug


.PHONY: validate-openapi
validate-openapi: $(SWAGGER)
	$(SWAGGER) validate openapi.yaml

## --------------------------------------
## Modules
## --------------------------------------

.PHONY: modules
modules: ## Runs go mod to ensure modules are up to date.
	go mod tidy
	cd $(TOOLS_DIR); go mod tidy

# --------------------------------------
## Release
## --------------------------------------

.PHONY: dist
dist:
	mkdir -p dist
	docker run -it -v $(PWD):/go/src/sigstore/fulcio -w /go/src/sigstore/fulcio golang:1.16.6 /bin/bash -c "GOOS=linux GOARCH=amd64 go build -o dist/fulcio-server-linux-amd64"

## --------------------------------------
## Tooling Binaries
## --------------------------------------

$(SWAGGER): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR); go build -tags=tools -o $(TOOLS_BIN_DIR)/swagger github.com/go-swagger/go-swagger/cmd/swagger
