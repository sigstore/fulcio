.PHONY: all test clean lint gosec

all: server

GENSRC = pkg/generated/models/%.go pkg/generated/restapi/%.go
OPENAPIDEPS = openapi.yaml
SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go"|grep -v pkg/generated) pkg/generated/restapi/configure_fulcio_server.go $(GENSRC)

$(GENSRC): $(OPENAPIDEPS)
	swagger generate server -f openapi.yaml -q -r COPYRIGHT.txt -t pkg/generated --exclude-main -A fulcio_server --exclude-spec --flag-strategy=pflag --default-produces application/json
	swagger generate client -f openapi.yaml -q -r COPYRIGHT.txt -t pkg/generated --default-consumes application/json\;q=1

# this exists to override pattern match rule above since this file is in the generated directory but should not be treated as generated code
pkg/generated/restapi/configure_fulcio_server.go: $(OPENAPIDEPS)
	

lint:
	$(GOBIN)/golangci-lint run -v ./...

gosec:
	$(GOBIN)/gosec ./...

server: $(SRCS)
	go build ./cmd/server

test:
	go test ./...

clean:
	rm -rf server

up:
	docker-compose -f docker-compose.yml build
	docker-compose -f docker-compose.yml up

debug:
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml build fulcio-server-debug
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml up fulcio-server-debug
