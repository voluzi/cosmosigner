BINARY := cosmosigner
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X github.com/voluzi/cosmosigner/internal/version.Version=$(VERSION) \
           -X github.com/voluzi/cosmosigner/internal/version.Commit=$(COMMIT) \
           -X github.com/voluzi/cosmosigner/internal/version.Date=$(DATE)

.PHONY: build install test test-race vet tidy clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/cosmosigner

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/cosmosigner

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

clean:
	rm -rf bin
