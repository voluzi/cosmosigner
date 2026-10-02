BINARY := cosmosigner
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X github.com/voluzi/cosmosigner/internal/version.Version=$(VERSION) \
           -X github.com/voluzi/cosmosigner/internal/version.Commit=$(COMMIT) \
           -X github.com/voluzi/cosmosigner/internal/version.Date=$(DATE)

.PHONY: build build-pkcs11 install test test-pkcs11 test-race vet tidy clean

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/cosmosigner

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/cosmosigner

test:
	go test ./...

test-race:
	go test -race ./...

test-cover:
	go test -race -coverprofile=coverage.out ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

clean:
	rm -rf bin

build-pkcs11: ## Build the native PKCS#11 variant (requires a C compiler).
	CGO_ENABLED=1 go build -tags pkcs11 -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-pkcs11 ./cmd/cosmosigner

test-pkcs11: ## Test a disposable token configured by scripts/softhsm-dev.sh.
	go vet -tags pkcs11 ./...
	go test -race -tags "pkcs11 pkcs11_integration" -run PKCS11 -count=10 ./internal/backend ./internal/config ./cmd/cosmosigner/cmd
	go test -race -tags "pkcs11 pkcs11_integration" ./...
