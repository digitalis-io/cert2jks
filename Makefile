.PHONY: build test test-race lint fmt vet tidy cover bench clean help

BIN_DIR  ?= bin
PKG       = ./...

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Compile all packages
	go build $(PKG)

test: ## Run unit tests
	go test $(PKG)

test-race: ## Run unit tests with race detector
	go test -race -count=1 $(PKG)

cover: ## Run tests with coverage report
	go test -coverprofile=coverage.out $(PKG)
	go tool cover -func=coverage.out

bench: ## Run benchmarks
	go test -bench=. -benchmem $(PKG)

lint: ## Run golangci-lint
	golangci-lint run

fmt: ## Format code with gofmt
	gofmt -s -w .

vet: ## Run go vet
	go vet $(PKG)

tidy: ## Tidy go.mod / go.sum
	go mod tidy

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) coverage.out
