# See https://tech.davis-hansson.com/p/make/
SHELL := bash
.DELETE_ON_ERROR:
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := all
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules
MAKEFLAGS += --no-print-directory
BIN := .tmp/bin
export PATH := $(abspath $(BIN)):$(PATH)
export GOBIN := $(abspath $(BIN))
COPYRIGHT_YEARS := 2023-2026
LICENSE_IGNORE := --ignore testdata/ --ignore .github/ --ignore ".*\.ya?ml"
BUF_VERSION := 1.73.0
GOLANGCI_LINT_VERSION ?= v2.13.2

.PHONY: help
help: ## Describe useful make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "%-30s %s\n", $$1, $$2}'

.PHONY: all
all: ## Build, test, and lint (default)
	$(MAKE) test
	$(MAKE) lint

.PHONY: clean
clean: ## Delete intermediate build artifacts
	@# -X only removes untracked files, -d recurses into directories, -f actually removes files/dirs
	git clean -Xdf

.PHONY: test
test: build ## Run unit tests
	go test -vet=off -race -cover ./...

.PHONY: build
build: generate ## Build all packages
	go build ./...

.PHONY: generate
generate: $(BIN)/buf $(BIN)/protoc-gen-go $(BIN)/protoc-gen-connect-go $(BIN)/license-header ## Regenerate code and licenses
	rm -rf internal/gen
	PATH="$(abspath $(BIN))" buf generate
	license-header \
		--license-type apache \
		--copyright-holder "Buf Technologies, Inc." \
		--year-range "$(COPYRIGHT_YEARS)" $(LICENSE_IGNORE)

.PHONY: lint
lint: $(BIN)/golangci-lint $(BIN)/buf ## Lint Go and protobuf
	go vet ./...
	golangci-lint run --modules-download-mode=readonly --timeout=3m0s
	golangci-lint fmt --diff
	buf lint
	buf format -d --exit-code

.PHONY: lintfix
lintfix: $(BIN)/golangci-lint $(BIN)/buf ## Automatically fix some lint errors
	golangci-lint run --fix --modules-download-mode=readonly --timeout=3m0s
	golangci-lint fmt
	buf format -w

.PHONY: install
install: ## Install all binaries
	go install ./...

.PHONY: upgrade
upgrade: ## Upgrade dependencies
	go get -u -t ./... && go mod tidy -v

.PHONY: checkgenerate
checkgenerate:
	@# Used in CI to verify that `make generate` doesn't produce a diff.
	test -z "$$(git status --porcelain | tee /dev/stderr)"

$(BIN)/license-header: Makefile
	@mkdir -p $(@D)
	go install github.com/bufbuild/buf/private/pkg/licenseheader/cmd/license-header@v${BUF_VERSION}

$(BIN)/golangci-lint: Makefile
	@mkdir -p $(@D)
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(BIN)/buf: Makefile
	@mkdir -p $(@D)
	go install github.com/bufbuild/buf/cmd/buf@v${BUF_VERSION}

$(BIN)/protoc-gen-go: Makefile go.mod
	@mkdir -p $(@D)
	@# The version of protoc-gen-go is determined by the version in go.mod
	go install google.golang.org/protobuf/cmd/protoc-gen-go

$(BIN)/protoc-gen-connect-go: Makefile go.mod
	@mkdir -p $(@D)
	@# The version of protoc-gen-connect-go is determined by the version in go.mod
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go
