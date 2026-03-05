SHELL := /bin/sh

APP_NAME := ende
PKG := ./cmd/ende
DIST_DIR := dist
PKG_DIR := $(DIST_DIR)/packages

GO ?= go
CGO_ENABLED ?= 0
DOCKER ?= docker
GO_DOCKER_IMAGE ?= golang:1.25
DOCKER_GOFLAGS ?= -mod=vendor

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS ?= -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

PLATFORMS := \
	darwin/amd64 \
	darwin/arm64 \
	linux/amd64 \
	linux/arm64 \
	windows/amd64 \
	windows/arm64

.PHONY: help build build-all package checksums test clean vendor docker-test docker-build docker-build-all

help:
	@echo "Targets:"
	@echo "  make build      Build for current OS/ARCH"
	@echo "  make build-all  Build for macOS, Linux, Windows (amd64/arm64)"
	@echo "  make package    Create release archives and checksums"
	@echo "  make checksums  Generate SHA256SUMS for archives"
	@echo "  make test       Run unit tests"
	@echo "  make vendor     Refresh vendored dependencies"
	@echo "  make docker-test      Run tests in Docker"
	@echo "  make docker-build     Build current OS/ARCH in Docker"
	@echo "  make docker-build-all Cross-build all targets in Docker"
	@echo "  make clean      Remove build artifacts"

build:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME) $(PKG)
	@echo "Built $(DIST_DIR)/$(APP_NAME)"

build-all:
	@mkdir -p $(DIST_DIR)
	@set -e; \
	for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		out="$(DIST_DIR)/$(APP_NAME)-$${os}-$${arch}"; \
		if [ "$$os" = "windows" ]; then out="$$out.exe"; fi; \
		echo "Building $$os/$$arch -> $$out"; \
		CGO_ENABLED=$(CGO_ENABLED) GOOS=$$os GOARCH=$$arch $(GO) build -ldflags "$(LDFLAGS)" -o $$out $(PKG); \
	done

package: build-all
	@mkdir -p $(PKG_DIR)
	@set -e; \
	for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		base="$(APP_NAME)-$${os}-$${arch}"; \
		bin="$(DIST_DIR)/$$base"; \
		if [ "$$os" = "windows" ]; then bin="$$bin.exe"; fi; \
		if [ "$$os" = "windows" ]; then \
			archive="$(PKG_DIR)/$$base.zip"; \
			zip -j -q "$$archive" "$$bin"; \
		else \
			archive="$(PKG_DIR)/$$base.tar.gz"; \
			tar -C "$(DIST_DIR)" -czf "$$archive" "$$(basename "$$bin")"; \
		fi; \
		echo "Packaged $$archive"; \
	done
	@$(MAKE) checksums

checksums:
	@mkdir -p $(PKG_DIR)
	@set -e; \
	cd $(PKG_DIR); \
	if command -v sha256sum >/dev/null 2>&1; then \
		sha256sum *.tar.gz *.zip > SHA256SUMS; \
	else \
		shasum -a 256 *.tar.gz *.zip > SHA256SUMS; \
	fi; \
	echo "Wrote $(PKG_DIR)/SHA256SUMS"

test:
	$(GO) test ./...

vendor:
	$(GO) mod vendor

docker-test:
	$(DOCKER) run --rm \
		-v "$(CURDIR)":/src \
		-w /src \
		$(GO_DOCKER_IMAGE) \
		sh -lc 'set -eu; export PATH="$$PATH:/usr/local/go/bin"; command -v go >/dev/null; go version; test -d vendor; GOFLAGS="$(DOCKER_GOFLAGS)" go test ./...'

docker-build:
	$(DOCKER) run --rm \
		-v "$(CURDIR)":/src \
		-w /src \
		-e CGO_ENABLED=$(CGO_ENABLED) \
		$(GO_DOCKER_IMAGE) \
		sh -lc 'set -eu; export PATH="$$PATH:/usr/local/go/bin"; command -v go >/dev/null; go version; test -d vendor; mkdir -p $(DIST_DIR); GOFLAGS="$(DOCKER_GOFLAGS)" go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME) $(PKG)'

docker-build-all:
	$(DOCKER) run --rm \
		-v "$(CURDIR)":/src \
		-w /src \
		-e CGO_ENABLED=$(CGO_ENABLED) \
		$(GO_DOCKER_IMAGE) \
		sh -lc 'set -eu; export PATH="$$PATH:/usr/local/go/bin"; command -v go >/dev/null; go version; test -d vendor; mkdir -p $(DIST_DIR); \
		for platform in $(PLATFORMS); do \
			os=$${platform%/*}; \
			arch=$${platform#*/}; \
			out="$(DIST_DIR)/$(APP_NAME)-$${os}-$${arch}"; \
			if [ "$$os" = "windows" ]; then out="$$out.exe"; fi; \
			echo "Building $$os/$$arch -> $$out"; \
			GOOS=$$os GOARCH=$$arch GOFLAGS="$(DOCKER_GOFLAGS)" go build -ldflags "$(LDFLAGS)" -o $$out $(PKG); \
		done'

clean:
	rm -rf $(DIST_DIR)
