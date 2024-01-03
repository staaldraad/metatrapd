SHELL := /bin/bash
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

all: build

GO = go
GOOS = $(shell $(GO) env GOOS)
GOARCH = $(shell $(GO) env GOARCH)

.PHONY: build
build:  ## Build metatrapd binary.
	$(GO) build -o bin/metatrapd cmd/metatrapd/main.go

.PHONY: release
release:  ## Build for all ARCH
	# 32-bit
	# Linux
	GOOS=linux GOARCH=386 $(GO) build -o bin/metatrapd-x86 cmd/metatrapd/main.go
	# 64-bit
	GOOS=linux GOARCH=amd64 $(GO) build -o bin/metatrapd-x64 cmd/metatrapd/main.go
	sha256sum bin/metatrapd-*  > bin/SHA256SUMS
