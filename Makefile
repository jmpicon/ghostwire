SHELL     := /bin/sh
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)
GOFLAGS   := -trimpath
# linux/arm is 32-bit ARMv7: Raspberry Pi OS still ships a 32-bit userland on
# plenty of boards, and a relay is exactly the job you want to hand to an SBC.
PLATFORMS := linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 freebsd/amd64
GOARM     ?= 7

.PHONY: all build test race vet fmt lint cross clean install docker onion help

all: build

## build: compile bin/gw and bin/gwd for this host
build:
	@mkdir -p bin
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/gw  ./cmd/gw
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/gwd ./cmd/gwd
	@echo "built $(VERSION)"

## test: unit and integration tests with the race detector
test: race

race:
	go test -race -count=1 ./...

## vet: static analysis
vet:
	go vet ./...

## fmt: rewrite sources with gofmt
fmt:
	gofmt -w .

## lint: fail if anything is unformatted, then vet
lint:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || { echo "gofmt: files need formatting"; exit 1; }
	go vet ./...

## cross: static binaries for every supported platform into dist/
cross:
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=''; suffix=$$arch; \
		[ "$$os" = windows ] && ext='.exe'; \
		[ "$$arch" = arm ] && suffix="armv$(GOARM)"; \
		echo "  $$os/$$suffix"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOARM=$(GOARM) go build $(GOFLAGS) -ldflags '$(LDFLAGS)' \
			-o dist/gw-$$os-$$suffix$$ext ./cmd/gw || exit 1; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOARM=$(GOARM) go build $(GOFLAGS) -ldflags '$(LDFLAGS)' \
			-o dist/gwd-$$os-$$suffix$$ext ./cmd/gwd || exit 1; \
	done
	@cd dist && sha256sum * > SHA256SUMS && echo "checksums in dist/SHA256SUMS"

## install: put gw and gwd in GOBIN
install:
	CGO_ENABLED=0 go install $(GOFLAGS) -ldflags '$(LDFLAGS)' ./cmd/gw ./cmd/gwd

## docker: bring up a relay with its own tor, in deploy/
docker:
	cd deploy && docker compose up -d --build

## onion: print the onion address of the dockerised relay
onion:
	@docker compose -f deploy/docker-compose.yml exec -T tor cat /var/lib/tor/ghostwire/hostname 2>/dev/null \
		| sed 's/$$/:1717/' || echo "relay not running: make docker"

## clean: remove build artefacts
clean:
	rm -rf bin dist

help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
