# AegisDNS build entry points.
#
# `make build` produces the single static binary that is the whole product:
# datapath, control plane and admin panel. It depends on `make web`, because
# the panel is embedded rather than shipped alongside.

BINARY      := seddns
PKG         := ./cmd/seddns
DIST        := dist
WEB_DIR     := web
EMBED_DIR   := internal/web/dist

VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

VERSION_PKG := github.com/MmTKya/DNS/internal/version
LDFLAGS     := -s -w \
	-X $(VERSION_PKG).Version=$(VERSION) \
	-X $(VERSION_PKG).Commit=$(COMMIT) \
	-X $(VERSION_PKG).Date=$(DATE)

# CGO stays off so that cross-compiling to arm64 and armv7 needs no toolchain
# and the result runs on any glibc or musl system.
export CGO_ENABLED := 0

.DEFAULT_GOAL := build

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: web
web: ## Build the admin panel into internal/web/dist
	cd $(WEB_DIR) && npm ci --no-audit --no-fund && npm run build
	@# vite's emptyOutDir removes the placeholder that keeps //go:embed working
	@# in a fresh checkout, so put it back.
	@printf '# Placeholder so that //go:embed all:dist succeeds in a fresh checkout.\n# `make web` fills this directory with the built panel.\n' > $(EMBED_DIR)/.gitkeep

.PHONY: build
build: web ## Build the binary for the host platform
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) $(PKG)

.PHONY: build-go
build-go: ## Build the binary without rebuilding the panel
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) $(PKG)

.PHONY: snapshot
snapshot: web ## Cross-compile every release target locally
	goreleaser build --snapshot --clean

.PHONY: test
test: ## Run the Go test suite
	go test ./...

.PHONY: test-race
test-race: ## Run the tests with the race detector
	CGO_ENABLED=1 go test -race ./...

.PHONY: lint
lint: ## Vet the Go code and typecheck the panel
	go vet ./...
	@unformatted="$$(gofmt -l cmd internal)"; \
	if [ -n "$$unformatted" ]; then \
		echo "These files need gofmt:"; echo "$$unformatted"; exit 1; \
	fi
	cd $(WEB_DIR) && npm run typecheck

.PHONY: run
run: build-go ## Run against dev.yaml on unprivileged ports
	./$(BINARY) --config dev.yaml

.PHONY: dev-config
dev-config: ## Write a dev.yaml that needs no privileges
	@printf 'mode: dns-only\nlog:\n  level: debug\ndns:\n  listen: ["127.0.0.1:5353"]\nhttp:\n  listen: "127.0.0.1:8080"\nstore:\n  path: "./data/seddns.db"\n' > dev.yaml
	@echo "wrote dev.yaml (dns on 127.0.0.1:5353, panel on 127.0.0.1:8080)"

.PHONY: clean
clean: ## Remove build output
	rm -rf $(BINARY) $(DIST) $(WEB_DIR)/dist
	find $(EMBED_DIR) -mindepth 1 ! -name .gitkeep -delete
