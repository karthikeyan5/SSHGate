.PHONY: all build install-local test test-integration vet clean sshgate-gate-linux \
	sshgate-mcp-darwin sshgate-signer-telegram-darwin darwin cross sshgate-signer-server

all: vet test build

build: sshgate-signer-server sshgate-gate-linux
	mkdir -p bin
	go build -o bin/sshgate-mcp              ./src/mcp/cmd/sshgate-mcp
	go build -o bin/sshgate-signer-telegram  ./src/signer/cmd/sshgate-signer-telegram
	go build -o bin/sshgate-gate             ./src/gate/cmd/sshgate-gate

# sshgate-signer-server: v2 hosted approval daemon (scaffold). Built into
# bin/ alongside the v1 binaries so a single `make build` produces
# every component the operator might deploy. Production VPS installs
# normally use install/deploy.sh, which re-builds at the deploy path;
# this target is for laptop-side dev + cross-compile parity.
sshgate-signer-server:
	mkdir -p bin
	go build -o bin/sshgate-signer-server ./src/signer-server/cmd/sshgate-signer-server

# Cross-compile sshgate-gate for the remote host (linux/amd64). Static, stripped, reproducible-ish.
sshgate-gate-linux:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags='-s -w' \
		-o bin/sshgate-gate-linux-amd64 ./src/gate/cmd/sshgate-gate

# macOS desktop builds (v1.1 Task C — for users running Claude Code on a Mac).
# sshgate-signer-telegram + sshgate-mcp run on the user's laptop; sshgate-gate is Linux-only
# (it's deployed to remote Linux servers, so no darwin target for it).
# Both archs built: amd64 (Intel Macs) + arm64 (Apple Silicon).
sshgate-mcp-darwin:
	mkdir -p bin
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/sshgate-mcp-darwin-amd64 ./src/mcp/cmd/sshgate-mcp
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o bin/sshgate-mcp-darwin-arm64 ./src/mcp/cmd/sshgate-mcp

sshgate-signer-telegram-darwin:
	mkdir -p bin
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/sshgate-signer-telegram-darwin-amd64 ./src/signer/cmd/sshgate-signer-telegram
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o bin/sshgate-signer-telegram-darwin-arm64 ./src/signer/cmd/sshgate-signer-telegram

darwin: sshgate-mcp-darwin sshgate-signer-telegram-darwin
	@echo "darwin builds done; sshgate-gate remains linux-only (deployed to Linux remotes)"

# Full cross-build matrix: linux laptop binaries + linux remote sshgate-gate + darwin laptop binaries.
cross: build darwin

# install-local is the fresh-clone laptop install used by /sshgate:setup
# and INSTALL.md. It depends on `build`, so ONE `make install-local`
# produces everything the install needs:
#   - <clone>/bin/*  (sshgate-mcp, sshgate-signer-telegram, sshgate-gate,
#                     sshgate-gate-linux-amd64) for scripts/install.sh
#   - $PATH binaries in $(go env GOPATH)/bin via `go install`
#                     (.mcp.json now references the bare `sshgate-mcp`)
#   - sshgate-gate-linux-amd64 staged into the STABLE config location the
#     MCP's add_server resolver checks (~/.config/sshgate/bin/), decoupled
#     from the plugin cache that `/plugin install` cannot keep src/ in.
# Run from the user's clone (it has src/). Honors $XDG_CONFIG_HOME.
install-local: build
	go install ./src/mcp/cmd/sshgate-mcp
	go install ./src/signer/cmd/sshgate-signer-telegram
	mkdir -p "$${XDG_CONFIG_HOME:-$$HOME/.config}/sshgate/bin"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags='-s -w' \
		-o "$${XDG_CONFIG_HOME:-$$HOME/.config}/sshgate/bin/sshgate-gate-linux-amd64" \
		./src/gate/cmd/sshgate-gate
	@echo "install-local done:"
	@echo "  <clone>/bin/* (incl. sshgate-gate-linux-amd64) -> for scripts/install.sh"
	@echo "  sshgate-mcp, sshgate-signer-telegram -> $$(go env GOPATH)/bin (must be on PATH)"
	@echo "  sshgate-gate-linux-amd64 -> $${XDG_CONFIG_HOME:-$$HOME/.config}/sshgate/bin/"

test:
	go test -race ./...

# Phase-1 e2e against a real Docker SSH target. Skipped automatically
# if `docker compose` is unavailable. Excluded from `make test` so
# contributor machines without Docker still get a green per-package
# suite.
test-integration:
	go test -race -tags=integration ./tests/integration/... -timeout=180s -v

# `go vet ./...` errors with "matched no packages" while the module is empty
# (Phase 0). Guard with `go list` so vet is a no-op until source exists.
vet:
	@if [ -n "$$(go list ./... 2>/dev/null)" ]; then \
		go vet ./...; \
	else \
		echo "vet: no packages yet, skipping"; \
	fi

clean:
	rm -rf bin
