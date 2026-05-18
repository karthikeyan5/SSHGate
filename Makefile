.PHONY: all build test test-integration vet clean velgate-linux \
	sshgate-mcp-darwin velsigner-darwin darwin cross velsigner-server

all: vet test build

build: velsigner-server
	mkdir -p bin
	go build -o bin/sshgate-mcp ./src/mcp/cmd/sshgate-mcp
	go build -o bin/velsigner   ./src/velsigner/cmd/velsigner
	go build -o bin/velgate     ./src/velgate/cmd/velgate

# velsigner-server: v2 hosted approval daemon (scaffold). Built into
# bin/ alongside the v1 binaries so a single `make build` produces
# every component the operator might deploy. Production VPS installs
# normally use install/deploy.sh, which re-builds at the deploy path;
# this target is for laptop-side dev + cross-compile parity.
velsigner-server:
	mkdir -p bin
	go build -o bin/velsigner-server ./src/velsigner-server/cmd/velsigner-server

# Cross-compile velgate for the remote host (linux/amd64). Static, stripped, reproducible-ish.
velgate-linux:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags='-s -w' \
		-o bin/velgate-linux-amd64 ./src/velgate/cmd/velgate

# macOS desktop builds (v1.1 Task C — for users running Claude Code on a Mac).
# velsigner + sshgate-mcp run on the user's laptop; velgate is Linux-only
# (it's deployed to remote Linux servers, so no darwin target for it).
# Both archs built: amd64 (Intel Macs) + arm64 (Apple Silicon).
sshgate-mcp-darwin:
	mkdir -p bin
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/sshgate-mcp-darwin-amd64 ./src/mcp/cmd/sshgate-mcp
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o bin/sshgate-mcp-darwin-arm64 ./src/mcp/cmd/sshgate-mcp

velsigner-darwin:
	mkdir -p bin
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/velsigner-darwin-amd64 ./src/velsigner/cmd/velsigner
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o bin/velsigner-darwin-arm64 ./src/velsigner/cmd/velsigner

darwin: sshgate-mcp-darwin velsigner-darwin
	@echo "darwin builds done; velgate remains linux-only (deployed to Linux remotes)"

# Full cross-build matrix: linux laptop binaries + linux remote velgate + darwin laptop binaries.
cross: build velgate-linux darwin

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
