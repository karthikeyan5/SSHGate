.PHONY: all build test test-integration vet clean velgate-linux

all: vet test build

build:
	mkdir -p bin
	go build -o bin/sshgate-mcp ./src/sshgate-mcp/cmd/sshgate-mcp
	go build -o bin/velsigner   ./src/velsigner/cmd/velsigner
	go build -o bin/velgate     ./src/velgate/cmd/velgate

# Cross-compile velgate for the remote host (linux/amd64). Static, stripped, reproducible-ish.
velgate-linux:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags='-s -w' \
		-o bin/velgate-linux-amd64 ./src/velgate/cmd/velgate

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
