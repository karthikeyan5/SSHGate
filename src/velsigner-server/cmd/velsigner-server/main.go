// Command velsigner-server is the hosted v2 signing service. It serves
// the HTTPS API described in docs/specs/2026-05-19-sshgate-design.md
// §"v2 vision → Wire protocol": SSHGate plugins on any machine submit
// a sign request, a human approves it (v2.1+ adds WebAuthn/TOTP UI),
// and the server returns signed payloads compatible with velgate.
//
// Flags:
//
//	--config <path>          TOML config (default: /etc/velsigner-server/config.toml
//	                          or $VELSIGNER_SERVER_CONFIG)
//	--api-key-file <path>    Single bearer-token file (0600). v2.0 only;
//	                          v2.1 replaces with per-client keys + WebAuthn.
//	--addr <host:port>       Listen address (default: :8443). TLS is
//	                          terminated upstream (Caddy/nginx) in v2.0.
//	--db <path>              SQLite database path (default:
//	                          /var/lib/velsigner-server/state.db)
//	--version                Print version and exit
//
// On startup:
//
//  1. Refuse to run as root (same reflex as velsigner — a daemon that
//     holds signing capability should never be the kernel).
//  2. Load the API key from --api-key-file (single-token bearer auth
//     for v2.0). Empty file = fatal.
//  3. Open the SQLite store (scaffold commit 2 wires this in; commit 1
//     leaves the field nil and handlers fall through to placeholders).
//  4. Build the http.Server and listen.
//  5. Shut down cleanly on SIGTERM/SIGINT (5s drain window).
//
// v2.0 does NOT terminate TLS itself: that's the reverse proxy's job
// (Caddy or nginx in the deploy script). The server binds plain HTTP
// on a private interface; the proxy handles the public 443.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	velsignerserver "github.com/karthikeyan5/sshgate/src/velsigner-server"
)

const version = "0.2.0-scaffold-1"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("velsigner-server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	apiKeyFile := fs.String("api-key-file", "", "Path to a 0600 file containing the bearer API key")
	addr := fs.String("addr", ":8443", "Listen address (host:port). Default :8443; TLS terminated upstream.")
	_ = fs.String("db", "/var/lib/velsigner-server/state.db", "SQLite database path (wired in scaffold commit 2)")
	_ = fs.String("config", defaultConfigPath(), "TOML config file (reserved for v2.1)")
	showVersion := fs.Bool("version", false, "Print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(os.Stdout, "velsigner-server %s\n", version)
		return 0
	}

	if err := assertNonRoot(); err != nil {
		logf("%v", err)
		return 1
	}

	if *apiKeyFile == "" {
		logf("--api-key-file is required (see --help)")
		return 1
	}
	apiKey, err := loadAPIKey(*apiKeyFile)
	if err != nil {
		logf("load api key: %v", err)
		return 1
	}

	logger := log.New(os.Stderr, "velsigner-server: ", log.LstdFlags|log.Lmicroseconds)
	// Store is nil in scaffold commit 1 — handlers return placeholders.
	// Commit 2 wires this to a sqlite-backed implementation.
	srv := velsignerserver.NewServer(apiKey, nil, logger)

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		// Long-poll handlers can hold the connection up to ~60s;
		// budget a comfortable WriteTimeout above that. v2.1 should
		// move to per-route timeouts.
		ReadTimeout:  90 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("listening on %s (version=%s)", *addr, version)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		logger.Printf("signal received, shutting down")
	case err := <-errCh:
		if err != nil {
			logf("listen: %v", err)
			return 1
		}
		return 0
	}

	// Graceful shutdown: stop accepting new connections, drain
	// in-flight requests up to 5s, then force-close.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logf("shutdown: %v", err)
		return 1
	}
	logger.Printf("stopped")
	return 0
}

// loadAPIKey reads path, trims surrounding whitespace, and returns the
// key. An empty file is treated as a fatal misconfiguration: the
// daemon refuses to start with an empty bearer token rather than
// accept all-token-mismatches as a feature.
func loadAPIKey(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	key := strings.TrimSpace(string(bytes.TrimSpace(raw)))
	if key == "" {
		return "", fmt.Errorf("api key file %s is empty", path)
	}
	return key, nil
}

// defaultConfigPath returns the env-overridden default config path.
// v2.0 doesn't actually parse a config file (all options are flags);
// the path is reserved for v2.1 when [auth], [tls], and [store]
// blocks land.
func defaultConfigPath() string {
	if p := os.Getenv("VELSIGNER_SERVER_CONFIG"); p != "" {
		return p
	}
	return "/etc/velsigner-server/config.toml"
}

// assertNonRoot mirrors velsigner's check. A daemon that owns
// signing capability should never run as UID 0.
func assertNonRoot() error {
	if os.Geteuid() == 0 {
		return errors.New("velsigner-server refuses to run as root; create a dedicated user (see install/deploy.sh)")
	}
	return nil
}

// logf writes one line to stderr with the daemon prefix. Mirrors the
// pattern used by the v1 velsigner main.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "velsigner-server: "+format+"\n", args...)
}
