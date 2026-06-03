// Command sshgate-mcp is the SSHGate Claude Code MCP server. It is
// the binary that Claude Code spawns per session for SSH execution
// against registered servers.
//
// Configuration (all paths in $XDG_CONFIG_HOME/sshgate/, default
// ~/.config/sshgate/):
//
//	servers.json          — alias → host/port/user registry
//	ssh/sshgate_ed25519   — SSH client private key (mode 0o600)
//	known_hosts           — TOFU host-key store (mode 0o600)
//
// Environment overrides:
//
//	$XDG_CONFIG_HOME         — config root (default ~/.config)
//	$SSHGATE_SIGNER_SOCK  — signer socket (default /run/sshgatesigner/sock)
//
// Stdio: stdout is the JSON-RPC channel (do not log there). stderr
// is the operator log. stdin EOF is a clean shutdown signal.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

const (
	defaultSignerSock = "/run/sshgatesigner/sock"
	// signTimeout covers the signer-side approval window (60s for
	// Telegram in v2) plus a couple of seconds of socket slack.
	signTimeout = 75 * time.Second
	// sshTimeout bounds a single SSH dial+exec.
	sshTimeout = 30 * time.Second
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("sshgate-mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	showVersion := fs.Bool("version", false, "Print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(os.Stdout, "sshgate-mcp %s\n", mcp.Version)
		return 0
	}

	logger := log.New(os.Stderr, "sshgate-mcp: ", log.LstdFlags)

	cfgRoot, err := configRoot()
	if err != nil {
		logger.Printf("config root: %v", err)
		return 1
	}
	regPath := filepath.Join(cfgRoot, "servers.json")
	keyPath := filepath.Join(cfgRoot, "ssh", "sshgate_ed25519")
	khPath := filepath.Join(cfgRoot, "known_hosts")

	servers, err := registry.New(regPath)
	if err != nil {
		logger.Printf("registry: %v", err)
		return 1
	}

	// Fail-fast: refuse to start without the SSH key. Anything later
	// would either succeed and SSH would fail at first use, or fail
	// in a confusing way. Better to surface the missing-key state at
	// startup so the operator can run /sshgate:setup.
	if err := requireFile(keyPath, 0o600); err != nil {
		logger.Printf("ssh key: %v", err)
		return 1
	}

	// known_hosts is created on first contact, so we only require
	// that the file (if it exists) is mode 0600.
	if err := requireFileIfExists(khPath, 0o600); err != nil {
		logger.Printf("known_hosts: %v", err)
		return 1
	}

	socketPath := os.Getenv("SSHGATE_SIGNER_SOCK")
	if socketPath == "" {
		socketPath = defaultSignerSock
	}

	signer := &signpkg.Client{SocketPath: socketPath, Timeout: signTimeout}
	sshClient := &sshpkg.Client{KeyPath: keyPath, KnownHostsPath: khPath, Timeout: sshTimeout}
	runner := &tools.Runner{
		Servers:        servers,
		Sign:           signer,
		SSH:            sshClient,
		SignerSockPath: socketPath,
	}

	server := &mcp.Server{Runner: runner, Logger: logger}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Printf("ready (registry=%s key=%s signer=%s)", regPath, keyPath, socketPath)
	if err := server.Serve(ctx, os.Stdin, os.Stdout); err != nil {
		logger.Printf("serve: %v", err)
		return 1
	}
	logger.Printf("shutdown")
	return 0
}

// configRoot returns the sshgate config root, honouring
// $XDG_CONFIG_HOME (default ~/.config). Returns an error if $HOME is
// unset and $XDG_CONFIG_HOME is empty.
func configRoot() (string, error) {
	if root := os.Getenv("XDG_CONFIG_HOME"); root != "" {
		return filepath.Join(root, "sshgate"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "sshgate"), nil
}

// requireFile fails if path does not exist or its permission bits are
// looser than maxPerm (i.e. it carries any bit set in ~maxPerm &
// 0o777).
func requireFile(path string, maxPerm os.FileMode) error {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("required file %s does not exist", path)
	}
	if err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm&^maxPerm != 0 {
		return fmt.Errorf("file %s has insecure mode %#o (must be at most %#o)", path, perm, maxPerm)
	}
	return nil
}

// requireFileIfExists is requireFile but tolerates a missing file.
func requireFileIfExists(path string, maxPerm os.FileMode) error {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return requireFile(path, maxPerm)
}
