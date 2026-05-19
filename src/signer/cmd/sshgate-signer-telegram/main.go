// Command signer is the local approval daemon for SSHGate. It runs
// as a dedicated OS user (`signer`) on Karthi's laptop, owns the
// master Ed25519 signing key, and signs commands only after the
// configured Backend returns Approved.
//
// Flags:
//
//	--config <path>   TOML config (default: /etc/signer/config.toml or
//	                  $VELSIGNER_CONFIG)
//	--init            Generate keypair + skeleton config + state dirs, exit
//	--dev             Only meaningful with --init: anchor generated paths
//	                  under $XDG_RUNTIME_DIR. No-op at runtime.
//	--version         Print version and exit
//
// On startup the daemon:
//
//  1. Fails fast if running as root (writing-to-a-master-key-file as
//     root is exactly the install-time mistake we want to catch).
//  2. Acquires an flock on <sock_dir>/sock.lock (daemon.md §3.1). A
//     second start refuses immediately.
//  3. Loads the private key via signer.LoadKey (mode 0o077 check).
//  4. Opens the audit log in append mode.
//  5. Builds the configured backend (currently only "stub"; "telegram"
//     is recognised as a config value but returns "not yet implemented
//     in v1.4 — landing in 2.1").
//  6. Runs the Unix-socket server until SIGTERM/SIGINT.
//
// SIGHUP is logged as "not supported in v1; restart to apply changes"
// per daemon.md §8.2; partial reloads are explicitly disallowed.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/karthikeyan5/sshgate/src/signer"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

const version = "0.1.4"

type tomlConfig struct {
	Paths struct {
		Key      string `toml:"key"`
		PubKey   string `toml:"pubkey"`
		AuditLog string `toml:"audit_log"`
		Socket   string `toml:"socket"`
	} `toml:"paths"`
	Backend struct {
		Type     string         `toml:"type"`
		Telegram telegramConfig `toml:"telegram"`
		Hosted   hostedConfig   `toml:"hosted"`
	} `toml:"backend"`
}

// hostedConfig is the [backend.hosted] block, consulted only when
// backend.type = "hosted". The v2 swap-point: setting this in
// /etc/signer/config.toml redirects approval traffic from the
// local Telegram bot to the centralized signer-server.
type hostedConfig struct {
	// BaseURL is the signer-server origin (no trailing slash),
	// e.g. https://signer-server.example.com.
	BaseURL string `toml:"base_url"`
	// APIKeyFile is the path to a 0600 file containing the
	// bearer token. Mirrors backend.telegram.token_path's "file,
	// not inline" rule (daemon.md §6).
	APIKeyFile string `toml:"api_key_file"`
	// ClientID identifies this laptop in the server's audit log.
	ClientID string `toml:"client_id"`
	// PollWaitSec bounds each /v1/poll long-poll. Default 30.
	PollWaitSec int `toml:"poll_wait_sec"`
	// TimeoutSec bounds the total per-Request budget. Default 60.
	TimeoutSec int `toml:"timeout_sec"`
}

// telegramConfig is the [backend.telegram] block. Only consulted when
// backend.type = "telegram"; an empty block is fine for stub.
type telegramConfig struct {
	// TokenPath points at a 0600 file whose entire content is the
	// @BotFather-issued bot token (no quotes, no surrounding whitespace).
	TokenPath string `toml:"token_path"`
	// AllowedUserID is the only Telegram user_id whose callbacks the
	// daemon will honour (spec §"signer-bot").
	AllowedUserID int64 `toml:"allowed_user_id"`
	// ChatStorePath is the JSON file capturing the DM chat_id learned
	// from the allowed user's first /start.
	ChatStorePath string `toml:"chatstore_path"`
	// Explainer is the optional LLM-explainer block. When Enabled is
	// false (or this block is absent in the TOML), no explainer is
	// wired up and v1 rendering applies.
	Explainer explainerConfig `toml:"explainer"`
}

// explainerConfig is the [backend.telegram.explainer] block. v1.1 Task D.
type explainerConfig struct {
	Enabled    bool   `toml:"enabled"`
	Endpoint   string `toml:"endpoint"`
	Model      string `toml:"model"`
	APIKeyPath string `toml:"api_key_path"`
	TimeoutSec int    `toml:"timeout_sec"`
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("signer", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath(), "TOML config file")
	doInit := fs.Bool("init", false, "Generate keypair + skeleton config + state dirs, then exit")
	dev := fs.Bool("dev", false, "Dev mode: only meaningful with --init (anchors generated paths under $XDG_RUNTIME_DIR); ignored at runtime")
	showVersion := fs.Bool("version", false, "Print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintf(os.Stdout, "signer %s\n", version)
		return 0
	}

	if *doInit {
		if err := doInitFlow(*configPath, *dev); err != nil {
			logf("init: %v", err)
			return 1
		}
		return 0
	}

	if err := assertNonRoot(); err != nil {
		logf("%v", err)
		return 1
	}
	// Note: assertion that we're running as the `signer` user
	// (production) vs any user (--dev) is omitted from v1.4. The
	// install script creates the signer user and the systemd unit
	// runs under `User=signer`; that's the load-bearing layer. If
	// the operator runs the binary as some other non-root user, the
	// 0o077 mask check on the key file will catch them.
	//
	// --dev is therefore a no-op on the runtime path; it only affects
	// --init (path anchoring under $XDG_RUNTIME_DIR). The flag is kept
	// declared at the top so `signer --dev --init` parses cleanly;
	// the help string for --dev says so explicitly.
	_ = dev

	cfg, err := loadConfig(*configPath)
	if err != nil {
		logf("load config: %v", err)
		return 1
	}

	// Singleton: flock <sock_dir>/sock.lock. The lockfile lives next
	// to the socket because that's the directory the operator can
	// inspect to "see what's holding the daemon."
	lockPath := cfg.Paths.Socket + ".lock"
	release, err := flockOrFail(lockPath)
	if err != nil {
		logf("%v", err)
		return 1
	}
	defer release()

	priv, err := signer.LoadKey(cfg.Paths.Key)
	if err != nil {
		logf("load key: %v", err)
		return 1
	}

	audit, err := signer.OpenAuditLog(cfg.Paths.AuditLog)
	if err != nil {
		logf("open audit log: %v", err)
		return 1
	}
	defer audit.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	bk, err := buildBackend(ctx, cfg.Backend)
	if err != nil {
		logf("build backend: %v", err)
		return 1
	}

	daemon := &signer.Daemon{
		Key:     priv,
		Backend: bk,
		Audit:   audit,
	}
	srv := &signer.Server{Path: cfg.Paths.Socket, Handler: daemon}

	// SIGHUP: log "restart to apply changes" and continue.
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	hupDone := make(chan struct{})
	go func() {
		defer close(hupDone)
		for {
			select {
			case <-hupCh:
				logf("SIGHUP received; config reload not supported in v1 — restart to apply changes")
			case <-ctx.Done():
				signal.Stop(hupCh)
				return
			}
		}
	}()

	logf("ready (socket=%s backend=%s)", cfg.Paths.Socket, cfg.Backend.Type)
	listenErr := srv.Listen(ctx)
	logf("shutting down")
	stop()
	<-hupDone
	if listenErr != nil {
		logf("listen returned: %v", listenErr)
	}
	logf("stopped")
	return 0
}

// loadConfig reads the TOML file at path and returns its parsed shape.
// Empty paths in the config are tolerated only when produced by --init;
// the production daemon refuses to start with empty path fields.
func loadConfig(path string) (tomlConfig, error) {
	var cfg tomlConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("decode %s: %w", path, err)
	}
	if cfg.Paths.Key == "" {
		return cfg, errors.New("config missing paths.key")
	}
	if cfg.Paths.AuditLog == "" {
		return cfg, errors.New("config missing paths.audit_log")
	}
	if cfg.Paths.Socket == "" {
		return cfg, errors.New("config missing paths.socket")
	}
	if cfg.Backend.Type == "" {
		return cfg, errors.New("config missing backend.type")
	}
	return cfg, nil
}

// buildBackend returns the Backend implementation for the configured
// type. "telegram" loads the bot token from the configured token file,
// validates it via getMe, then starts the polling loop. ctx scopes the
// polling goroutine — when ctx is cancelled (SIGTERM), polling exits.
func buildBackend(ctx context.Context, bcfg struct {
	Type     string         `toml:"type"`
	Telegram telegramConfig `toml:"telegram"`
	Hosted   hostedConfig   `toml:"hosted"`
}) (backend.Backend, error) {
	switch bcfg.Type {
	case "stub":
		return backend.StubBackend{}, nil
	case "telegram":
		return buildTelegramBackend(ctx, bcfg.Telegram)
	case "hosted":
		return buildHostedBackend(bcfg.Hosted)
	default:
		return nil, fmt.Errorf("unknown backend type %q", bcfg.Type)
	}
}

// buildHostedBackend reads the bearer token file and constructs the
// HostedServerBackend. It does NOT probe the server with a /healthz
// call: a misconfigured base_url surfaces on the first sign request
// rather than blocking daemon startup (the daemon still serves
// "error" responses to the MCP, which surfaces the operator's
// misconfiguration without preventing other v1 backends from
// continuing to work after a swap-back).
func buildHostedBackend(c hostedConfig) (backend.Backend, error) {
	if c.BaseURL == "" {
		return nil, errors.New(`config missing backend.hosted.base_url`)
	}
	if c.APIKeyFile == "" {
		return nil, errors.New(`config missing backend.hosted.api_key_file`)
	}
	if c.ClientID == "" {
		return nil, errors.New(`config missing backend.hosted.client_id`)
	}
	keyRaw, err := os.ReadFile(c.APIKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read hosted api key %s: %w", c.APIKeyFile, err)
	}
	key := string(bytes.TrimSpace(keyRaw))
	if key == "" {
		return nil, fmt.Errorf("hosted api key file %s is empty", c.APIKeyFile)
	}
	pollWait := time.Duration(c.PollWaitSec) * time.Second
	if pollWait == 0 {
		pollWait = 30 * time.Second
	}
	timeout := time.Duration(c.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	logf("hosted backend ready (base_url=%s client_id=%s poll_wait=%s timeout=%s)",
		c.BaseURL, c.ClientID, pollWait, timeout)
	return &backend.HostedServerBackend{
		BaseURL:    c.BaseURL,
		APIKey:     key,
		ClientID:   c.ClientID,
		HTTPClient: &http.Client{Timeout: timeout + 10*time.Second},
		PollWait:   pollWait,
		Timeout:    timeout,
	}, nil
}

// buildTelegramBackend reads the bot token, constructs the backend
// (which calls getMe internally — daemon.md §11 "fail fast at the
// boundary"), and starts the polling goroutine before returning.
func buildTelegramBackend(ctx context.Context, c telegramConfig) (backend.Backend, error) {
	if c.TokenPath == "" {
		return nil, errors.New(`config missing backend.telegram.token_path`)
	}
	if c.AllowedUserID == 0 {
		return nil, errors.New(`config missing backend.telegram.allowed_user_id`)
	}
	if c.ChatStorePath == "" {
		return nil, errors.New(`config missing backend.telegram.chatstore_path`)
	}

	tokenRaw, err := os.ReadFile(c.TokenPath)
	if err != nil {
		return nil, fmt.Errorf("read token: %w", err)
	}
	token := string(bytes.TrimSpace(tokenRaw))
	if token == "" {
		return nil, fmt.Errorf("token file %s is empty", c.TokenPath)
	}

	tb, err := backend.NewTelegramBackend(backend.TelegramOptions{
		BotToken:      token,
		AllowedUserID: c.AllowedUserID,
		ChatStore:     &backend.FileChatStore{Path: c.ChatStorePath},
	})
	if err != nil {
		return nil, fmt.Errorf("new telegram backend: %w", err)
	}

	// Optional: wire up the LLM command explainer (v1.1 Task D). The
	// daemon refuses to start if [backend.telegram.explainer] enabled =
	// true but the configured key file is missing — silent fallback is
	// worse than fail-fast for a misconfigured operator.
	if c.Explainer.Enabled {
		ex, err := buildExplainer(c.Explainer)
		if err != nil {
			return nil, fmt.Errorf("build explainer: %w", err)
		}
		tb.Explainer = ex
		if c.Explainer.TimeoutSec > 0 {
			tb.ExplainerTimeout = time.Duration(c.Explainer.TimeoutSec) * time.Second
		}
		logf("telegram explainer enabled (model=%s endpoint=%s timeout=%s)",
			c.Explainer.Model, c.Explainer.Endpoint, tb.ExplainerTimeout)
	}

	if err := tb.Run(ctx); err != nil {
		return nil, fmt.Errorf("start telegram polling: %w", err)
	}
	logf("telegram backend ready (allowed_user_id=%d chatstore=%s)", c.AllowedUserID, c.ChatStorePath)
	return tb, nil
}

// buildExplainer validates the explainer config block and returns a
// configured OpenAICompatibleExplainer. Errors are wrapped with
// per-field context so a misconfiguration message points the operator
// at the exact TOML key.
func buildExplainer(c explainerConfig) (backend.Explainer, error) {
	if c.Endpoint == "" {
		return nil, errors.New("config missing backend.telegram.explainer.endpoint")
	}
	if c.Model == "" {
		return nil, errors.New("config missing backend.telegram.explainer.model")
	}
	if c.APIKeyPath == "" {
		return nil, errors.New("config missing backend.telegram.explainer.api_key_path")
	}
	keyRaw, err := os.ReadFile(c.APIKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read explainer api key %s: %w", c.APIKeyPath, err)
	}
	key := string(bytes.TrimSpace(keyRaw))
	if key == "" {
		return nil, fmt.Errorf("explainer api key file %s is empty", c.APIKeyPath)
	}
	timeout := 5 * time.Second
	if c.TimeoutSec > 0 {
		timeout = time.Duration(c.TimeoutSec) * time.Second
	}
	return &backend.OpenAICompatibleExplainer{
		Endpoint:   c.Endpoint,
		Model:      c.Model,
		APIKey:     key,
		HTTPClient: &http.Client{Timeout: timeout},
		Timeout:    timeout,
	}, nil
}

// defaultConfigPath returns the value of $VELSIGNER_CONFIG if set,
// otherwise /etc/signer/config.toml.
func defaultConfigPath() string {
	if p := os.Getenv("VELSIGNER_CONFIG"); p != "" {
		return p
	}
	return "/etc/signer/config.toml"
}

// assertNonRoot returns an error if the process is running as UID 0.
// Daemons that hold a master signing key should NEVER run as root — a
// compromised daemon then has the kernel.
func assertNonRoot() error {
	if os.Geteuid() == 0 {
		return errors.New("signer refuses to run as root; create a dedicated user (run scripts/install.sh)")
	}
	return nil
}

// flockOrFail acquires an exclusive non-blocking flock on lockPath and
// returns a function that releases it. If the lock is held by another
// live process, flockOrFail returns an error rather than blocking.
func flockOrFail(lockPath string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir lock dir: %w", err)
	}
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o660)
	if err != nil {
		return nil, fmt.Errorf("open lockfile: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another signer instance is running (lock held on %s)", lockPath)
		}
		return nil, fmt.Errorf("flock %s: %w", lockPath, err)
	}
	// Stamp the PID so an operator running `cat sock.lock` sees what
	// holds the lock.
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
		// We don't remove the lockfile: a stale empty file is fine,
		// and removal races with the next start trying to open it.
	}, nil
}

// doInitFlow generates a fresh keypair, creates the state directories,
// and writes a skeleton TOML config at configPath. The flow is
// idempotent only in the sense of "second run fails clearly" — it
// refuses to overwrite existing keys (so an accidental --init does not
// silently rotate the master key).
//
// In --dev mode, paths are rooted under $XDG_RUNTIME_DIR/signer-<pid>
// so the operator can run the daemon entirely in userspace; --config is
// resolved relative to that root if it does not look absolute.
func doInitFlow(configPath string, dev bool) error {
	var root, keyPath, pubPath, auditPath, sockPath string
	if dev {
		runtime := os.Getenv("XDG_RUNTIME_DIR")
		if runtime == "" {
			runtime = filepath.Join(os.TempDir(), "signer-dev")
		}
		// Anchor everything under one dir for easy cleanup. Use the
		// config path's parent if the operator provided one in a
		// non-default location.
		if configPath != "" && filepath.IsAbs(configPath) {
			root = filepath.Dir(configPath)
		} else {
			root = filepath.Join(runtime, "signer-"+strconv.Itoa(os.Getpid()))
		}
		keyPath = filepath.Join(root, "gate.key")
		pubPath = filepath.Join(root, "gate.pub")
		auditPath = filepath.Join(root, "approvals.log")
		sockPath = filepath.Join(root, "sock")
	} else {
		root = "/var/lib/signer"
		keyPath = filepath.Join(root, "keys", "gate.key")
		pubPath = filepath.Join(root, "keys", "gate.pub")
		auditPath = filepath.Join(root, "log", "approvals.log")
		sockPath = "/run/signer/sock"
	}

	// Make the directories the daemon will need.
	dirs := []string{
		filepath.Dir(keyPath),
		filepath.Dir(auditPath),
		filepath.Dir(sockPath),
		filepath.Dir(configPath),
	}
	for _, d := range dirs {
		if d == "" || d == "." {
			continue
		}
		if err := os.MkdirAll(d, 0o750); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	if err := signer.GenerateKeyPair(keyPath, pubPath); err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	// Write a skeleton config. Refuse to overwrite — the operator
	// might have hand-customised an existing config.
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing config %s", configPath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat config: %w", err)
	}

	body := fmt.Sprintf(`# signer v1.4 configuration

[paths]
key       = %q
pubkey    = %q
audit_log = %q
socket    = %q

[backend]
# "stub" denies every request; used by the phase-1 e2e test that proves
# the cryptographic loop without a human in the loop. Switch to
# "telegram" once task 2.1 lands.
type = "stub"
`, keyPath, pubPath, auditPath, sockPath)

	if err := os.WriteFile(configPath, []byte(body), 0o640); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	logf("init: keys at %s, %s", keyPath, pubPath)
	logf("init: audit log at %s", auditPath)
	logf("init: socket at %s", sockPath)
	logf("init: config at %s", configPath)
	return nil
}

// logf writes one line to stderr with the "signer: " prefix. Errors
// from the write are intentionally ignored — there is no recovery for
// "could not write to stderr."
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "signer: "+format+"\n", args...)
}
