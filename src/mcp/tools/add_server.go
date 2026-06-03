package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

// AddServerInput is the JSON input to sshgate.add_server.
//
// Exactly one of BootstrapKeyPath / BootstrapAgent must be set. The
// bootstrap leg uses the operator's existing SSH access to lay down
// gate; subsequent connections use the SSHGate dedicated key (with
// command="..." forcing).
type AddServerInput struct {
	Alias string `json:"alias" jsonschema:"new alias to register; [a-z][a-z0-9-]{0,30}"`
	Host  string `json:"host" jsonschema:"remote hostname or IP"`
	Port  int    `json:"port,omitempty" jsonschema:"remote SSH port (default 22)"`
	User  string `json:"user" jsonschema:"remote SSH username"`
	// BootstrapKeyPath is the absolute path to a private key the
	// operator already uses to reach Host (e.g. ~/.ssh/id_ed25519).
	BootstrapKeyPath string `json:"bootstrap_key_path,omitempty" jsonschema:"absolute path to an existing private key for the FIRST SSH dial (e.g. ~/.ssh/id_ed25519); refuses files with mode looser than 0600"`
	// BootstrapAgent (mutually exclusive with BootstrapKeyPath) routes
	// the bootstrap dial through ssh-agent via $SSH_AUTH_SOCK.
	BootstrapAgent bool `json:"bootstrap_agent,omitempty" jsonschema:"use ssh-agent ($SSH_AUTH_SOCK) for the FIRST SSH dial"`
	// ReadOnly deploys gate without uploading gate.pub. The
	// remote runs in read-only mode (reads exec, writes deny locally
	// at the gate). This is the tier-1 install path: no signer, no
	// Telegram, no master key — useful when the operator wants to try
	// the gate before committing to a signer setup. Run
	// /sshgate:setup later to add a signer + push gate.pub via
	// UpgradeServerToSigning.
	ReadOnly bool `json:"read_only,omitempty" jsonschema:"deploy gate WITHOUT uploading gate.pub; remote runs in read-only mode (writes denied at the gate). Tier-1 install path"`
}

// AddServerOutput summarises a successful add. Fingerprint is the
// SHA256 of the remote SSH host key as captured during the bootstrap
// dial — operators verify out-of-band that this matches the host they
// intended to register.
type AddServerOutput struct {
	Alias       string `json:"alias"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	User        string `json:"user"`
	Fingerprint string `json:"fingerprint"`
	BinaryPath  string `json:"binary_path"`
	VerifiedOK  bool   `json:"verified_ok"`
	// Idempotent is true when a pre-existing restricted entry was
	// detected and the rewrite was skipped (we only verified + registered).
	Idempotent bool `json:"idempotent,omitempty"`
	// ReadOnlyMode echoes AddServerInput.ReadOnly. When true, the
	// remote has gate deployed but NO gate.pub — writes will be
	// denied at the gate until UpgradeServerToSigning is run.
	ReadOnlyMode bool `json:"read_only_mode,omitempty"`
}

// addServerCfg gathers the host-side paths/env knobs that the runner
// consults when running AddServer. Defaults are populated when fields
// are zero; tests inject overrides directly.
type addServerCfg struct {
	// GateBinaryPath is the local path to the cross-compiled gate
	// binary (sshgate-gate-linux-amd64). Default: resolved by
	// defaultGateBinaryPath — $SSHGATE_GATE_BIN, then
	// <configRoot>/bin/, then os.Executable-relative, then
	// $CLAUDE_PLUGIN_ROOT/bin/.
	GateBinaryPath string
	// GatePubPath is the local path to the gate signing pubkey.
	// Default: <configRoot>/pubkey-distrib/gate.pub.
	GatePubPath string
	// SSHGatePubPath is the local path to the SSHGate dedicated SSH
	// pubkey. Default: <configRoot>/ssh/sshgate_ed25519.pub.
	SSHGatePubPath string
	// RemoteHome is the directory on the remote where ~/.sshgate-gate/ lives.
	// Default: "~" (left as a shell tilde — the remote shell expands it).
	RemoteHome string
}

// AddServerConfig overrides AddServer's defaults. Set fields are used
// verbatim; zero fields fall back to the documented defaults. Wired
// through Runner.AddServerCfg (intended for tests).
type AddServerConfig = addServerCfg

// remoteGateDir is the canonical install location on the remote.
const remoteGateDir = "~/.sshgate-gate"
const remoteGateBin = "~/.sshgate-gate/gate"
const remoteGatePub = "~/.sshgate-gate/gate.pub"
const remoteAuthKeys = "~/.ssh/authorized_keys"
const remoteAuthKeysBackup = "~/.ssh/authorized_keys.sshgate-backup"

// aliasPattern is the allowed alias shape: lowercase ASCII start,
// lowercase / digit / hyphen continuation, 1-31 chars total.
var aliasPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// hostnamePattern matches a DNS hostname per RFC 1123 (one or more
// labels separated by dots; each label starts and ends with
// alphanumeric, may contain hyphens in between; case-insensitive).
// We additionally accept IPv4 dotted-quad and bracket-stripped IPv6
// via parseHostLiteral below.
var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// usernamePattern matches a POSIX-style username: starts with lowercase
// letter or underscore, followed by up to 31 lowercase letters / digits
// / underscores / hyphens (32 char max — `useradd` upstream cap).
var usernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// validateHost rejects Host strings that are neither a DNS hostname
// nor a bare IPv4/IPv6 literal. The check is case-insensitive on the
// hostname path; net.ParseIP handles both v4 and v6 forms (callers
// pass IPv6 literals without brackets — net.JoinHostPort re-brackets
// at dial time).
func validateHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("host is empty")
	}
	if len(host) > 253 {
		return fmt.Errorf("host %q exceeds 253 chars", host)
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if !hostnamePattern.MatchString(strings.ToLower(host)) {
		return fmt.Errorf("host %q is not a valid hostname or IP literal", host)
	}
	return nil
}

// validateUser rejects User strings that don't look like POSIX
// usernames. Unicode, embedded whitespace, and shell metacharacters
// are rejected at this boundary so they never reach the audit log
// or an SSH ClientConfig.
func validateUser(user string) error {
	user = strings.TrimSpace(user)
	if user == "" {
		return errors.New("user is empty")
	}
	if !usernamePattern.MatchString(user) {
		return fmt.Errorf("user %q is not a valid POSIX username (regex %s)", user, usernamePattern)
	}
	return nil
}

// bootstrapDialTimeout bounds the bootstrap-leg dial + handshake.
const bootstrapDialTimeout = 20 * time.Second

// AddServer registers a new server alias and installs gate on it
// using the bootstrap credentials supplied in in. The flow is:
//
//  1. Validate inputs (alias regex, exactly one bootstrap method,
//     not-already-registered).
//  2. Dial the remote with the bootstrap credentials (using the
//     SAME TOFU known_hosts as r.SSH so the host key pins on first
//     contact).
//  3. Upload gate + gate.pub under ~/.sshgate-gate/.
//  4. Back up authorized_keys and rewrite it to gate the SSHGate
//     dedicated key behind a command= forcing.
//  5. Verify by reconnecting via r.SSH (empty SSH_ORIGINAL_COMMAND
//     → "SSHGATE_OK").
//  6. Register the alias in the registry.
//
// Steps 3-5 are wrapped in a rollback: any failure restores
// authorized_keys from the backup and removes ~/.sshgate-gate/. The
// registry is never touched on failure.
//
// Idempotent: if the alias is new but authorized_keys already has the
// canonical restricted entry for our pubkey, steps 3-5 reduce to
// "verify + register" (Output.Idempotent=true).
func (r *Runner) AddServer(ctx context.Context, in AddServerInput) (AddServerOutput, error) {
	if r.Servers == nil {
		return AddServerOutput{}, errors.New("tools: Servers is nil")
	}
	if r.SSH == nil {
		return AddServerOutput{}, errors.New("tools: SSH is nil")
	}
	if !aliasPattern.MatchString(in.Alias) {
		return AddServerOutput{}, fmt.Errorf("tools: invalid alias %q (must match %s)", in.Alias, aliasPattern)
	}
	if err := validateHost(in.Host); err != nil {
		return AddServerOutput{}, fmt.Errorf("tools: %w", err)
	}
	if err := validateUser(in.User); err != nil {
		return AddServerOutput{}, fmt.Errorf("tools: %w", err)
	}
	port := in.Port
	if port == 0 {
		port = 22
	}
	if _, exists := r.Servers.Get(in.Alias); exists {
		return AddServerOutput{}, fmt.Errorf("tools: alias %q already registered; use sshgate.remove_server first", in.Alias)
	}
	if in.BootstrapAgent == (in.BootstrapKeyPath != "") {
		return AddServerOutput{}, errors.New("tools: must specify exactly one of bootstrap_key_path or bootstrap_agent=true")
	}

	cfg, err := r.resolveAddServerCfg()
	if err != nil {
		return AddServerOutput{}, err
	}

	// Read local materials first so we fail fast before touching the
	// remote.
	gateBin, err := readLocalFile(cfg.GateBinaryPath, "gate binary",
		"run /sshgate:setup (or `make install-local`) to build sshgate-gate-linux-amd64 into ~/.config/sshgate/bin/")
	if err != nil {
		return AddServerOutput{}, err
	}
	// Tier-1 (read-only) skips the signing pubkey entirely — the
	// operator hasn't set up signer yet, so the file may not even
	// exist on disk. Tier-2 reads it and pushes it to the remote.
	var gatePubBytes []byte
	if !in.ReadOnly {
		gatePubBytes, err = readLocalFile(cfg.GatePubPath, "gate signing public key",
			"ensure /sshgate:setup tier-2 has been run (or pass read_only=true for tier-1)")
		if err != nil {
			return AddServerOutput{}, err
		}
	}
	sshgatePubBytes, err := readLocalFile(cfg.SSHGatePubPath, "SSHGate dedicated SSH public key",
		"ensure /sshgate:setup has been run")
	if err != nil {
		return AddServerOutput{}, err
	}
	sshgatePub, _, _, _, err := ssh.ParseAuthorizedKey(sshgatePubBytes)
	if err != nil {
		return AddServerOutput{}, fmt.Errorf("tools: parse %s: %w", cfg.SSHGatePubPath, err)
	}

	// Dial the bootstrap leg.
	bootCfg, err := r.buildBootstrapClientConfig(in)
	if err != nil {
		return AddServerOutput{}, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, bootstrapDialTimeout)
	defer cancel()
	bootClient, hostFingerprint, err := dialBootstrap(dialCtx, in.Host, port, bootCfg)
	if err != nil {
		return AddServerOutput{}, fmt.Errorf("tools: bootstrap dial: %w", err)
	}
	defer bootClient.Close()

	// Check whether authorized_keys already has the canonical
	// restricted entry for our pubkey. If so, skip the rewrite.
	existing, _, err := runSSH(ctx, bootClient, "cat "+remoteAuthKeys+" 2>/dev/null || true")
	if err != nil {
		return AddServerOutput{}, fmt.Errorf("tools: read authorized_keys: %w", err)
	}
	idempotent := hasRestrictedEntryForKey(existing, sshgatePub, remoteGateBin)

	if !idempotent {
		// Run the full auto-setup, with rollback on any failure.
		if err := r.runAutoSetup(ctx, bootClient, gateBin, gatePubBytes,
			sshgatePub, existing); err != nil {
			return AddServerOutput{}, err
		}
	}

	// Step 7 — verify via r.SSH (sshgate dedicated key). Empty cmd
	// triggers the SSHGATE_OK probe path in gate's main.
	probe, _, _, err := r.SSH.Run(ctx, in.Host, in.User, port, "")
	if err != nil || !strings.Contains(string(probe), "SSHGATE_OK") {
		// Roll back if we just made changes; idempotent re-use never
		// modified anything, so skip rollback in that case.
		if !idempotent {
			r.rollback(ctx, bootClient, existing != nil)
		}
		if err != nil {
			return AddServerOutput{}, fmt.Errorf("tools: verify probe: %w (stdout=%q)", err, string(probe))
		}
		return AddServerOutput{}, fmt.Errorf("tools: verify probe did not return SSHGATE_OK (got %q)", string(probe))
	}

	// Step 9 — register.
	if err := r.Servers.Add(in.Alias, registry.Entry{
		Host:    in.Host,
		Port:    port,
		User:    in.User,
		AddedAt: time.Now().UTC(),
	}); err != nil {
		// Roll back the remote — registry was the last step.
		if !idempotent {
			r.rollback(ctx, bootClient, existing != nil)
		}
		return AddServerOutput{}, fmt.Errorf("tools: registry add: %w", err)
	}

	return AddServerOutput{
		Alias:        in.Alias,
		Host:         in.Host,
		Port:         port,
		User:         in.User,
		Fingerprint:  hostFingerprint,
		BinaryPath:   remoteGateBin,
		VerifiedOK:   true,
		Idempotent:   idempotent,
		ReadOnlyMode: in.ReadOnly,
	}, nil
}

// runAutoSetup executes steps 1–5 of the auto-setup flow (mkdir,
// upload, backup, rewrite authorized_keys). On any failure, it
// restores authorized_keys from the backup and removes ~/.sshgate-gate/.
//
// When gatePubBytes is nil, the gate.pub upload step is skipped
// — the remote runs in tier-1 read-only mode (gate's keystore
// treats missing pubkey as "no signer configured"; reads execute,
// writes are denied at the gate).
func (r *Runner) runAutoSetup(
	ctx context.Context, bootClient *ssh.Client,
	gateBin, gatePubBytes []byte,
	sshgatePub ssh.PublicKey, existingAuthKeys []byte,
) error {
	// Step 1: ensure ~/.sshgate-gate/ exists with the right perms.
	if _, _, err := runSSH(ctx, bootClient,
		"mkdir -p "+remoteGateDir+" && chmod 700 "+remoteGateDir,
	); err != nil {
		return fmt.Errorf("tools: mkdir .gate: %w", err)
	}

	// Step 2: upload gate binary.
	if err := uploadFile(ctx, bootClient, gateBin, remoteGateBin, "755"); err != nil {
		r.rollbackPartial(ctx, bootClient, existingAuthKeys, false /* authKeysRewritten */)
		return fmt.Errorf("tools: upload gate: %w", err)
	}

	// Step 3: upload gate.pub (skipped in tier-1 read-only mode).
	if gatePubBytes != nil {
		if err := uploadFile(ctx, bootClient, gatePubBytes, remoteGatePub, "644"); err != nil {
			r.rollbackPartial(ctx, bootClient, existingAuthKeys, false)
			return fmt.Errorf("tools: upload gate.pub: %w", err)
		}
	}

	// Step 4: backup authorized_keys (no-op if already exists).
	if _, _, err := runSSH(ctx, bootClient,
		// Use -n on cp via test; do not overwrite an existing backup
		// (we want to preserve the ORIGINAL state, not the most recent
		// pre-rewrite state, in case of repeated runs).
		"mkdir -p ~/.ssh && touch "+remoteAuthKeys+
			" && if [ ! -f "+remoteAuthKeysBackup+" ]; then cp "+remoteAuthKeys+" "+remoteAuthKeysBackup+"; fi",
	); err != nil {
		r.rollbackPartial(ctx, bootClient, existingAuthKeys, false)
		return fmt.Errorf("tools: backup authorized_keys: %w", err)
	}

	// Step 5: rewrite authorized_keys for the sshgate dedicated key.
	rewritten, err := rewriteAuthorizedKeys(existingAuthKeys, sshgatePub, remoteGateBin)
	if err != nil {
		r.rollbackPartial(ctx, bootClient, existingAuthKeys, false)
		return fmt.Errorf("tools: build authorized_keys: %w", err)
	}
	if err := uploadFile(ctx, bootClient, rewritten, remoteAuthKeys, "600"); err != nil {
		r.rollbackPartial(ctx, bootClient, existingAuthKeys, true)
		return fmt.Errorf("tools: write authorized_keys: %w", err)
	}
	return nil
}

// rollbackPartial cleans up after a mid-setup failure. authKeysRewritten
// indicates whether the rewrite finished (in which case the backup
// must be restored to undo it). Errors here are logged-implicitly via
// nil-discard; the caller already has a primary error to surface.
func (r *Runner) rollbackPartial(ctx context.Context, c *ssh.Client, original []byte, authKeysRewritten bool) {
	if authKeysRewritten {
		// Try the backup first; if that fails for some reason, write
		// the captured original directly.
		_, _, _ = runSSH(ctx, c,
			"if [ -f "+remoteAuthKeysBackup+" ]; then cp "+remoteAuthKeysBackup+" "+remoteAuthKeys+
				" && chmod 600 "+remoteAuthKeys+"; fi")
		if original != nil {
			_ = uploadFile(ctx, c, original, remoteAuthKeys, "600")
		}
	}
	_, _, _ = runSSH(ctx, c, "rm -rf "+remoteGateDir)
}

// UpgradeServerToSigning pushes gate.pub to an already-registered
// alias so the remote can verify signed write commands. Used in the
// tier-1 → tier-2 transition: after the operator runs /sshgate:setup
// to generate a signer, the slash command iterates registered servers
// and calls this method to switch each one from "read-only" to
// "signed-write" mode.
//
// The upload reuses the same bootstrap-leg credentials that AddServer
// used originally (BootstrapKeyPath / BootstrapAgent). We do not
// route the push through the SSHGate dedicated key because that key
// is locked to `command="~/.sshgate-gate/gate"` — it cannot place a
// file. Re-supplying bootstrap creds is the simplest correct design
// for v1.x; revisit when v2.x ships the hosted signer.
//
// Idempotent: calling on a server that already has gate.pub
// overwrites it. The probe at the end is the same SSHGATE_OK
// post-install check AddServer uses.
func (r *Runner) UpgradeServerToSigning(ctx context.Context, alias string, bootstrap AddServerInput) error {
	if r.Servers == nil {
		return errors.New("tools: Servers is nil")
	}
	if r.SSH == nil {
		return errors.New("tools: SSH is nil")
	}
	entry, ok := r.Servers.Get(alias)
	if !ok {
		return fmt.Errorf("tools: unknown server alias %q (check sshgate.list_servers)", alias)
	}
	if bootstrap.BootstrapAgent == (bootstrap.BootstrapKeyPath != "") {
		return errors.New("tools: must specify exactly one of bootstrap_key_path or bootstrap_agent=true")
	}
	// Fill the bootstrap host/user/port from the registry so callers
	// only have to supply the credentials.
	bootstrap.Alias = alias
	bootstrap.Host = entry.Host
	bootstrap.User = entry.User
	bootstrap.Port = entry.Port

	cfg, err := r.resolveAddServerCfg()
	if err != nil {
		return err
	}
	gatePubBytes, err := readLocalFile(cfg.GatePubPath, "gate signing public key",
		"run /sshgate:setup tier-2 to generate it")
	if err != nil {
		return err
	}

	bootCfg, err := r.buildBootstrapClientConfig(bootstrap)
	if err != nil {
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, bootstrapDialTimeout)
	defer cancel()
	bootClient, _, err := dialBootstrap(dialCtx, entry.Host, entry.Port, bootCfg)
	if err != nil {
		return fmt.Errorf("tools: bootstrap dial: %w", err)
	}
	defer bootClient.Close()

	// Push gate.pub. The remote directory already exists (gate
	// itself is in there), so we skip the mkdir; uploadFile sets the
	// final mode deterministically.
	if err := uploadFile(ctx, bootClient, gatePubBytes, remoteGatePub, "644"); err != nil {
		return fmt.Errorf("tools: upload gate.pub: %w", err)
	}

	// Verify via r.SSH (sshgate dedicated key) — empty cmd triggers
	// the SSHGATE_OK probe regardless of pubkey state, so this only
	// confirms the gate still answers, not that signed writes work.
	// The actual signed-write path is exercised the first time the
	// operator runs a write command through sshgate.run.
	probe, _, _, err := r.SSH.Run(ctx, entry.Host, entry.User, entry.Port, "")
	if err != nil || !strings.Contains(string(probe), "SSHGATE_OK") {
		if err != nil {
			return fmt.Errorf("tools: verify probe: %w (stdout=%q)", err, string(probe))
		}
		return fmt.Errorf("tools: verify probe did not return SSHGATE_OK (got %q)", string(probe))
	}
	return nil
}

// rollback is the post-verify rollback path: the auto-setup completed
// but the verification probe failed. We restore authorized_keys from
// the backup and remove ~/.sshgate-gate/. The hadOriginal flag is reserved
// for future granularity (e.g. distinguishing "no original file" from
// "original was empty") — today both cases collapse to restore-or-noop.
func (r *Runner) rollback(ctx context.Context, c *ssh.Client, hadOriginal bool) {
	_ = hadOriginal
	_, _, _ = runSSH(ctx, c,
		"if [ -f "+remoteAuthKeysBackup+" ]; then cp "+remoteAuthKeysBackup+" "+remoteAuthKeys+
			" && chmod 600 "+remoteAuthKeys+"; fi")
	_, _, _ = runSSH(ctx, c, "rm -rf "+remoteGateDir)
}

// resolveAddServerCfg fills in the default paths for the runner. Tests
// inject overrides via Runner.AddServerCfg.
func (r *Runner) resolveAddServerCfg() (addServerCfg, error) {
	cfg := r.AddServerCfg
	if cfg.GateBinaryPath == "" {
		p, err := defaultGateBinaryPath()
		if err != nil {
			return cfg, err
		}
		cfg.GateBinaryPath = p
	}
	if cfg.GatePubPath == "" {
		if env := os.Getenv("SSHGATE_SSHGATE_PUB_PATH"); env != "" {
			cfg.GatePubPath = env
		} else {
			root, err := configRoot()
			if err != nil {
				return cfg, err
			}
			cfg.GatePubPath = filepath.Join(root, "pubkey-distrib", "gate.pub")
		}
	}
	if cfg.SSHGatePubPath == "" {
		if env := os.Getenv("SSHGATE_SSH_PUBKEY_PATH"); env != "" {
			cfg.SSHGatePubPath = env
		} else {
			root, err := configRoot()
			if err != nil {
				return cfg, err
			}
			cfg.SSHGatePubPath = filepath.Join(root, "ssh", "sshgate_ed25519.pub")
		}
	}
	return cfg, nil
}

// gateBinaryName is the canonical basename of the cross-compiled
// remote gate binary (linux/amd64). It is the PREFIXED name produced
// by `make sshgate-gate-linux` and `make install-local`. The old
// unprefixed `gate-linux-amd64` is gone (audit B3).
const gateBinaryName = "sshgate-gate-linux-amd64"

// defaultGateBinaryPath resolves the cross-compiled gate binary. The
// /plugin install cache strips src/ and bin/, so we cannot rely on a
// path under the plugin cache. Resolution order (audit B3/M1/m1):
//
//  1. $SSHGATE_GATE_BIN — explicit operator override (absolute path).
//  2. <configRoot>/bin/sshgate-gate-linux-amd64 — the STABLE location
//     `make install-local` writes to (~/.config/sshgate/bin/).
//  3. <dir(os.Executable())>/sshgate-gate-linux-amd64 — covers the
//     `go install` layout where the gate sits beside sshgate-mcp in
//     $GOPATH/bin (dev / belt-and-braces).
//  4. $CLAUDE_PLUGIN_ROOT/bin/sshgate-gate-linux-amd64 — last-resort
//     legacy path for a clone-as-plugin-root install that still ships
//     a built bin/. (Note: this is CLAUDE_PLUGIN_ROOT, not the dead
//     SSHGATE_PLUGIN_ROOT that was never set — audit m1.)
//
// Each candidate is stat-checked; the first that exists wins. If none
// exists we return candidate (2) so readLocalFile surfaces a clean
// error naming the stable location and the build command.
func defaultGateBinaryPath() (string, error) {
	if env := os.Getenv("SSHGATE_GATE_BIN"); env != "" {
		return env, nil
	}

	root, err := configRoot()
	if err != nil {
		return "", err
	}
	configCandidate := filepath.Join(root, "bin", gateBinaryName)

	candidates := []string{configCandidate}

	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), gateBinaryName))
	}
	if pluginRoot := os.Getenv("CLAUDE_PLUGIN_ROOT"); pluginRoot != "" {
		candidates = append(candidates, filepath.Join(pluginRoot, "bin", gateBinaryName))
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	// None found: return the stable config-root candidate so the
	// missing-file error points the operator at the right place.
	return configCandidate, nil
}

// configRoot returns the SSHGate config root honouring
// $XDG_CONFIG_HOME / $HOME, mirroring sshgate-mcp/main.go.
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

// readLocalFile reads path with a helpful error envelope. The error
// mentions both the kind (what the file is) and a hint (how to
// produce it) when the file is missing.
func readLocalFile(path, kind, hint string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("tools: %s not found at %s; %s", kind, path, hint)
	}
	if err != nil {
		return nil, fmt.Errorf("tools: read %s: %w", path, err)
	}
	return b, nil
}

// buildBootstrapClientConfig assembles an *ssh.ClientConfig for the
// FIRST dial to the server. Auth comes from either BootstrapKeyPath or
// ssh-agent ($SSH_AUTH_SOCK). Host-key verification uses the same TOFU
// store as r.SSH.
func (r *Runner) buildBootstrapClientConfig(in AddServerInput) (*ssh.ClientConfig, error) {
	auth, err := bootstrapAuthMethod(in)
	if err != nil {
		return nil, err
	}

	// Re-use the regular SSH client's known_hosts for TOFU so the
	// bootstrap pin is the one subsequent r.SSH dials verify against.
	khPath := r.knownHostsPath()
	if khPath == "" {
		return nil, errors.New("tools: SSH client has no KnownHostsPath; cannot pin host key")
	}
	return &ssh.ClientConfig{
		User:            in.User,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: sshpkg.TOFU(khPath),
		Timeout:         bootstrapDialTimeout,
	}, nil
}

// bootstrapAuthMethod returns the AuthMethod implied by in's bootstrap
// fields. Caller has already validated that exactly one path is set.
func bootstrapAuthMethod(in AddServerInput) (ssh.AuthMethod, error) {
	if in.BootstrapAgent {
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, errors.New("tools: bootstrap_agent=true but $SSH_AUTH_SOCK is empty")
		}
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return nil, fmt.Errorf("dial ssh-agent: %w", err)
		}
		ag := agent.NewClient(conn)
		return ssh.PublicKeysCallback(ag.Signers), nil
	}
	if in.BootstrapKeyPath != "" {
		info, err := os.Stat(in.BootstrapKeyPath)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("bootstrap key %s does not exist", in.BootstrapKeyPath)
		}
		if err != nil {
			return nil, fmt.Errorf("stat bootstrap key: %w", err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("bootstrap key %s has insecure mode %#o (must be 0600)",
				in.BootstrapKeyPath, perm)
		}
		body, err := os.ReadFile(in.BootstrapKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read bootstrap key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(body)
		if err != nil {
			return nil, fmt.Errorf("parse bootstrap key: %w", err)
		}
		return ssh.PublicKeys(signer), nil
	}
	return nil, errors.New("tools: no bootstrap method")
}

// knownHostsPath introspects r.SSH for its known_hosts path. We use a
// small interface-cast rather than threading another field through the
// Runner; production wires in *sshpkg.Client, which exports the field.
func (r *Runner) knownHostsPath() string {
	type kh interface {
		KnownHosts() string
	}
	if k, ok := r.SSH.(kh); ok {
		return k.KnownHosts()
	}
	// Fallback: reflect on the common *sshpkg.Client type.
	if c, ok := r.SSH.(*sshpkg.Client); ok {
		return c.KnownHostsPath
	}
	return ""
}

// dialBootstrap performs the TCP dial + SSH handshake and returns the
// connected client plus the captured host-key fingerprint.
//
// Fingerprint capture: we wrap the supplied HostKeyCallback so we can
// observe the presented key (the TOFU callback updates the known_hosts
// store as a side effect).
func dialBootstrap(ctx context.Context, host string, port int, cfg *ssh.ClientConfig) (*ssh.Client, string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("dial %s: %w", addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// Intercept the host-key callback to capture the fingerprint.
	original := cfg.HostKeyCallback
	var captured string
	cfg.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		captured = sshpkg.Fingerprint(key)
		if original == nil {
			return nil
		}
		return original(hostname, remote, key)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("ssh handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(sshConn, chans, reqs), captured, nil
}

// runSSH executes cmd in a fresh session on client and returns its
// stdout and stderr. A non-zero exit is surfaced as an error wrapping
// "exit N: <stderr>" so callers can react without parsing.
func runSSH(ctx context.Context, client *ssh.Client, cmd string) ([]byte, []byte, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, nil, fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	// Propagate ctx by closing the session if ctx fires.
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-stopWatch:
		}
	}()
	if err := sess.Run(cmd); err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			return stdout.Bytes(), stderr.Bytes(),
				fmt.Errorf("exit %d: %s", ee.ExitStatus(), strings.TrimSpace(stderr.String()))
		}
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("run %q: %w", cmd, err)
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

// uploadFile sends body to remotePath via a fresh `sh -c "cat >..."`
// pipe and chmods to mode. We use the shell pipe rather than SFTP so
// the dependency surface stays small (the linuxserver image and most
// hardened sshd configs disable SFTP for the gate-gated key in
// later phases, but for the bootstrap leg we're still on the
// operator's normal key — either would work). The chmod step makes the
// final mode deterministic regardless of the remote umask.
//
// remotePath MUST be one of the package constants — they begin with a
// tilde (~/.sshgate-gate/...) so the remote shell tilde-expands them. We
// deliberately do NOT shell-quote remotePath: double-quoting would
// suppress tilde expansion, and the constants are statically known to
// be free of shell metacharacters.
func uploadFile(ctx context.Context, c *ssh.Client, body []byte, remotePath, mode string) error {
	if strings.ContainsAny(remotePath, " \t\n\r\x00\"'\\$`|&;<>(){}*?[]!#") {
		return fmt.Errorf("upload: remotePath %q contains shell metacharacters", remotePath)
	}
	sess, err := c.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	// Single shell command: cat to file, then chmod. remotePath is a
	// vetted constant — see the check above; we paste it verbatim so
	// the leading "~" tilde-expands as the remote shell intends.
	cmd := fmt.Sprintf("cat > %s && chmod %s %s", remotePath, mode, remotePath)
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-stopWatch:
		}
	}()
	if err := sess.Start(cmd); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	if _, err := io.Copy(stdin, bytes.NewReader(body)); err != nil {
		_ = sess.Close()
		return fmt.Errorf("write body: %w", err)
	}
	if err := stdin.Close(); err != nil {
		return fmt.Errorf("close stdin: %w", err)
	}
	if err := sess.Wait(); err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("upload exit %d: %s", ee.ExitStatus(), strings.TrimSpace(stderr.String()))
		}
		return fmt.Errorf("upload wait: %w", err)
	}
	return nil
}
