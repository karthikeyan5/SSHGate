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
// velgate; subsequent connections use the SSHGate dedicated key (with
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
}

// addServerCfg gathers the host-side paths/env knobs that the runner
// consults when running AddServer. Defaults are populated when fields
// are zero; tests inject overrides directly.
type addServerCfg struct {
	// VelgateBinaryPath is the local path to the cross-compiled
	// velgate binary. Default: bin/velgate-linux-amd64 next to the
	// running MCP binary.
	VelgateBinaryPath string
	// VelgatePubPath is the local path to the velgate signing pubkey.
	// Default: <configRoot>/pubkey-distrib/velgate.pub.
	VelgatePubPath string
	// SSHGatePubPath is the local path to the SSHGate dedicated SSH
	// pubkey. Default: <configRoot>/ssh/sshgate_ed25519.pub.
	SSHGatePubPath string
	// RemoteHome is the directory on the remote where ~/.velgate/ lives.
	// Default: "~" (left as a shell tilde — the remote shell expands it).
	RemoteHome string
}

// AddServerConfig overrides AddServer's defaults. Set fields are used
// verbatim; zero fields fall back to the documented defaults. Wired
// through Runner.AddServerCfg (intended for tests).
type AddServerConfig = addServerCfg

// remoteVelgateDir is the canonical install location on the remote.
const remoteVelgateDir = "~/.velgate"
const remoteVelgateBin = "~/.velgate/velgate"
const remoteVelgatePub = "~/.velgate/velgate.pub"
const remoteAuthKeys = "~/.ssh/authorized_keys"
const remoteAuthKeysBackup = "~/.ssh/authorized_keys.sshgate-backup"

// aliasPattern is the allowed alias shape: lowercase ASCII start,
// lowercase / digit / hyphen continuation, 1-31 chars total.
var aliasPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// bootstrapDialTimeout bounds the bootstrap-leg dial + handshake.
const bootstrapDialTimeout = 20 * time.Second

// AddServer registers a new server alias and installs velgate on it
// using the bootstrap credentials supplied in in. The flow is:
//
//  1. Validate inputs (alias regex, exactly one bootstrap method,
//     not-already-registered).
//  2. Dial the remote with the bootstrap credentials (using the
//     SAME TOFU known_hosts as r.SSH so the host key pins on first
//     contact).
//  3. Upload velgate + velgate.pub under ~/.velgate/.
//  4. Back up authorized_keys and rewrite it to gate the SSHGate
//     dedicated key behind a command= forcing.
//  5. Verify by reconnecting via r.SSH (empty SSH_ORIGINAL_COMMAND
//     → "VELGATE_OK").
//  6. Register the alias in the registry.
//
// Steps 3-5 are wrapped in a rollback: any failure restores
// authorized_keys from the backup and removes ~/.velgate/. The
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
	if strings.TrimSpace(in.Host) == "" {
		return AddServerOutput{}, errors.New("tools: host is empty")
	}
	if strings.TrimSpace(in.User) == "" {
		return AddServerOutput{}, errors.New("tools: user is empty")
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
	velgateBin, err := readLocalFile(cfg.VelgateBinaryPath, "velgate binary",
		"build it with `make velgate-linux` first")
	if err != nil {
		return AddServerOutput{}, err
	}
	velgatePubBytes, err := readLocalFile(cfg.VelgatePubPath, "velgate signing public key",
		"ensure /sshgate:setup has been run")
	if err != nil {
		return AddServerOutput{}, err
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
	idempotent := hasRestrictedEntryForKey(existing, sshgatePub, remoteVelgateBin)

	if !idempotent {
		// Run the full auto-setup, with rollback on any failure.
		if err := r.runAutoSetup(ctx, bootClient, velgateBin, velgatePubBytes,
			sshgatePub, existing); err != nil {
			return AddServerOutput{}, err
		}
	}

	// Step 7 — verify via r.SSH (sshgate dedicated key). Empty cmd
	// triggers the VELGATE_OK probe path in velgate's main.
	probe, _, _, err := r.SSH.Run(ctx, in.Host, in.User, port, "")
	if err != nil || !strings.Contains(string(probe), "VELGATE_OK") {
		// Roll back if we just made changes; idempotent re-use never
		// modified anything, so skip rollback in that case.
		if !idempotent {
			r.rollback(ctx, bootClient, existing != nil)
		}
		if err != nil {
			return AddServerOutput{}, fmt.Errorf("tools: verify probe: %w (stdout=%q)", err, string(probe))
		}
		return AddServerOutput{}, fmt.Errorf("tools: verify probe did not return VELGATE_OK (got %q)", string(probe))
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
		Alias:       in.Alias,
		Host:        in.Host,
		Port:        port,
		User:        in.User,
		Fingerprint: hostFingerprint,
		BinaryPath:  remoteVelgateBin,
		VerifiedOK:  true,
		Idempotent:  idempotent,
	}, nil
}

// runAutoSetup executes steps 1–5 of the auto-setup flow (mkdir,
// upload, backup, rewrite authorized_keys). On any failure, it
// restores authorized_keys from the backup and removes ~/.velgate/.
func (r *Runner) runAutoSetup(
	ctx context.Context, bootClient *ssh.Client,
	velgateBin, velgatePubBytes []byte,
	sshgatePub ssh.PublicKey, existingAuthKeys []byte,
) error {
	// Step 1: ensure ~/.velgate/ exists with the right perms.
	if _, _, err := runSSH(ctx, bootClient,
		"mkdir -p "+remoteVelgateDir+" && chmod 700 "+remoteVelgateDir,
	); err != nil {
		return fmt.Errorf("tools: mkdir .velgate: %w", err)
	}

	// Step 2: upload velgate binary.
	if err := uploadFile(ctx, bootClient, velgateBin, remoteVelgateBin, "755"); err != nil {
		r.rollbackPartial(ctx, bootClient, existingAuthKeys, false /* authKeysRewritten */)
		return fmt.Errorf("tools: upload velgate: %w", err)
	}

	// Step 3: upload velgate.pub.
	if err := uploadFile(ctx, bootClient, velgatePubBytes, remoteVelgatePub, "644"); err != nil {
		r.rollbackPartial(ctx, bootClient, existingAuthKeys, false)
		return fmt.Errorf("tools: upload velgate.pub: %w", err)
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
	rewritten, err := rewriteAuthorizedKeys(existingAuthKeys, sshgatePub, remoteVelgateBin)
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
	_, _, _ = runSSH(ctx, c, "rm -rf "+remoteVelgateDir)
}

// rollback is the post-verify rollback path: the auto-setup completed
// but the verification probe failed. We restore authorized_keys from
// the backup and remove ~/.velgate/. The hadOriginal flag is reserved
// for future granularity (e.g. distinguishing "no original file" from
// "original was empty") — today both cases collapse to restore-or-noop.
func (r *Runner) rollback(ctx context.Context, c *ssh.Client, hadOriginal bool) {
	_ = hadOriginal
	_, _, _ = runSSH(ctx, c,
		"if [ -f "+remoteAuthKeysBackup+" ]; then cp "+remoteAuthKeysBackup+" "+remoteAuthKeys+
			" && chmod 600 "+remoteAuthKeys+"; fi")
	_, _, _ = runSSH(ctx, c, "rm -rf "+remoteVelgateDir)
}

// resolveAddServerCfg fills in the default paths for the runner. Tests
// inject overrides via Runner.AddServerCfg.
func (r *Runner) resolveAddServerCfg() (addServerCfg, error) {
	cfg := r.AddServerCfg
	if cfg.VelgateBinaryPath == "" {
		p, err := defaultVelgateBinaryPath()
		if err != nil {
			return cfg, err
		}
		cfg.VelgateBinaryPath = p
	}
	if cfg.VelgatePubPath == "" {
		if env := os.Getenv("SSHGATE_VELGATE_PUB_PATH"); env != "" {
			cfg.VelgatePubPath = env
		} else {
			root, err := configRoot()
			if err != nil {
				return cfg, err
			}
			cfg.VelgatePubPath = filepath.Join(root, "pubkey-distrib", "velgate.pub")
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

// defaultVelgateBinaryPath resolves the bundled velgate-linux-amd64
// binary. It checks $SSHGATE_PLUGIN_ROOT first (set by Claude Code at
// plugin load), then falls back to <dir(os.Executable())>/../bin.
func defaultVelgateBinaryPath() (string, error) {
	if root := os.Getenv("SSHGATE_PLUGIN_ROOT"); root != "" {
		return filepath.Join(root, "bin", "velgate-linux-amd64"), nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("os.Executable: %w", err)
	}
	// Two layouts we expect:
	//   <root>/bin/sshgate-mcp        (production plugin layout)
	//   <root>/.../sshgate-mcp        (go test / dev)
	// Try sibling first, then parent's bin dir.
	dir := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(dir, "velgate-linux-amd64"),
		filepath.Join(dir, "..", "bin", "velgate-linux-amd64"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	// Fall through with the first candidate; readLocalFile will
	// surface a clean error mentioning the build target.
	return candidates[0], nil
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
// hardened sshd configs disable SFTP for the velgate-gated key in
// later phases, but for the bootstrap leg we're still on the
// operator's normal key — either would work). The chmod step makes the
// final mode deterministic regardless of the remote umask.
//
// remotePath MUST be one of the package constants — they begin with a
// tilde (~/.velgate/...) so the remote shell tilde-expands them. We
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
