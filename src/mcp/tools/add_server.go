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
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

// AddServerInput carries the bootstrap-credential fields the shared
// provisioning machinery consumes. The human-only CLI add (Provision)
// builds one with just BootstrapKeyPath set to the SSHGate dedicated key;
// bootstrapAuthMethod resolves it into an ssh.AuthMethod.
//
// Exactly one of BootstrapKeyPath / BootstrapAgent must be set. The
// bootstrap leg uses an existing SSH credential to lay down gate;
// subsequent connections use the SSHGate dedicated key (with
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
	// the gate before committing to a signer setup. To move to
	// signed-write, revoke and re-provision with `sshgate add` (no
	// --read-only) after running /sshgate:setup.
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
	// ReadOnlyMode echoes the tier-1 read-only request. When true, the
	// remote has gate deployed but NO gate.pub — writes are denied at
	// the gate until the server is re-provisioned at tier-2.
	ReadOnlyMode bool `json:"read_only_mode,omitempty"`
}

// addServerCfg gathers the host-side local paths the shared provisioning
// machinery consults. The CLI add (Provision) carries the equivalent paths in
// its own provisionCfg; this struct survives as the override knob wired
// through Runner.AddServerCfg (intended for tests).
type addServerCfg struct {
	// GateBinaryPath is the local path to the cross-compiled gate
	// binary (sshgate-gate-linux-amd64).
	GateBinaryPath string
	// GatePubPath is the local path to the gate signing pubkey
	// (pubkey-distrib/gate.pub).
	GatePubPath string
	// SSHGatePubPath is the local path to the SSHGate dedicated SSH
	// pubkey (ssh/sshgate_ed25519.pub).
	SSHGatePubPath string
	// RemoteHome is the directory on the remote where ~/.sshgate-gate/ lives.
	// Default: "~" (left as a shell tilde — the remote shell expands it).
	RemoteHome string
}

// AddServerConfig is the exported alias wired through Runner.AddServerCfg
// (intended for tests). Set fields are used verbatim.
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

// bootstrapSession is the minimal set of remote operations the
// bootstrap pipeline performs over the operator's first-leg SSH
// connection: run a command (capturing stdout/stderr/exit), upload a
// file, and close the connection. It exists ONLY as a test seam — the
// production implementation (sshBootstrapSession) is a thin wrapper that
// delegates verbatim to the existing runSSH / uploadFile / *ssh.Client
// logic, so behaviour is byte-for-byte unchanged. Tests substitute an
// in-memory fake (via the newBootstrapSession var below) so the
// dial-upload-rollback flow is reachable without a real sshd.
//
// The method set is deliberately matched to the current call sites and
// nothing more:
//   - Run mirrors runSSH(ctx, client, cmd) — used for the
//     authorized_keys idempotency probe, mkdir, backup, and rollback.
//   - Upload mirrors uploadFile(ctx, client, body, remotePath, mode) —
//     used for the gate binary, gate.pub, and the rewritten
//     authorized_keys.
//   - Close mirrors *ssh.Client.Close — the deferred connection teardown.
type bootstrapSession interface {
	Run(ctx context.Context, cmd string) (stdout, stderr []byte, err error)
	Upload(ctx context.Context, body []byte, remotePath, mode string) error
	Close() error
}

// sshBootstrapSession is the production bootstrapSession: a thin wrapper
// over a connected *ssh.Client. Run/Upload forward to the package functions
// runSSH / uploadFile; Close forwards to the client. The indirection exists
// solely so tests can swap in an in-memory fake.
type sshBootstrapSession struct {
	client *ssh.Client
}

func (s *sshBootstrapSession) Run(ctx context.Context, cmd string) ([]byte, []byte, error) {
	return runSSH(ctx, s.client, cmd)
}

func (s *sshBootstrapSession) Upload(ctx context.Context, body []byte, remotePath, mode string) error {
	return uploadFile(ctx, s.client, body, remotePath, mode)
}

func (s *sshBootstrapSession) Close() error {
	return s.client.Close()
}

// newBootstrapSession dials the bootstrap leg and returns a live
// bootstrapSession plus the captured host-key fingerprint. It is a
// package-level var (mirroring the established `var dialWithCtx` seam in
// src/mcp/sign and `var gateDirFn` in src/gate/cmd) SOLELY so in-package
// tests can substitute an in-memory fake session and restore the
// original via defer. Production always uses the default below, which
// performs the real TCP dial + SSH handshake via dialBootstrap and wraps
// the resulting *ssh.Client in sshBootstrapSession. No env var, no
// exported API, no behaviour change.
var newBootstrapSession = func(ctx context.Context, host string, port int, cfg *ssh.ClientConfig) (bootstrapSession, string, error) {
	client, fingerprint, err := dialBootstrap(ctx, host, port, cfg)
	if err != nil {
		return nil, "", err
	}
	return &sshBootstrapSession{client: client}, fingerprint, nil
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
	ctx context.Context, bootSess bootstrapSession,
	gateBin, gatePubBytes []byte,
	sshgatePub ssh.PublicKey, existingAuthKeys []byte,
) error {
	// Step 1: ensure ~/.sshgate-gate/ exists with the right perms.
	if _, _, err := bootSess.Run(ctx,
		"mkdir -p "+remoteGateDir+" && chmod 700 "+remoteGateDir,
	); err != nil {
		return fmt.Errorf("tools: mkdir .gate: %w", err)
	}

	// Step 2: upload gate binary.
	if err := bootSess.Upload(ctx, gateBin, remoteGateBin, "755"); err != nil {
		r.rollbackPartial(ctx, bootSess, existingAuthKeys, false /* authKeysRewritten */)
		return fmt.Errorf("tools: upload gate: %w", err)
	}

	// Step 3: upload gate.pub (skipped in tier-1 read-only mode).
	if gatePubBytes != nil {
		if err := bootSess.Upload(ctx, gatePubBytes, remoteGatePub, "644"); err != nil {
			r.rollbackPartial(ctx, bootSess, existingAuthKeys, false)
			return fmt.Errorf("tools: upload gate.pub: %w", err)
		}
	}

	// Step 4: backup authorized_keys (no-op if already exists).
	if _, _, err := bootSess.Run(ctx,
		// Use -n on cp via test; do not overwrite an existing backup
		// (we want to preserve the ORIGINAL state, not the most recent
		// pre-rewrite state, in case of repeated runs).
		"mkdir -p ~/.ssh && touch "+remoteAuthKeys+
			" && if [ ! -f "+remoteAuthKeysBackup+" ]; then cp "+remoteAuthKeys+" "+remoteAuthKeysBackup+"; fi",
	); err != nil {
		r.rollbackPartial(ctx, bootSess, existingAuthKeys, false)
		return fmt.Errorf("tools: backup authorized_keys: %w", err)
	}

	// Step 5: rewrite authorized_keys for the sshgate dedicated key.
	rewritten, err := rewriteAuthorizedKeys(existingAuthKeys, sshgatePub, remoteGateBin)
	if err != nil {
		r.rollbackPartial(ctx, bootSess, existingAuthKeys, false)
		return fmt.Errorf("tools: build authorized_keys: %w", err)
	}
	if err := bootSess.Upload(ctx, rewritten, remoteAuthKeys, "600"); err != nil {
		r.rollbackPartial(ctx, bootSess, existingAuthKeys, true)
		return fmt.Errorf("tools: write authorized_keys: %w", err)
	}
	return nil
}

// rollbackPartial cleans up after a mid-setup failure. authKeysRewritten
// indicates whether the rewrite finished (in which case the backup
// must be restored to undo it). Errors here are logged-implicitly via
// nil-discard; the caller already has a primary error to surface.
func (r *Runner) rollbackPartial(ctx context.Context, c bootstrapSession, original []byte, authKeysRewritten bool) {
	if authKeysRewritten {
		// Try the backup first; if that fails for some reason, write
		// the captured original directly.
		_, _, _ = c.Run(ctx,
			"if [ -f "+remoteAuthKeysBackup+" ]; then cp "+remoteAuthKeysBackup+" "+remoteAuthKeys+
				" && chmod 600 "+remoteAuthKeys+"; fi")
		if original != nil {
			_ = c.Upload(ctx, original, remoteAuthKeys, "600")
		}
	}
	_, _, _ = c.Run(ctx, "rm -rf "+remoteGateDir)
}

// rollback is the post-verify rollback path: the auto-setup completed
// but the verification probe failed. We restore authorized_keys from
// the backup and remove ~/.sshgate-gate/. The hadOriginal flag is reserved
// for future granularity (e.g. distinguishing "no original file" from
// "original was empty") — today both cases collapse to restore-or-noop.
//
// It returns the error (if any) from the authorized_keys RESTORE step.
// Provision uses it to decide whether to escalate its remediation message:
// for the CLI path the "backup" is the human's PLAIN pasted line, so a
// restore failure can leave an un-restricted SSHGate key on the host and the
// human must be told. The gate-dir removal error is intentionally not
// surfaced — a leftover ~/.sshgate-gate/ is harmless next to a
// correctly-restricted key.
func (r *Runner) rollback(ctx context.Context, c bootstrapSession, hadOriginal bool) error {
	_ = hadOriginal
	_, _, restoreErr := c.Run(ctx,
		"if [ -f "+remoteAuthKeysBackup+" ]; then cp "+remoteAuthKeysBackup+" "+remoteAuthKeys+
			" && chmod 600 "+remoteAuthKeys+"; fi")
	_, _, _ = c.Run(ctx, "rm -rf "+remoteGateDir)
	return restoreErr
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

// dialAgentSock dials the ssh-agent Unix socket at $SSH_AUTH_SOCK. It is
// a package-level var SOLELY as an in-package test seam (same rationale
// as newBootstrapSession): tests point it at a controlled net.Conn so
// the agent-auth branch is reachable without a live ssh-agent. Production
// always uses net.Dial("unix", sock); no env var, no exported API, no
// behaviour change.
var dialAgentSock = func(sock string) (net.Conn, error) {
	return net.Dial("unix", sock)
}

// parsePrivateKey parses an OpenSSH private key into a Signer. It is a
// package-level var for the same in-package test-seam reason as above —
// the parse-success branch can be exercised with a key that is known to
// parse, and tests may inject a deterministic Signer. Production always
// uses ssh.ParsePrivateKey verbatim.
var parsePrivateKey = ssh.ParsePrivateKey

// bootstrapAuthMethod returns the AuthMethod implied by in's bootstrap
// fields. Caller has already validated that exactly one path is set.
func bootstrapAuthMethod(in AddServerInput) (ssh.AuthMethod, error) {
	if in.BootstrapAgent {
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, errors.New("tools: bootstrap_agent=true but $SSH_AUTH_SOCK is empty")
		}
		conn, err := dialAgentSock(sock)
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
		signer, err := parsePrivateKey(body)
		if err != nil {
			return nil, fmt.Errorf("parse bootstrap key: %w", err)
		}
		return ssh.PublicKeys(signer), nil
	}
	return nil, errors.New("tools: no bootstrap method")
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
