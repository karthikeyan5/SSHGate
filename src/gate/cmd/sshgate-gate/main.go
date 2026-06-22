// Command gate is the remote-side gate of SSHGate. OpenSSH invokes
// it through a forced `command="~/.sshgate-gate/gate"` entry on the
// SSHGate dedicated key; the forwarded command from the client arrives
// in $SSH_ORIGINAL_COMMAND.
//
// Exit codes (BSD sysexits where applicable):
//
//	0  — success (also: empty SSH_ORIGINAL_COMMAND, the post-install
//	     verification probe; prints SSHGATE_OK and exits 0)
//	1  — generic runtime failure or non-zero from /bin/sh -c on the
//	     non-pass-through paths (the stub SSHGATE_REVOKE/SSHGATE_UPDATE
//	     handlers fall here)
//	65 — EX_DATAERR: bad signature, bad envelope format, expired sig,
//	     validity window too long
//	70 — EX_SOFTWARE: pubkey file unreadable, corrupt, or has insecure
//	     mode
//	77 — EX_NOPERM: write command without a verified SSHGATE_SIG prefix
//
// Exit codes from the executed inner command are passed through
// directly (so /bin/sh -c 'exit 42' makes gate exit 42).
//
// Stdio discipline: gate's own log lines go to stderr only,
// prefixed with "gate: ". Stdout is reserved for the executed
// inner command's stdout. The post-install probe is the one
// exception — it prints exactly "SSHGATE_OK" to stdout because the
// installer reads that line over SSH to confirm the gate is alive.
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/karthikeyan5/sshgate/src/classify"
	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/hostkey"
	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// sessionSalt is the per-process 32 random bytes the redactor uses to
// derive HMAC marker keys. Populated by run() at startup, never
// persisted, never transmitted. Per-process equals per-session because
// OpenSSH spawns a fresh gate for every SSH_ORIGINAL_COMMAND
// invocation. Stored at package scope so execChild can read it without
// threading it through every call site.
var sessionSalt [32]byte

// redactRules, when non-nil, is a test-injected redaction ruleset.
// Production leaves it nil and compiles the real v1.2 ruleset
// (redactrules.Combined() — sshgate-native + gitleaks-vendored)
// LAZILY in execChild: only the execute path needs it, so a per-command
// gate spawn that denies a write, fails signature verification, or
// answers the install probe never pays the ~1 MB regex-compile cost.
// Kept out of init() (daemon guideline 1.6) so test imports don't pay
// it either.
var redactRules []redact.Rule

// Exit codes (BSD sysexits subset).
const (
	exitOK        = 0
	exitGeneric   = 1
	exitDataErr   = 65 // EX_DATAERR
	exitSoftware  = 70 // EX_SOFTWARE
	exitNoPermVal = 77 // EX_NOPERM
)

func main() {
	os.Exit(run())
}

// run is the testable entry point; main exits on its return value.
func run() int {
	// Per-process redactor state: fresh 32-byte salt + compiled-in
	// ruleset. Failures here are fatal — we cannot serve traffic
	// without a fresh salt for HMAC marker keys.
	if _, err := rand.Read(sessionSalt[:]); err != nil {
		logf("crypto/rand: %v", err)
		return exitSoftware
	}

	raw := os.Getenv("SSH_ORIGINAL_COMMAND")
	if raw == "" {
		// Post-install probe. Stdout only (the installer reads this).
		fmt.Println("SSHGATE_OK")
		return exitOK
	}

	// Locate gate.pub alongside the binary.
	pubPath, err := pubKeyPath()
	if err != nil {
		logf("locate pubkey: %v", err)
		return exitSoftware
	}
	pubkey, err := gate.LoadPubKey(pubPath)
	if err != nil {
		logf("load pubkey: %v", err)
		return exitSoftware
	}

	// Decide whether the inbound line is signed.
	signed := sigwire.IsSigned(raw)

	// Tier-1 read-only mode: pubkey is nil when gate.pub is absent.
	// Reads still execute (no signature check required); writes and
	// signed commands are denied — there is no anchor to verify them
	// against, and silently exec'ing them would be a privilege
	// escalation against the operator's expectation that "no signer
	// means no writes."
	if pubkey == nil {
		if signed {
			logf("no signing key configured; signed commands cannot be verified")
			return exitNoPermVal
		}
		kind := classify.Classify(raw)
		if kind == classify.KindRead {
			return execChild(raw)
		}
		// KindWrite or KindUnknown (empty/whitespace already handled
		// upstream — anything else unknown falls through as write).
		logf("no signing key configured (read-only install — re-run /sshgate:setup to add a signer)")
		return exitNoPermVal
	}

	innerCmd := raw
	if signed {
		// Self-derive THIS gate's host-key fingerprints so VerifySigned can
		// enforce the per-server binding: a signature approved for server X
		// must name X's pinned host key, so it cannot be replayed on server Y.
		// Reading the world-readable static /etc/ssh/ssh_host_*.pub files at
		// process start is identity, not decision state — the gate stays
		// stateless. An empty set fails closed inside VerifySigned
		// (ErrHostMismatch), which is the correct outcome when the gate cannot
		// identify itself; we surface a clearer error here when the glob itself
		// errored.
		selfHostFPs, herr := hostKeyFPsFn()
		if herr != nil {
			logf("derive host-key fingerprints: %v", herr)
			return exitSoftware
		}
		ic, err := gate.VerifySigned(raw, pubkey, time.Now(), selfHostFPs)
		if err != nil {
			logf("%v", err)
			return exitDataErr
		}
		innerCmd = ic
	}

	// Administrative commands. Only valid when signed.
	if signed {
		if innerCmd == "SSHGATE_REVOKE" {
			return doRevoke()
		}
		if strings.HasPrefix(innerCmd, "SSHGATE_UPDATE ") {
			// Future: self-update path (fetch + verify + replace the gate binary).
			logf("SSHGATE_UPDATE not yet implemented")
			return exitGeneric
		}
	}

	kind := classify.Classify(innerCmd)
	switch kind {
	case classify.KindRead:
		return execChild(innerCmd)
	case classify.KindWrite, classify.KindUnknown:
		// Fail-safe: unknown is treated as write (classify.Classify
		// already returns KindWrite for the truly-unknown cases; an
		// empty/whitespace cmd is the only KindUnknown that can reach
		// here, and we treat that as denied too).
		if !signed {
			logf("write commands require a SSHGATE_SIG prefix")
			return exitNoPermVal
		}
		return execChild(innerCmd)
	default:
		logf("unexpected classification: %v", kind)
		return exitGeneric
	}
}

// execChild runs cmd under a signal-aware context. SIGTERM/SIGINT
// received by gate are propagated to the child process group via
// the context cancellation wired through Exec. The child's
// stdout/stderr are wrapped in redact.Writer instances so every byte
// the child emits passes Layer-1 redaction (v1.2 R1).
func execChild(cmd string) int {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	// Compile the redaction ruleset lazily — only this execute path needs
	// it. A test may inject redactRules beforehand (the package-var seam);
	// honour that and compile the real ruleset only when it is unset.
	rules := redactRules
	if rules == nil {
		rules = redactrules.Combined()
	}
	exit, err := gate.ExecWithRedaction(ctx, cmd, gate.ExecOpts{
		SessionSalt: sessionSalt,
		Rules:       rules,
	})
	if err != nil {
		logf("%v", err)
		if exit < 0 {
			return exitGeneric
		}
	}
	if exit < 0 {
		return exitGeneric
	}
	return exit
}

// gateDirFn resolves the gate install directory and the absolute path
// to the running gate binary inside it. It is a package-level var so
// in-package tests can point the resolution at a t.TempDir without
// re-exec'ing the test binary; production code always uses
// defaultGateDir, which derives both from os.Executable(). This is NOT
// driven by any environment variable on purpose — letting the
// environment redirect where gate.pub is read would be a signature
// forgery surface, since gate.pub is the trust anchor for every
// verified command.
var gateDirFn = defaultGateDir

// homeDirFn resolves the operator's home directory. Same test-seam
// rationale as gateDirFn; defaults to os.UserHomeDir.
var homeDirFn = os.UserHomeDir

// hostKeyFPsFn returns THIS gate's own SSH host-key fingerprints, used to
// enforce the per-server host-key binding on the signed-write path. It is a
// package-level var so in-package tests can inject a controlled set without an
// /etc/ssh on the test box; production reads the real host keys from
// hostkey.DefaultHostKeyGlob (/etc/ssh/ssh_host_*.pub). Like gateDirFn this is
// deliberately NOT driven by any environment variable: letting the environment
// redirect which host keys the gate trusts would be a binding-forgery surface.
var hostKeyFPsFn = hostkey.LoadHostFingerprints

// defaultGateDir returns the directory holding the gate binary and the
// binary's own absolute path, both derived from os.Executable().
func defaultGateDir() (gateDir, binaryPath string, err error) {
	exe, err := os.Executable()
	if err != nil {
		return "", "", fmt.Errorf("os.Executable: %w", err)
	}
	return filepath.Dir(exe), exe, nil
}

// pubKeyPath returns the path to gate.pub, expected to live in the
// same directory as the gate binary itself.
func pubKeyPath() (string, error) {
	dir, _, err := gateDirFn()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "gate.pub"), nil
}

// doRevoke performs the on-host teardown half of a revoke. It locates
// the gate install directory relative to os.Executable() (so the
// SSHGate dedicated key, which is the only one routed here, controls
// exactly its own line in authorized_keys), runs gate.Revoke, and
// prints a single SSHGATE_REVOKED status line to stdout on success.
// The MCP side detects that prefix as confirmation.
//
// Exit codes:
//
//	0  — revoke succeeded (lines may or may not have matched; both are
//	     legitimate, the dir is gone either way)
//	1  — could not resolve paths or rewrite authorized_keys
func doRevoke() int {
	gateDir, binaryPath, err := gateDirFn()
	if err != nil {
		logf("revoke: %v", err)
		return exitGeneric
	}

	home, err := homeDirFn()
	if err != nil {
		logf("revoke: home dir: %v", err)
		return exitGeneric
	}

	res, err := gate.Revoke(home, gateDir, binaryPath)
	if err != nil {
		logf("revoke: %v", err)
		return exitGeneric
	}
	fmt.Println(gate.FormatRevokeStdout(res))
	return exitOK
}

// logf writes a single line to stderr with the "gate: " prefix.
// Errors from the write are intentionally ignored — there is no
// recovery path for "could not write to stderr."
func logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	// Unwrap-friendly sentinels render through %v as expected. Keep
	// only one final newline.
	msg = strings.TrimRight(msg, "\n")
	fmt.Fprintf(os.Stderr, "gate: %s\n", msg)
}
