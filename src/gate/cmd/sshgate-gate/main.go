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
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/karthikeyan5/sshgate/src/classify"
	"github.com/karthikeyan5/sshgate/src/sigwire"
	"github.com/karthikeyan5/sshgate/src/gate"
)

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
		ic, err := gate.VerifySigned(raw, pubkey, time.Now())
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
			// TODO(v1.1): fetch + verify + replace the gate binary.
			logf("SSHGATE_UPDATE not yet implemented (v1.1)")
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
// the context cancellation wired through Exec.
func execChild(cmd string) int {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	exit, err := gate.Exec(ctx, cmd)
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

// pubKeyPath returns the path to gate.pub, expected to live in the
// same directory as the gate binary itself.
func pubKeyPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("os.Executable: %w", err)
	}
	dir := filepath.Dir(exe)
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
	exe, err := os.Executable()
	if err != nil {
		logf("revoke: os.Executable: %v", err)
		return exitGeneric
	}
	gateDir := filepath.Dir(exe)
	binaryPath := exe

	home, err := os.UserHomeDir()
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
