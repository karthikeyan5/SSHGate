package gate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/karthikeyan5/sshgate/src/redact"
)

// Exec runs cmd via "/bin/sh -c <cmd>", streaming the child's stdout
// and stderr to the calling process's os.Stdout and os.Stderr — or,
// if a session salt and ruleset are supplied via ExecOpts, through a
// redact.Writer that scrubs Layer-1 named-format secrets inline. It
// blocks until the child exits or ctx is cancelled, whichever comes
// first.
//
// Return values:
//
//   - exitCode is the child's exit code in the range 0..255. When the
//     process is killed by a signal (including ctx cancellation), the
//     exit code is reported as 128+signum, matching the convention used
//     by shells. If the process never started (e.g. /bin/sh missing),
//     exitCode is -1.
//   - err is non-nil only on start failures. A nonzero exit code from a
//     successfully-started child is NOT an error from gate's
//     perspective — the caller is expected to propagate exitCode as
//     gate's own exit status.
//
// Exec sets a process group on the child so that ctx cancellation
// kills the whole group, not just the shell. This matters because the
// child may itself spawn subprocesses (e.g. pipelines) that would
// otherwise be reparented to PID 1 and outlive cancellation.
//
// Exec wraps the historical no-redact signature; new callers should
// use ExecWithRedaction.
func Exec(ctx context.Context, cmd string) (exitCode int, err error) {
	return ExecWithRedaction(ctx, cmd, ExecOpts{})
}

// ExecOpts holds the optional redactor wiring for a single command.
//
// SessionSalt is a per-process 32-byte random value used for HMAC
// marker keys. Generated once at gate startup (see
// cmd/sshgate-gate/main.go) and never persisted.
//
// Rules is the compiled-in ruleset (typically rules.Combined()). When
// empty, both Stdout and Stderr pass through with no redaction —
// equivalent to v1.0 behaviour, useful for tests that exercise the
// raw executor.
type ExecOpts struct {
	SessionSalt [32]byte
	Rules       []redact.Rule
}

// ExecWithRedaction is the v1.2 entry point. When opts.Rules is
// non-empty, c.Stdout and c.Stderr are wrapped in redact.Writer
// instances so every byte the child emits passes through the
// streaming scrubber before reaching the SSH stream.
//
// The redactor lives at the gate boundary by design (see
// docs/audits/secrets-redaction-architecture-2026-05-19.md §"Where
// it lives") — the MCP-side trust boundary is bypassable; the gate
// is the only physical choke point.
func ExecWithRedaction(ctx context.Context, cmd string, opts ExecOpts) (exitCode int, err error) {
	if strings.TrimSpace(cmd) == "" {
		return -1, errors.New("exec: empty command")
	}
	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)

	// Stdout / Stderr: when a ruleset is configured, wrap in a
	// redact.Writer per stream. Stderr is treated identically to
	// stdout — the spec is explicit: both streams pass through their
	// own writer (no cross-stream coupling, no shared buffer).
	var stdoutCloser, stderrCloser io.Closer
	if len(opts.Rules) > 0 {
		ow := redact.NewWriter(os.Stdout, opts.SessionSalt, opts.Rules)
		ew := redact.NewWriter(os.Stderr, opts.SessionSalt, opts.Rules)
		c.Stdout = ow
		c.Stderr = ew
		stdoutCloser = ow
		stderrCloser = ew
	} else {
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
	}
	c.Stdin = os.Stdin
	// Run the child in its own process group so ctx cancellation kills
	// the whole tree (the shell plus anything it spawned).
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// When ctx is cancelled, send SIGKILL to the whole process group.
	// exec.CommandContext by default only signals the direct child;
	// override Cancel so we get the group.
	c.Cancel = func() error {
		if c.Process == nil {
			return os.ErrProcessDone
		}
		// Negative PID targets the process group.
		return syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
	}

	if err := c.Start(); err != nil {
		return -1, fmt.Errorf("exec: start /bin/sh: %w", err)
	}
	waitErr := c.Wait()
	// Flush the redact.Writer instances after the child exits so any
	// bytes still held inside the safe-prefix tail (or inside a
	// not-yet-completed PEM accumulator) reach the SSH stream. Close
	// errors here are surfaced over the wait error only when the
	// child itself succeeded — a write error after a successful exit
	// is still an error the agent should see.
	if stdoutCloser != nil {
		if cerr := stdoutCloser.Close(); cerr != nil && waitErr == nil {
			waitErr = fmt.Errorf("redact stdout: %w", cerr)
		}
	}
	if stderrCloser != nil {
		if cerr := stderrCloser.Close(); cerr != nil && waitErr == nil {
			waitErr = fmt.Errorf("redact stderr: %w", cerr)
		}
	}
	if waitErr == nil {
		return 0, nil
	}
	// Extract the exit code or signal status from the wait error.
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		ws, ok := exitErr.Sys().(syscall.WaitStatus)
		if ok {
			if ws.Signaled() {
				return 128 + int(ws.Signal()), nil
			}
			return ws.ExitStatus(), nil
		}
		// Fallback: ExitCode() returns -1 if signaled; use it as best effort.
		return exitErr.ExitCode(), nil
	}
	// Non-ExitError wait failure (e.g. waitpid syscall error). Treat as
	// a start/run failure so the caller can distinguish it.
	return -1, fmt.Errorf("exec: wait: %w", waitErr)
}
