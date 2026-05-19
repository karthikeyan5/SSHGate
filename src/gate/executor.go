package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// Exec runs cmd via "/bin/sh -c <cmd>", streaming the child's stdout
// and stderr to the calling process's os.Stdout and os.Stderr. It
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
func Exec(ctx context.Context, cmd string) (exitCode int, err error) {
	if strings.TrimSpace(cmd) == "" {
		return -1, errors.New("exec: empty command")
	}
	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
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
