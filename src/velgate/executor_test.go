package velgate_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/velgate"
)

// captureStdout runs fn while temporarily redirecting os.Stdout to a
// pipe; it returns whatever fn wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	var buf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&buf, r)
	}()
	fn()
	_ = w.Close()
	wg.Wait()
	_ = r.Close()
	return buf.String()
}

func TestExec(t *testing.T) {
	t.Run("echo returns 0 and writes to stdout", func(t *testing.T) {
		var exit int
		var err error
		out := captureStdout(t, func() {
			exit, err = velgate.Exec(context.Background(), "echo hello")
		})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if exit != 0 {
			t.Errorf("exit = %d, want 0", exit)
		}
		if out != "hello\n" {
			t.Errorf("stdout = %q, want %q", out, "hello\n")
		}
	})

	t.Run("false returns exit 1", func(t *testing.T) {
		exit, err := velgate.Exec(context.Background(), "false")
		if err != nil {
			t.Fatalf("err = %v, want nil (false's nonzero exit is not a start error)", err)
		}
		if exit != 1 {
			t.Errorf("exit = %d, want 1", exit)
		}
	})

	t.Run("explicit exit code passes through", func(t *testing.T) {
		exit, err := velgate.Exec(context.Background(), "sh -c 'exit 42'")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if exit != 42 {
			t.Errorf("exit = %d, want 42", exit)
		}
	})

	t.Run("nonexistent command exits nonzero", func(t *testing.T) {
		exit, err := velgate.Exec(context.Background(), "/nonexistent/path/binary")
		if err != nil {
			t.Fatalf("err = %v, want nil (nonzero exit is not a start error)", err)
		}
		if exit == 0 {
			t.Errorf("exit = 0, want nonzero")
		}
	})

	t.Run("context cancel terminates a long sleep", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		exit, err := velgate.Exec(ctx, "sleep 10")
		dur := time.Since(start)
		if dur > 5*time.Second {
			t.Fatalf("exec ran %v, expected to be killed promptly", dur)
		}
		_ = err
		if exit == 0 {
			t.Errorf("exit = 0, want nonzero (process should have been killed)")
		}
	})

	t.Run("large stdout streams without buffering", func(t *testing.T) {
		// Print ~64KB of output. captureStdout via os.Pipe is bounded by
		// pipe buffer; we read concurrently in captureStdout so the
		// child shouldn't block.
		out := captureStdout(t, func() {
			// 64 KB of "x" via printf — portable across sh/bash.
			_, err := velgate.Exec(context.Background(), "yes x | head -c 65536")
			if err != nil {
				t.Errorf("err = %v", err)
			}
		})
		if len(out) < 65000 {
			t.Errorf("stdout len = %d, want ≥ 65000", len(out))
		}
		// Sanity check first chars.
		if !strings.HasPrefix(out, "x") {
			t.Errorf("stdout prefix = %q, want to start with x", out[:min(10, len(out))])
		}
	})

	t.Run("empty cmd is rejected", func(t *testing.T) {
		exit, err := velgate.Exec(context.Background(), "")
		if err == nil {
			t.Errorf("err = nil, want error for empty cmd; exit=%d", exit)
		}
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
