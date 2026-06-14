package sign_test

import (
	"bufio"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// rawConn is the slice of net.Conn a raw handler needs: it can read the
// (single-line) request the client sent and then write/close arbitrarily
// — including a newline-less fragment followed by Close to drive the
// client's read-side EOF / partial-line path, which the higher-level
// startFakeSigner (which always frames responses with a trailing '\n')
// cannot express.
type rawConn interface {
	io.Writer
	io.Closer
}

// startRawSigner binds a unix socket on t.TempDir and, for each accepted
// connection, first drains the client's request line (so the client's
// Write succeeds) and then invokes handle with the live conn. handle is
// responsible for whatever bytes go back (or not) and for closing.
func startRawSigner(t *testing.T, handle func(c rawConn)) (path string, stop func()) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "raw.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				// Drain the request line so the client's Write completes
				// before we exercise the response side.
				br := bufio.NewReader(c)
				_, _ = br.ReadBytes('\n')
				handle(c)
			}(conn)
		}
	}()
	return path, func() {
		_ = ln.Close()
		wg.Wait()
	}
}
