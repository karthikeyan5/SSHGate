package sign_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// fakeVelsigner accepts one connection, reads a JSON line, and writes
// whatever response the test pre-arranged. Tests stop the server via
// the returned cancel func.
type fakeVelsigner struct {
	t        *testing.T
	respond  func(req map[string]any) string
	delay    time.Duration
	gotReqCh chan map[string]any
}

func startFakeVelsigner(t *testing.T, respond func(req map[string]any) string) (path string, gotReqCh chan map[string]any, stop func()) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gotReqCh = make(chan map[string]any, 8)
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
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				line, err := br.ReadBytes('\n')
				if err != nil && err != io.EOF {
					return
				}
				var req map[string]any
				_ = json.Unmarshal(line, &req)
				gotReqCh <- req
				resp := respond(req)
				if resp != "" {
					_, _ = c.Write([]byte(resp + "\n"))
				}
				// If respond returns "" (empty), drop without writing —
				// simulates a stuck/half-closed server.
			}(conn)
		}
	}()
	return path, gotReqCh, func() {
		_ = ln.Close()
		wg.Wait()
	}
}

func TestSign_Approved(t *testing.T) {
	t.Parallel()
	path, gotReq, stop := startFakeVelsigner(t, func(req map[string]any) string {
		return `{"request_id":"r1","status":"approved","signatures":[{"cmd":"rm /tmp/x","sig":"VELGATE_SIG:abc:def"}]}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	out, err := c.Sign(context.Background(), "r1", []sign.CmdReq{
		{Server: "prod-db", Cmd: "rm /tmp/x", TTLSec: 60},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(out) != 1 || out[0].Cmd != "rm /tmp/x" || out[0].Sig != "VELGATE_SIG:abc:def" {
		t.Errorf("got %+v", out)
	}
	select {
	case req := <-gotReq:
		if req["kind"] != "sign" {
			t.Errorf("req.kind = %v; want sign", req["kind"])
		}
		if req["request_id"] != "r1" {
			t.Errorf("req.request_id = %v", req["request_id"])
		}
	default:
		t.Error("server received no request")
	}
}

func TestSign_Denied(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeVelsigner(t, func(req map[string]any) string {
		return `{"request_id":"r1","status":"denied"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "rm -rf /", TTLSec: 60}})
	if !errors.Is(err, sign.ErrDenied) {
		t.Errorf("err = %v; want ErrDenied", err)
	}
}

func TestSign_Timeout(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeVelsigner(t, func(req map[string]any) string {
		return `{"request_id":"r1","status":"timeout"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if !errors.Is(err, sign.ErrTimeout) {
		t.Errorf("err = %v; want ErrTimeout", err)
	}
}

func TestSign_UnreachableMissingSocket(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.sock")
	c := &sign.Client{SocketPath: path, Timeout: 500 * time.Millisecond}
	_, err := c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if !errors.Is(err, sign.ErrUnreachable) {
		t.Errorf("err = %v; want ErrUnreachable", err)
	}
}

func TestSign_ErrorStatus(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeVelsigner(t, func(req map[string]any) string {
		return `{"request_id":"r1","status":"error","error":"bad request"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want non-nil for error status")
	}
	// Should NOT be denied/timeout — it's a structural error.
	if errors.Is(err, sign.ErrDenied) || errors.Is(err, sign.ErrTimeout) || errors.Is(err, sign.ErrUnreachable) {
		t.Errorf("error mis-classified: %v", err)
	}
}

func TestSign_MalformedResponse(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeVelsigner(t, func(req map[string]any) string {
		return `not-json-at-all`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want non-nil for malformed response")
	}
}

func TestSign_RequestIDMismatch(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeVelsigner(t, func(req map[string]any) string {
		return `{"request_id":"other","status":"approved","signatures":[]}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want non-nil for mismatched request_id")
	}
}

func TestSign_ContextCancelled(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeVelsigner(t, func(req map[string]any) string {
		// Sleep longer than the test's ctx timeout — we want the
		// dialed connection's read to be aborted by ctx cancellation.
		time.Sleep(2 * time.Second)
		return `{"request_id":"r1","status":"approved","signatures":[]}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := c.Sign(ctx, "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want non-nil when ctx cancelled")
	}
}
