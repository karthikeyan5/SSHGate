package sign

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// writeFailConn is a net.Conn whose Write always fails, so we can drive
// the Sign "sign: write" wrap deterministically. A single conn.Write of
// the (small) request body against a peer-closed real socket usually
// succeeds into the kernel buffer, so the failure is not reproducible
// without controlling the conn — hence the dialWithCtx seam.
type writeFailConn struct {
	closed chan struct{}
}

func newWriteFailConn() *writeFailConn { return &writeFailConn{closed: make(chan struct{})} }

var errWriteBoom = errors.New("boom: write refused")

func (w *writeFailConn) Read(b []byte) (int, error) {
	// Block until Close so the client never gets a phantom reply; in
	// practice Sign errors out on Write before ever reading.
	<-w.closed
	return 0, net.ErrClosed
}
func (w *writeFailConn) Write(b []byte) (int, error) { return 0, errWriteBoom }
func (w *writeFailConn) Close() error {
	select {
	case <-w.closed:
	default:
		close(w.closed)
	}
	return nil
}
func (w *writeFailConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (w *writeFailConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (w *writeFailConn) SetDeadline(t time.Time) error      { return nil }
func (w *writeFailConn) SetReadDeadline(t time.Time) error  { return nil }
func (w *writeFailConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "unix" }
func (dummyAddr) String() string  { return "fake" }

// TestSign_WriteFailure_WrapsSignWrite swaps the dialer (in-package
// test-only seam) for one returning a conn whose Write always fails,
// and asserts the error is wrapped as "sign: write" — proving the
// write-error branch, not a misclassified ctx/dial sentinel.
func TestSign_WriteFailure_WrapsSignWrite(t *testing.T) {
	orig := dialWithCtx
	t.Cleanup(func() { dialWithCtx = orig })
	dialWithCtx = func(ctx context.Context, path string) (net.Conn, error) {
		return newWriteFailConn(), nil
	}

	c := &Client{SocketPath: "/unused/by/the/fake/dialer", Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r1", []CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want a write failure")
	}
	if !strings.Contains(err.Error(), "sign: write") {
		t.Errorf("err = %q; want it to contain %q", err.Error(), "sign: write")
	}
	if !errors.Is(err, errWriteBoom) {
		t.Errorf("err = %v; want it to wrap the underlying write error", err)
	}
	// Not a transport-classification sentinel and not ctx-derived.
	if errors.Is(err, ErrUnreachable) || errors.Is(err, ErrSignerPermission) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("write failure mis-classified: %v", err)
	}
}
