package sign_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// TestSign_PermissionDenied_MapsToSignerPermission asserts that a dial
// refused with EACCES — exactly what a user whose shell is not yet in
// the sshgatesigner group hits against the 0660 socket — maps to the
// ErrSignerPermission sentinel (NOT ErrUnreachable). The actionable
// "log out and back in" guidance hangs off this sentinel (audit item B).
//
// We reproduce EACCES by binding a real listener and then chmod'ing the
// socket file to 0000; a non-root caller is then refused at connect.
func TestSign_PermissionDenied_MapsToSignerPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses unix-socket permission checks")
	}
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	defer func() {
		_ = ln.Close()
		wg.Wait()
	}()

	// Strip all access bits so a non-root connect() is refused (EACCES).
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod 0000: %v", err)
	}
	// Sanity: confirm the kernel actually refuses us with a permission
	// error on this platform; if it does not (e.g. unusual FS/container),
	// skip rather than assert a false negative.
	if conn, derr := net.DialTimeout("unix", path, 500*time.Millisecond); derr == nil {
		_ = conn.Close()
		t.Skip("platform did not enforce socket permission on connect; cannot exercise EACCES path")
	} else if !errors.Is(derr, os.ErrPermission) {
		t.Skipf("dial error was not a permission error on this platform: %v", derr)
	}

	c := &sign.Client{SocketPath: path, Timeout: 500 * time.Millisecond}
	_, err = c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "rm /x", TTLSec: 60}})
	if err == nil {
		t.Fatal("expected an error dialing a 0000 socket, got nil")
	}
	if !errors.Is(err, sign.ErrSignerPermission) {
		t.Errorf("err = %v; want ErrSignerPermission", err)
	}
	// Must NOT be mis-classified as the dead-daemon sentinel.
	if errors.Is(err, sign.ErrUnreachable) {
		t.Errorf("err = %v; permission-denied was mis-classified as ErrUnreachable", err)
	}
}

// TestSign_GenericDialFailure_MapsToUnreachable locks the other side of
// the distinction: a missing socket (no daemon) is ErrUnreachable, NOT
// ErrSignerPermission.
func TestSign_GenericDialFailure_MapsToUnreachable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "absent.sock") // never created

	c := &sign.Client{SocketPath: path, Timeout: 500 * time.Millisecond}
	_, err := c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("expected an error dialing a missing socket, got nil")
	}
	if !errors.Is(err, sign.ErrUnreachable) {
		t.Errorf("err = %v; want ErrUnreachable", err)
	}
	if errors.Is(err, sign.ErrSignerPermission) {
		t.Errorf("err = %v; missing-socket was mis-classified as ErrSignerPermission", err)
	}
}
