package ssh_test

import (
	"context"
	cryptoed "crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	sshlib "golang.org/x/crypto/ssh"
	"go.uber.org/goleak"

	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

// TestMain runs goleak across the ssh-package test suite. The SSH
// client uses a per-call watcher goroutine; the in-process test
// server uses an accept loop and a per-connection goroutine. All of
// these are torn down by the time individual tests return.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// testServer is a minimal in-process SSH server that accepts a single
// public-key auth (matching authKey), opens at most one session per
// connection, executes the requested command via handler, and returns
// the handler's stdout/stderr/exit.
type testServer struct {
	listener net.Listener
	host     string
	port     int
	hostKey  sshlib.Signer
	authKey  sshlib.PublicKey
	handler  func(cmd string) (stdout, stderr []byte, exit int)
	wg       sync.WaitGroup
}

func newTestServer(t *testing.T, authKey sshlib.PublicKey, handler func(string) ([]byte, []byte, int)) *testServer {
	t.Helper()
	_, hostPriv, err := cryptoed.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := sshlib.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr := ln.Addr().(*net.TCPAddr)
	s := &testServer{
		listener: ln,
		host:     tcpAddr.IP.String(),
		port:     tcpAddr.Port,
		hostKey:  hostSigner,
		authKey:  authKey,
		handler:  handler,
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s
}

func (s *testServer) acceptLoop() {
	defer s.wg.Done()
	cfg := &sshlib.ServerConfig{
		PublicKeyCallback: func(conn sshlib.ConnMetadata, key sshlib.PublicKey) (*sshlib.Permissions, error) {
			if string(key.Marshal()) == string(s.authKey.Marshal()) {
				return &sshlib.Permissions{}, nil
			}
			return nil, errors.New("public key not authorized")
		},
	}
	cfg.AddHostKey(s.hostKey)

	var connWG sync.WaitGroup
	for {
		tcp, err := s.listener.Accept()
		if err != nil {
			connWG.Wait()
			return
		}
		connWG.Add(1)
		go func(c net.Conn) {
			defer connWG.Done()
			s.handleConn(c, cfg)
		}(tcp)
	}
}

func (s *testServer) handleConn(tcp net.Conn, cfg *sshlib.ServerConfig) {
	defer tcp.Close()
	sshConn, chans, reqs, err := sshlib.NewServerConn(tcp, cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go sshlib.DiscardRequests(reqs)

	var sessWG sync.WaitGroup
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(sshlib.UnknownChannelType, "unknown channel")
			continue
		}
		ch, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		sessWG.Add(1)
		go func(c sshlib.Channel, rs <-chan *sshlib.Request) {
			defer sessWG.Done()
			s.handleSession(c, rs)
		}(ch, requests)
	}
	sessWG.Wait()
}

func (s *testServer) handleSession(ch sshlib.Channel, requests <-chan *sshlib.Request) {
	defer ch.Close()
	for req := range requests {
		switch req.Type {
		case "exec":
			cmd := parseExecCmd(req.Payload)
			_ = req.Reply(true, nil)
			stdout, stderr, exit := s.handler(cmd)
			if len(stdout) > 0 {
				_, _ = ch.Write(stdout)
			}
			if len(stderr) > 0 {
				_, _ = ch.Stderr().Write(stderr)
			}
			// Sentinel exitNoStatus: tear the session down cleanly WITHOUT
			// sending an exit-status reply, so x/crypto/ssh surfaces an
			// *ExitMissingError on the client side. Exercises the signal-
			// terminated → exit=-1 mapping in Client.Run.
			if exit != exitNoStatus {
				status := struct {
					Status uint32
				}{Status: uint32(exit)}
				_, _ = ch.SendRequest("exit-status", false, sshlib.Marshal(&status))
			}
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// exitNoStatus is a test-only sentinel handler return value: the test
// server closes the session without sending an exit-status reply,
// reproducing a signal-terminated remote (x/crypto/ssh then returns an
// *ExitMissingError to the client).
const exitNoStatus = -999

// parseExecCmd parses the SSH "exec" request payload, which is a
// big-endian uint32 length followed by the command string.
func parseExecCmd(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if n < 0 || n > len(payload)-4 {
		return ""
	}
	return string(payload[4 : 4+n])
}

func (s *testServer) stop() {
	_ = s.listener.Close()
	s.wg.Wait()
}

// generateClientKey returns a fresh Ed25519 key written to a temp
// file (mode 0o600) and the corresponding ssh.PublicKey.
func generateClientKey(t *testing.T) (keyPath string, pub sshlib.PublicKey) {
	t.Helper()
	pubKey, priv, err := cryptoed.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := sshlib.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath = filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	pk, err := sshlib.NewPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	return keyPath, pk
}

func TestClient_Run_Echo(t *testing.T) {
	t.Parallel()
	keyPath, pub := generateClientKey(t)
	srv := newTestServer(t, pub, func(cmd string) ([]byte, []byte, int) {
		if cmd == "echo hello" {
			return []byte("hello\n"), nil, 0
		}
		return nil, []byte("unknown cmd\n"), 1
	})
	defer srv.stop()

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	c := &sshpkg.Client{KeyPath: keyPath, KnownHostsPath: khPath, Timeout: 5 * time.Second}
	stdout, stderr, exit, err := c.Run(context.Background(), srv.host, "tester", srv.port, "echo hello")
	if err != nil {
		t.Fatalf("Run: %v (stderr=%s)", err, stderr)
	}
	if string(stdout) != "hello\n" {
		t.Errorf("stdout = %q", stdout)
	}
	if exit != 0 {
		t.Errorf("exit = %d; want 0", exit)
	}
}

func TestClient_Run_NonZeroExit(t *testing.T) {
	t.Parallel()
	keyPath, pub := generateClientKey(t)
	srv := newTestServer(t, pub, func(cmd string) ([]byte, []byte, int) {
		return nil, []byte("boom\n"), 17
	})
	defer srv.stop()

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	c := &sshpkg.Client{KeyPath: keyPath, KnownHostsPath: khPath, Timeout: 5 * time.Second}
	stdout, stderr, exit, err := c.Run(context.Background(), srv.host, "tester", srv.port, "anything")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	_ = stdout
	if exit != 17 {
		t.Errorf("exit = %d; want 17", exit)
	}
	if !strings.Contains(string(stderr), "boom") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestClient_Run_BadKeyFails(t *testing.T) {
	t.Parallel()
	_, pub1 := generateClientKey(t)
	pub2KeyPath, _ := generateClientKey(t)
	srv := newTestServer(t, pub1, func(cmd string) ([]byte, []byte, int) {
		return []byte("should not run"), nil, 0
	})
	defer srv.stop()

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	c := &sshpkg.Client{KeyPath: pub2KeyPath, KnownHostsPath: khPath, Timeout: 5 * time.Second}
	_, _, _, err := c.Run(context.Background(), srv.host, "tester", srv.port, "anything")
	if err == nil {
		t.Fatal("Run with bad key returned nil; want error")
	}
}

func TestClient_Run_BadHostFails(t *testing.T) {
	t.Parallel()
	keyPath, _ := generateClientKey(t)
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	c := &sshpkg.Client{KeyPath: keyPath, KnownHostsPath: khPath, Timeout: 500 * time.Millisecond}
	_, _, _, err := c.Run(context.Background(), "127.0.0.1", "tester", 1, "anything")
	if err == nil {
		t.Fatal("Run with bad host returned nil; want error")
	}
}

func TestClient_Run_CtxCancelled(t *testing.T) {
	t.Parallel()
	keyPath, pub := generateClientKey(t)
	srv := newTestServer(t, pub, func(cmd string) ([]byte, []byte, int) {
		time.Sleep(2 * time.Second)
		return nil, nil, 0
	})
	defer srv.stop()

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	c := &sshpkg.Client{KeyPath: keyPath, KnownHostsPath: khPath, Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _, _, err := c.Run(ctx, srv.host, "tester", srv.port, "sleep")
	if err == nil {
		t.Fatal("Run with cancelled ctx returned nil; want error")
	}
}

// TestRun_CommandLongerThanTimeoutCompletes is a regression test
// pinning the documented behavior of Client.Timeout: it bounds only the
// dial + SSH handshake, NOT command execution. Client.Run clears the
// connection deadline immediately after the handshake (see client.go,
// SetDeadline(time.Time{})), so a command that runs LONGER than Timeout
// must still complete and return its output. This guards against a
// future contributor "fixing" the (now-corrected) docstring by making
// Timeout kill long-running commands.
func TestRun_CommandLongerThanTimeoutCompletes(t *testing.T) {
	t.Parallel()
	keyPath, pub := generateClientKey(t)
	const sleep = 3 * time.Second
	srv := newTestServer(t, pub, func(cmd string) ([]byte, []byte, int) {
		// Simulate a command that runs well past Timeout, e.g.
		// "sleep 3; echo done".
		time.Sleep(sleep)
		return []byte("done\n"), nil, 0
	})
	defer srv.stop()

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	// Short Timeout (1s) — far less than the 3s the command runs for.
	c := &sshpkg.Client{KeyPath: keyPath, KnownHostsPath: khPath, Timeout: 1 * time.Second}

	// No deadline on ctx: command execution is bounded by ctx, not by
	// Timeout, and we want it to run to completion.
	start := time.Now()
	stdout, stderr, exit, err := c.Run(context.Background(), srv.host, "tester", srv.port, "sleep 3; echo done")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v (stderr=%s) — command longer than Timeout should still succeed", err, stderr)
	}
	if elapsed < sleep {
		t.Errorf("Run returned after %v; expected it to wait the full %v command (Timeout must not bound exec)", elapsed, sleep)
	}
	if string(stdout) != "done\n" {
		t.Errorf("stdout = %q; want %q", stdout, "done\n")
	}
	if exit != 0 {
		t.Errorf("exit = %d; want 0", exit)
	}
}

func TestClient_Run_HostKeyMismatch(t *testing.T) {
	t.Parallel()
	keyPath, pub := generateClientKey(t)
	srv1 := newTestServer(t, pub, func(cmd string) ([]byte, []byte, int) {
		return []byte("ok\n"), nil, 0
	})
	host, port := srv1.host, srv1.port

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	c := &sshpkg.Client{KeyPath: keyPath, KnownHostsPath: khPath, Timeout: 5 * time.Second}
	if _, _, _, err := c.Run(context.Background(), host, "tester", port, "echo"); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	srv1.stop()

	srv2 := newTestServerOnPort(host, port, pub, func(cmd string) ([]byte, []byte, int) {
		return []byte("imposter"), nil, 0
	})
	if srv2 == nil {
		t.Skip("could not rebind to original port; mismatch test cannot run")
	}
	defer srv2.stop()
	_, _, _, err := c.Run(context.Background(), host, "tester", port, "echo")
	if err == nil {
		t.Fatal("Run after host-key change returned nil; want error")
	}
	if !errors.Is(err, sshpkg.ErrHostKeyChanged) && !strings.Contains(err.Error(), "host key") {
		t.Errorf("err did not surface host-key change: %v", err)
	}
}

// newTestServerOnPort tries to bind to a specific port. Returns nil
// on bind failure so the caller can skip.
func newTestServerOnPort(host string, port int, authKey sshlib.PublicKey, handler func(string) ([]byte, []byte, int)) *testServer {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil
	}
	_, hostPriv, _ := cryptoed.GenerateKey(rand.Reader)
	hostSigner, _ := sshlib.NewSignerFromKey(hostPriv)
	tcpAddr := ln.Addr().(*net.TCPAddr)
	s := &testServer{
		listener: ln,
		host:     tcpAddr.IP.String(),
		port:     tcpAddr.Port,
		hostKey:  hostSigner,
		authKey:  authKey,
		handler:  handler,
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s
}

func TestClient_Run_KeyFileMissing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := &sshpkg.Client{KeyPath: filepath.Join(dir, "nope"), KnownHostsPath: filepath.Join(dir, "kh"), Timeout: 1 * time.Second}
	_, _, _, err := c.Run(context.Background(), "127.0.0.1", "u", 22, "x")
	if err == nil {
		t.Fatal("missing key should error")
	}
}
