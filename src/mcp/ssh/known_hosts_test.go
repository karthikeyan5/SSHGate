package ssh_test

import (
	cryptorand "crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sshlib "golang.org/x/crypto/ssh"

	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

func makeHostKey(t *testing.T) sshlib.PublicKey {
	t.Helper()
	pub, _, err := cryptorand.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := sshlib.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func tcpAddr() net.Addr {
	a, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:22")
	return a
}

func TestTOFU_FirstContactAppends(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")
	key := makeHostKey(t)

	cb := sshpkg.TOFU(khPath)
	if err := cb("example.com:22", tcpAddr(), key); err != nil {
		t.Fatalf("first contact failed: %v", err)
	}
	body, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "example.com") {
		t.Errorf("known_hosts missing hostname: %s", body)
	}
	info, err := os.Stat(khPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("known_hosts mode = %#o; want 0600", perm)
	}
}

func TestTOFU_SubsequentMatchAccepts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")
	key := makeHostKey(t)

	cb := sshpkg.TOFU(khPath)
	if err := cb("example.com:22", tcpAddr(),key); err != nil {
		t.Fatal(err)
	}
	if err := cb("example.com:22", tcpAddr(),key); err != nil {
		t.Errorf("second contact: %v", err)
	}
}

func TestTOFU_MismatchRefuses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")
	k1 := makeHostKey(t)
	k2 := makeHostKey(t)

	cb := sshpkg.TOFU(khPath)
	if err := cb("example.com:22", tcpAddr(),k1); err != nil {
		t.Fatal(err)
	}
	err := cb("example.com:22", tcpAddr(),k2)
	if err == nil {
		t.Fatal("mismatch accepted; want error")
	}
	if !errors.Is(err, sshpkg.ErrHostKeyChanged) {
		t.Errorf("err = %v; want ErrHostKeyChanged", err)
	}
	if !strings.Contains(err.Error(), "SHA256:") {
		t.Errorf("err should include fingerprint: %v", err)
	}
}

func TestTOFU_CreatesDirIfMissing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	khPath := filepath.Join(dir, "deeper", "known_hosts")
	key := makeHostKey(t)

	cb := sshpkg.TOFU(khPath)
	if err := cb("example.com:22", tcpAddr(),key); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(khPath)
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("parent dir mode = %#o; want 0700", perm)
	}
}
