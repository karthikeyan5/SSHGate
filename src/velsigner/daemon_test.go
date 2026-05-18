package velsigner_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/common"
	"github.com/karthikeyan5/sshgate/src/velsigner"
	"github.com/karthikeyan5/sshgate/src/velsigner/backend"
)

// memConn is an in-memory full-duplex pipe wrapper with separate
// request/response buffers. Suitable for unit-testing Daemon.
// HandleSignRequest without spinning a real socket.
type memConn struct {
	in  *bytes.Reader
	out *bytes.Buffer
}

func (m *memConn) Read(p []byte) (int, error)  { return m.in.Read(p) }
func (m *memConn) Write(p []byte) (int, error) { return m.out.Write(p) }

func newDaemon(t *testing.T, bk backend.Backend) (*velsigner.Daemon, ed25519.PublicKey, *velsigner.AuditLog, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	audit, err := velsigner.OpenAuditLog(auditPath)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	d := &velsigner.Daemon{
		Key:     priv,
		Backend: bk,
		Audit:   audit,
		NowFunc: func() time.Time { return time.Unix(1000, 0) },
	}
	return d, pub, audit, auditPath
}

func TestDaemon_ApprovePath_SignaturesVerify(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, pub, audit, auditPath := newDaemon(t, mock)
	defer audit.Close()

	req := `{"kind":"sign","request_id":"r_a1","commands":[{"server":"prod","cmd":"systemctl restart nginx","ttl_seconds":60},{"server":"prod","cmd":"apt install -y certbot","ttl_seconds":60}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}

	// Pre-arrange approval so the daemon's Request call resolves
	// immediately when it reaches the backend.
	mock.Approve("r_a1", "karthi")

	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}

	var resp struct {
		RequestID  string `json:"request_id"`
		Status     string `json:"status"`
		Signatures []struct {
			Cmd string `json:"cmd"`
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal response: %v\nraw=%q", err, conn.out.String())
	}
	if resp.RequestID != "r_a1" {
		t.Errorf("RequestID = %q; want r_a1", resp.RequestID)
	}
	if resp.Status != "approved" {
		t.Fatalf("Status = %q; want approved", resp.Status)
	}
	if len(resp.Signatures) != 2 {
		t.Fatalf("got %d sigs; want 2", len(resp.Signatures))
	}

	// Each sig must verify with the public key.
	for i, s := range resp.Signatures {
		if !common.IsSigned(s.Sig) {
			t.Errorf("sig %d missing prefix: %q", i, s.Sig)
			continue
		}
		sig, payload, err := common.DecodeSigned(s.Sig)
		if err != nil {
			t.Errorf("decode sig %d: %v", i, err)
			continue
		}
		if payload.Cmd != s.Cmd {
			t.Errorf("payload cmd mismatch: %q vs %q", payload.Cmd, s.Cmd)
		}
		// Re-marshal payload to recover the exact bytes that were
		// signed (same trick velgate.VerifySigned uses).
		signedBytes, _ := json.Marshal(payload)
		if !ed25519.Verify(pub, signedBytes, sig) {
			t.Errorf("sig %d failed to verify", i)
		}
		// TS / Exp sanity: TS == NowFunc, Exp = TS + TTLSec.
		if payload.TS != 1000 {
			t.Errorf("payload.TS = %d; want 1000 (NowFunc)", payload.TS)
		}
		if payload.Exp-payload.TS != 60 {
			t.Errorf("exp - ts = %d; want 60", payload.Exp-payload.TS)
		}
		if payload.Nonce == "" {
			t.Errorf("payload.Nonce empty")
		}
	}

	// Audit event present.
	audit.Close() // flush + release
	got := readAudit(t, auditPath)
	if len(got) != 1 || got[0].Status != "approved" || got[0].RequestID != "r_a1" {
		t.Errorf("audit = %+v; want one approved event for r_a1", got)
	}
}

func TestDaemon_DenyPath(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath := newDaemon(t, mock)
	defer audit.Close()
	mock.Deny("r_d1")
	req := `{"kind":"sign","request_id":"r_d1","commands":[{"server":"prod","cmd":"rm /tmp/x","ttl_seconds":60}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}
	var resp struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "denied" || resp.RequestID != "r_d1" {
		t.Errorf("resp = %+v; want denied for r_d1", resp)
	}
	audit.Close()
	got := readAudit(t, auditPath)
	if len(got) != 1 || got[0].Status != "denied" {
		t.Errorf("audit = %+v; want one denied", got)
	}
}

func TestDaemon_TimeoutPath(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath := newDaemon(t, mock)
	defer audit.Close()
	mock.Timeout("r_t1")
	req := `{"kind":"sign","request_id":"r_t1","commands":[{"server":"prod","cmd":"reboot","ttl_seconds":60}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}
	var resp struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "timeout" {
		t.Errorf("Status = %q; want timeout", resp.Status)
	}
	audit.Close()
	got := readAudit(t, auditPath)
	if len(got) != 1 || got[0].Status != "timeout" {
		t.Errorf("audit = %+v; want one timeout", got)
	}
}

func TestDaemon_MalformedRequest(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath := newDaemon(t, mock)
	defer audit.Close()
	// Garbled JSON: missing closing brace, then newline.
	conn := &memConn{in: bytes.NewReader([]byte(`{"kind":"sign"`+"\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest unexpectedly returned err: %v", err)
	}
	var resp struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "error" {
		t.Errorf("Status = %q; want error; full=%+v", resp.Status, resp)
	}
	if resp.Error == "" {
		t.Errorf("Error field empty")
	}
	audit.Close()
	got := readAudit(t, auditPath)
	if len(got) != 1 || got[0].Status != "error" {
		t.Errorf("audit = %+v; want one error", got)
	}
}

func TestDaemon_ConcurrentRequestsDontCross(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, _ := newDaemon(t, mock)
	defer audit.Close()

	const N = 10
	// Pre-arrange all outcomes before launching the daemon calls so we
	// don't race on Approve-vs-Request ordering.
	for i := 0; i < N; i++ {
		mock.Approve(fmt.Sprintf("r_%d", i), "")
	}

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			req := fmt.Sprintf(`{"kind":"sign","request_id":"r_%d","commands":[{"server":"s","cmd":"echo %d","ttl_seconds":60}]}`+"\n", i, i)
			conn := &memConn{in: bytes.NewReader([]byte(req)), out: &bytes.Buffer{}}
			if err := d.HandleSignRequest(context.Background(), conn); err != nil {
				t.Errorf("req %d: %v", i, err)
				return
			}
			var resp struct {
				RequestID string `json:"request_id"`
				Status    string `json:"status"`
			}
			if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
				t.Errorf("req %d unmarshal: %v", i, err)
				return
			}
			want := fmt.Sprintf("r_%d", i)
			if resp.RequestID != want {
				t.Errorf("req %d: got RequestID %q; want %q", i, resp.RequestID, want)
			}
			if resp.Status != "approved" {
				t.Errorf("req %d: status %q; want approved", i, resp.Status)
			}
		}()
	}
	wg.Wait()
}

// readAudit re-opens the audit log file and parses all lines.
func readAudit(t *testing.T, path string) []velsigner.AuditEvent {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var out []velsigner.AuditEvent
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var ev velsigner.AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("bad audit line: %v\n%q", err, sc.Text())
		}
		out = append(out, ev)
	}
	return out
}
