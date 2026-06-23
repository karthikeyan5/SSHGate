package signer_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/signer"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// clock is a mutable test clock so a single test can advance time across
// a grant's expiry boundary. newDaemon pins a fixed clock; grant-expiry
// tests build the Daemon directly with this instead.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// newGrantDaemon builds a Daemon with the given backend and a mutable
// clock starting at base. Mirrors newDaemon's audit/key wiring.
func newGrantDaemon(t *testing.T, bk backend.Backend, base time.Time) (*signer.Daemon, ed25519.PublicKey, *signer.AuditLog, string, *clock) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	audit, err := signer.OpenAuditLog(auditPath)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	clk := &clock{t: base}
	d := &signer.Daemon{
		Key:     priv,
		Backend: bk,
		Audit:   audit,
		NowFunc: clk.now,
	}
	return d, pub, audit, auditPath, clk
}

// grantResp is the decoded request_grant response shape.
type grantResp struct {
	RequestID  string `json:"request_id"`
	Status     string `json:"status"`
	GrantID    string `json:"grant_id"`
	ExpiryUnix int64  `json:"expiry_unix"`
	Error      string `json:"error"`
}

// grantSignResp is the decoded sign response shape (with the approver carried
// in the audit, not the wire; we read approver from the audit log).
type grantSignResp struct {
	RequestID  string `json:"request_id"`
	Status     string `json:"status"`
	Signatures []struct {
		Cmd string `json:"cmd"`
		Sig string `json:"sig"`
	} `json:"signatures"`
	Error string `json:"error"`
}

// createGrant drives the real request_grant path through the daemon and
// returns the decoded response. The backend approval for reqID must be
// pre-armed by the caller (e.g. mock.Approve(reqID, "karthi")).
func createGrant(t *testing.T, d *signer.Daemon, reqID, alias, scope string, commands []string, durationSec int64) grantResp {
	t.Helper()
	body := map[string]any{
		"kind":             "request_grant",
		"request_id":       reqID,
		"alias":            alias,
		"scope":            scope,
		"duration_seconds": durationSec,
	}
	if len(commands) > 0 {
		body["commands"] = commands
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal grant req: %v", err)
	}
	conn := &memConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest(request_grant): %v", err)
	}
	var resp grantResp
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode grant resp: %v\nraw=%q", err, conn.out.String())
	}
	return resp
}

// signOne drives a single-command sign request and returns the decoded
// response. host/reveal/reason are optional.
func signOne(t *testing.T, d *signer.Daemon, reqID, alias, cmd, host string, reveal bool, reason string) grantSignResp {
	t.Helper()
	cmdObj := map[string]any{
		"server":      alias,
		"cmd":         cmd,
		"ttl_seconds": 60,
	}
	if host != "" {
		cmdObj["host"] = host
	}
	if reveal {
		cmdObj["reveal"] = true
		cmdObj["reason"] = reason
	}
	body := map[string]any{
		"kind":       "sign",
		"request_id": reqID,
		"commands":   []any{cmdObj},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal sign req: %v", err)
	}
	conn := &memConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest(sign): %v", err)
	}
	var resp grantSignResp
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode sign resp: %v\nraw=%q", err, conn.out.String())
	}
	return resp
}

// approverFor scans the audit log for the row matching reqID and returns
// its approved_by — this is how we distinguish an auto-signed grant
// ("grant:<id>") from a human-prompted approval ("karthi").
func approverFor(t *testing.T, auditPath, reqID string) string {
	t.Helper()
	for _, ev := range readAudit(t, auditPath) {
		if ev.RequestID == reqID {
			return ev.ApprovedBy
		}
	}
	t.Fatalf("no audit row for request_id %q", reqID)
	return ""
}

const grantHost = "SHA256:grantTestHostKeyFingerprintAAAAAAAAAAAAAAAA"

// TestGrant_ScopeAll_AutoSignsWithoutPrompt is the core auto-approve
// happy path: after a scope=all grant on an alias, a subsequent write on
// that alias auto-signs WITHOUT consulting the backend. We prove "no
// prompt" by leaving the sign request's reqID UNARMED on the mock — if
// the daemon prompted, the unarmed channel would never resolve and the
// test would hang to the package timeout (a loud failure). The approver
// in the audit log is "grant:<id>", confirming the grant path.
func TestGrant_ScopeAll_AutoSignsWithoutPrompt(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, pub, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_req", "karthi")
	gr := createGrant(t, d, "g_req", "prod", "all", nil, 3600)
	if gr.Status != "approved" {
		t.Fatalf("grant status = %q; want approved (err=%q)", gr.Status, gr.Error)
	}
	if gr.GrantID == "" {
		t.Fatal("grant_id empty on approval")
	}

	// Sign reqID is NOT armed — only a grant auto-approve can resolve it.
	resp := signOne(t, d, "s_auto", "prod", "systemctl restart nginx", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("sign status = %q; want approved", resp.Status)
	}
	if len(resp.Signatures) != 1 {
		t.Fatalf("got %d sigs; want 1", len(resp.Signatures))
	}
	// The auto-signed signature must verify under the daemon key.
	sig, payload, err := sigwire.DecodeSigned(resp.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	signedBytes, _ := json.Marshal(payload)
	if !ed25519.Verify(pub, signedBytes, sig) {
		t.Error("auto-signed signature does not verify")
	}
	if payload.Host != grantHost {
		t.Errorf("payload.Host = %q; want %q (host-binding preserved under a grant)", payload.Host, grantHost)
	}
	// Audit proves the grant path (not a human prompt).
	if got := approverFor(t, auditPath, "s_auto"); !strings.HasPrefix(got, "grant:") {
		t.Errorf("approved_by = %q; want grant:<id> (auto-approved)", got)
	}
}

// TestGrant_ScopeCommands_ExactMatchOnly pins exact-string scope: the
// exact command auto-signs; a near-miss (extra arg) and a different alias
// both fall through to the human prompt.
func TestGrant_ScopeCommands_ExactMatchOnly(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_req", "karthi")
	gr := createGrant(t, d, "g_req", "src", "commands", []string{"systemctl stop app"}, 3600)
	if gr.Status != "approved" {
		t.Fatalf("grant status = %q; want approved", gr.Status)
	}

	// Exact match → auto-signs (reqID unarmed, only grant can resolve it).
	resp := signOne(t, d, "s_exact", "src", "systemctl stop app", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("exact-match sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_exact"); !strings.HasPrefix(got, "grant:") {
		t.Errorf("exact match approved_by = %q; want grant:<id>", got)
	}

	// Near-miss (extra arg) → must prompt. Arm the reqID so the prompt
	// resolves, then assert the approver is the HUMAN, not the grant.
	mock.Approve("s_near", "karthi")
	resp = signOne(t, d, "s_near", "src", "systemctl stop app --now", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("near-miss sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_near"); got != "karthi" {
		t.Errorf("near-miss approved_by = %q; want human \"karthi\" (NOT auto-signed)", got)
	}

	// Different alias, exact command → must prompt (grant is per-alias).
	mock.Approve("s_otheralias", "karthi")
	resp = signOne(t, d, "s_otheralias", "other", "systemctl stop app", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("other-alias sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_otheralias"); got != "karthi" {
		t.Errorf("other-alias approved_by = %q; want human (grant is per-alias)", got)
	}
}

// TestGrant_RevealNeverAutoSigned is the critical security test: even
// under a scope=all grant, a SECRET-REVEAL request must ALWAYS prompt the
// human — a grant must never auto-sign a reveal. We arm the human prompt
// and assert the approver is the human (not the grant) AND that the
// signed payload still carries reveal=true.
func TestGrant_RevealNeverAutoSigned(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_req", "karthi")
	gr := createGrant(t, d, "g_req", "prod", "all", nil, 3600)
	if gr.Status != "approved" {
		t.Fatalf("grant status = %q; want approved", gr.Status)
	}

	// A reveal on the SAME alias the scope=all grant covers. It must
	// prompt — so arm the human approval; if the grant auto-signed it,
	// the approver would be "grant:..." instead.
	mock.Approve("s_reveal", "karthi")
	resp := signOne(t, d, "s_reveal", "prod", "cat /etc/secret.env", grantHost, true, "debugging auth")
	if resp.Status != "approved" {
		t.Fatalf("reveal sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_reveal"); got != "karthi" {
		t.Fatalf("reveal approved_by = %q; want human \"karthi\" — a grant MUST NOT auto-sign a reveal", got)
	}
	// The signed payload must still carry reveal=true (the human approved
	// a reveal, not a plain write).
	_, payload, err := sigwire.DecodeSigned(resp.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !payload.Reveal {
		t.Error("payload.Reveal = false; want true (reveal must survive the prompt path)")
	}
}

// TestGrant_CrossServer pins that a grant for alias X never auto-signs a
// command aimed at alias Y.
func TestGrant_CrossServer(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_req", "karthi")
	createGrant(t, d, "g_req", "X", "all", nil, 3600)

	mock.Approve("s_y", "karthi")
	resp := signOne(t, d, "s_y", "Y", "rm -rf /tmp/x", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("cross-server sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_y"); got != "karthi" {
		t.Errorf("cross-server approved_by = %q; want human (grant for X must not cover Y)", got)
	}
}

// TestGrant_Expired pins that once a grant's window elapses, a matching
// command prompts again (the signer never auto-signs past expiry).
func TestGrant_Expired(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	base := time.Unix(1000, 0)
	d, _, audit, auditPath, clk := newGrantDaemon(t, mock, base)
	defer audit.Close()

	// 1h grant minted at base.
	mock.Approve("g_req", "karthi")
	gr := createGrant(t, d, "g_req", "prod", "all", nil, 3600)
	if gr.Status != "approved" {
		t.Fatalf("grant status = %q; want approved", gr.Status)
	}

	// Advance past expiry (base + 1h + 1s).
	clk.set(base.Add(3601 * time.Second))

	mock.Approve("s_expired", "karthi")
	resp := signOne(t, d, "s_expired", "prod", "systemctl restart nginx", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("post-expiry sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_expired"); got != "karthi" {
		t.Errorf("post-expiry approved_by = %q; want human (expired grant must not auto-sign)", got)
	}
}

// TestGrant_FreshDaemonHasNoGrants pins the in-memory / restart-drops
// property: a daemon with no grant created auto-signs nothing — every
// write prompts.
func TestGrant_FreshDaemonHasNoGrants(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("s_fresh", "karthi")
	resp := signOne(t, d, "s_fresh", "prod", "systemctl restart nginx", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("fresh-daemon sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_fresh"); got != "karthi" {
		t.Errorf("fresh-daemon approved_by = %q; want human (no grants exist by default)", got)
	}
}

// TestGrant_DeniedNotStored pins that a backend-denied request_grant
// stores no grant — a subsequent matching write still prompts.
func TestGrant_DeniedNotStored(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Deny("g_req")
	gr := createGrant(t, d, "g_req", "prod", "all", nil, 3600)
	if gr.Status != "denied" {
		t.Fatalf("grant status = %q; want denied", gr.Status)
	}
	if gr.GrantID != "" {
		t.Errorf("grant_id = %q; want empty on denial", gr.GrantID)
	}

	mock.Approve("s_afterdeny", "karthi")
	resp := signOne(t, d, "s_afterdeny", "prod", "systemctl restart nginx", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_afterdeny"); got != "karthi" {
		t.Errorf("approved_by = %q; want human (denied grant must store nothing)", got)
	}
}

// TestGrant_CreationValidation is the request_grant validation table:
// duration ceiling, non-positive duration, bad scope, empty command set.
func TestGrant_CreationValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		scope       string
		commands    []string
		durationSec int64
		wantErrSub  string
	}{
		{"duration over 24h", "all", nil, 86401, "24h"},
		{"duration zero", "all", nil, 0, "duration_seconds must be > 0"},
		{"duration negative", "all", nil, -1, "duration_seconds must be > 0"},
		{"invalid scope", "everything", nil, 3600, "invalid scope"},
		{"commands scope empty list", "commands", nil, 3600, "requires a non-empty commands list"},
		{"all scope with commands", "all", []string{"ls"}, 3600, "must not carry a commands list"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mock := backend.NewMockBackend()
			d, _, audit, _, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
			defer audit.Close()

			// No mock arming — these must be rejected BEFORE the backend.
			gr := createGrant(t, d, "g_bad", "prod", tc.scope, tc.commands, tc.durationSec)
			if gr.Status != "error" {
				t.Fatalf("status = %q; want error (%s)", gr.Status, tc.name)
			}
			if !strings.Contains(gr.Error, tc.wantErrSub) {
				t.Errorf("error = %q; want substring %q", gr.Error, tc.wantErrSub)
			}
		})
	}
}

// TestGrant_BoundaryExact24hAllowed pins the inclusive ceiling: a grant of
// exactly 24h (86400s) is allowed; the 86401 rejection above is a true
// boundary, not an off-by-one.
func TestGrant_BoundaryExact24hAllowed(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, _, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_24h", "karthi")
	gr := createGrant(t, d, "g_24h", "prod", "all", nil, 86400)
	if gr.Status != "approved" {
		t.Fatalf("status = %q; want approved (exactly 24h is allowed) err=%q", gr.Status, gr.Error)
	}
}

// TestGrant_Revoke pins that revoke_grant drops the grant: a matching
// write that auto-signed before revoke prompts again after.
func TestGrant_Revoke(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_req", "karthi")
	createGrant(t, d, "g_req", "prod", "all", nil, 3600)

	// Before revoke: auto-signs (unarmed sign reqID).
	resp := signOne(t, d, "s_before", "prod", "systemctl restart nginx", grantHost, false, "")
	if got := approverFor(t, auditPath, "s_before"); !strings.HasPrefix(got, "grant:") {
		t.Fatalf("pre-revoke approved_by = %q; want grant:<id>", got)
	}
	_ = resp

	// Revoke (no approval needed; never touches the backend).
	revBody := map[string]any{"kind": "revoke_grant", "request_id": "rv_req", "alias": "prod"}
	raw, _ := json.Marshal(revBody)
	conn := &memConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest(revoke_grant): %v", err)
	}
	var rv revokeGrantResp
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &rv); err != nil {
		t.Fatalf("decode revoke resp: %v\nraw=%q", err, conn.out.String())
	}
	if rv.Status != "approved" {
		t.Fatalf("revoke status = %q; want approved", rv.Status)
	}

	// After revoke: must prompt again.
	mock.Approve("s_after", "karthi")
	resp = signOne(t, d, "s_after", "prod", "systemctl restart nginx", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("post-revoke sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_after"); got != "karthi" {
		t.Errorf("post-revoke approved_by = %q; want human (grant was revoked)", got)
	}
}

// revokeGrantResp is the decoded revoke_grant response shape.
type revokeGrantResp struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	Error     string `json:"error"`
}

// TestGrant_ByteIdenticalToHumanApproved pins the gate-unchanged
// invariant: an auto-signed payload and a human-approved payload for the
// SAME (command, host, ttl) are identical in every field except the
// random Nonce, and both verify under the daemon key. This is what lets
// the gate stay completely unaware of grants.
func TestGrant_ByteIdenticalToHumanApproved(t *testing.T) {
	t.Parallel()
	base := time.Unix(1000, 0)

	// Human-approved sign (no grant).
	mock1 := backend.NewMockBackend()
	dH, pubH, auditH, _, _ := newGrantDaemon(t, mock1, base)
	defer auditH.Close()
	mock1.Approve("s_human", "karthi")
	human := signOne(t, dH, "s_human", "prod", "systemctl restart nginx", grantHost, false, "")
	if human.Status != "approved" {
		t.Fatalf("human sign status = %q; want approved", human.Status)
	}

	// Grant-auto-signed sign on a fresh daemon at the SAME clock.
	mock2 := backend.NewMockBackend()
	dG, pubG, auditG, auditPathG, _ := newGrantDaemon(t, mock2, base)
	defer auditG.Close()
	mock2.Approve("g_req", "karthi")
	createGrant(t, dG, "g_req", "prod", "all", nil, 3600)
	auto := signOne(t, dG, "s_auto", "prod", "systemctl restart nginx", grantHost, false, "")
	if auto.Status != "approved" {
		t.Fatalf("auto sign status = %q; want approved", auto.Status)
	}
	if got := approverFor(t, auditPathG, "s_auto"); !strings.HasPrefix(got, "grant:") {
		t.Fatalf("auto approved_by = %q; want grant:<id>", got)
	}

	_, ph, err := sigwire.DecodeSigned(human.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode human: %v", err)
	}
	_, pg, err := sigwire.DecodeSigned(auto.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode auto: %v", err)
	}

	if ph.Cmd != pg.Cmd {
		t.Errorf("Cmd differs: %q vs %q", ph.Cmd, pg.Cmd)
	}
	if ph.TS != pg.TS {
		t.Errorf("TS differs: %d vs %d", ph.TS, pg.TS)
	}
	if ph.Exp != pg.Exp {
		t.Errorf("Exp differs: %d vs %d", ph.Exp, pg.Exp)
	}
	if ph.Host != pg.Host {
		t.Errorf("Host differs: %q vs %q", ph.Host, pg.Host)
	}
	if ph.Reveal != pg.Reveal {
		t.Errorf("Reveal differs: %v vs %v", ph.Reveal, pg.Reveal)
	}
	// Nonce is the ONLY field expected to differ (independent randomness).
	if ph.Nonce == pg.Nonce {
		t.Error("Nonce identical across two signs; want independent random nonces")
	}
	// Both verify under their respective keys (the per-daemon keys differ,
	// but the payload SHAPE is identical — that's the invariant).
	hb, _ := json.Marshal(ph)
	if !ed25519.Verify(pubH, hb, mustSig(t, human.Signatures[0].Sig)) {
		t.Error("human signature does not verify")
	}
	gb, _ := json.Marshal(pg)
	if !ed25519.Verify(pubG, gb, mustSig(t, auto.Signatures[0].Sig)) {
		t.Error("auto signature does not verify")
	}
}

func mustSig(t *testing.T, wire string) []byte {
	t.Helper()
	sig, _, err := sigwire.DecodeSigned(wire)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	return sig
}
