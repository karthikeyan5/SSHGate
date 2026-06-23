package sign_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// TestRequestGrant_SendsProtoVersion and TestRevokeGrant_SendsProtoVersion
// confirm F6: the MCP stamps sigwire.ProtoVersion on the grant/revoke
// requests it builds, mirroring the sign path.
func TestRequestGrant_SendsProtoVersion(t *testing.T) {
	t.Parallel()
	path, gotReq, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"g1","status":"approved","grant_id":"g_abc","expiry_unix":1700000000}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	if _, _, err := c.RequestGrant(context.Background(), "g1", "prod", "all", nil, 3600); err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	assertProtoVersion(t, gotReq)
}

func TestRevokeGrant_SendsProtoVersion(t *testing.T) {
	t.Parallel()
	path, gotReq, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"rv1","status":"approved"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	if err := c.RevokeGrant(context.Background(), "rv1", "prod"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	assertProtoVersion(t, gotReq)
}

func assertProtoVersion(t *testing.T, gotReq chan map[string]any) {
	t.Helper()
	select {
	case req := <-gotReq:
		pv, ok := req["proto_version"].(float64)
		if !ok {
			t.Fatalf("proto_version missing/!number on the wire: %v", req["proto_version"])
		}
		if int(pv) != sigwire.ProtoVersion {
			t.Errorf("proto_version = %d; want %d", int(pv), sigwire.ProtoVersion)
		}
	case <-time.After(time.Second):
		t.Fatal("fake signer did not receive the request")
	}
}

func TestRequestGrant_Approved(t *testing.T) {
	t.Parallel()
	path, gotReq, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"g1","status":"approved","grant_id":"g_abc","expiry_unix":1700000000}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	gid, exp, err := c.RequestGrant(context.Background(), "g1", "prod", "all", nil, 3600)
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if gid != "g_abc" {
		t.Errorf("grant_id = %q; want g_abc", gid)
	}
	if exp != 1700000000 {
		t.Errorf("expiry = %d; want 1700000000", exp)
	}
	select {
	case req := <-gotReq:
		if req["kind"] != "request_grant" {
			t.Errorf("kind = %v; want request_grant", req["kind"])
		}
		if req["alias"] != "prod" {
			t.Errorf("alias = %v; want prod", req["alias"])
		}
		if req["scope"] != "all" {
			t.Errorf("scope = %v; want all", req["scope"])
		}
		// JSON numbers decode to float64 in a map[string]any.
		if req["duration_seconds"].(float64) != 3600 {
			t.Errorf("duration_seconds = %v; want 3600", req["duration_seconds"])
		}
	case <-time.After(time.Second):
		t.Fatal("fake signer did not receive the request")
	}
}

func TestRequestGrant_ScopeCommandsCarriesList(t *testing.T) {
	t.Parallel()
	path, gotReq, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"g2","status":"approved","grant_id":"g_xyz","expiry_unix":1700000123}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, _, err := c.RequestGrant(context.Background(), "g2", "src", "commands", []string{"systemctl stop app", "tar czf bak.tgz /data"}, 7200)
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	select {
	case req := <-gotReq:
		if req["scope"] != "commands" {
			t.Errorf("scope = %v; want commands", req["scope"])
		}
		cmds, ok := req["commands"].([]any)
		if !ok || len(cmds) != 2 || cmds[0] != "systemctl stop app" {
			t.Errorf("commands = %v; want the 2-entry list", req["commands"])
		}
	case <-time.After(time.Second):
		t.Fatal("fake signer did not receive the request")
	}
}

func TestRequestGrant_Denied(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"g3","status":"denied"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, _, err := c.RequestGrant(context.Background(), "g3", "prod", "all", nil, 3600)
	if !errors.Is(err, sign.ErrDenied) {
		t.Errorf("err = %v; want ErrDenied", err)
	}
}

func TestRequestGrant_DaemonError(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"g4","status":"error","error":"duration_seconds 90000 exceeds the 24h grant ceiling (86400)"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, _, err := c.RequestGrant(context.Background(), "g4", "prod", "all", nil, 90000)
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, sign.ErrDenied) || errors.Is(err, sign.ErrTimeout) {
		t.Errorf("err = %v; want a plain daemon error (not a sentinel)", err)
	}
}

func TestRevokeGrant_Approved(t *testing.T) {
	t.Parallel()
	path, gotReq, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"rv1","status":"approved"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	if err := c.RevokeGrant(context.Background(), "rv1", "prod"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	select {
	case req := <-gotReq:
		if req["kind"] != "revoke_grant" {
			t.Errorf("kind = %v; want revoke_grant", req["kind"])
		}
		if req["alias"] != "prod" {
			t.Errorf("alias = %v; want prod", req["alias"])
		}
	case <-time.After(time.Second):
		t.Fatal("fake signer did not receive the request")
	}
}

func TestRequestGrant_EmptyRequestID(t *testing.T) {
	t.Parallel()
	c := &sign.Client{SocketPath: "/nonexistent", Timeout: time.Second}
	if _, _, err := c.RequestGrant(context.Background(), "", "prod", "all", nil, 3600); err == nil {
		t.Error("expected error for empty requestID")
	}
}

// TestRequestGrant_EmptyRequestIDErrorSurfacesReason is the F3 mirror of
// the merged Sign 2b fix: a daemon error response with an EMPTY request_id
// (a malformed request, or a failure reported before the id is echoed)
// must surface the daemon's real reason from resp.Error, NOT the opaque
// `response request_id "" != "g_..."` correlation-mismatch string.
func TestRequestGrant_EmptyRequestIDErrorSurfacesReason(t *testing.T) {
	t.Parallel()
	const reason = "backend: telegram send: bot<REDACTED> failed"
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"","status":"error","error":"` + reason + `"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, _, err := c.RequestGrant(context.Background(), "g_real", "prod", "all", nil, 3600)
	if err == nil {
		t.Fatal("err is nil; want the daemon's error reason surfaced")
	}
	msg := err.Error()
	if !strings.Contains(msg, reason) {
		t.Errorf("error did not surface daemon reason %q; got: %v", reason, msg)
	}
	if strings.Contains(msg, "request_id") && strings.Contains(msg, "!=") {
		t.Errorf("error mis-reported as a request_id correlation mismatch instead of the real reason: %v", msg)
	}
	if errors.Is(err, sign.ErrDenied) || errors.Is(err, sign.ErrTimeout) || errors.Is(err, sign.ErrUnreachable) {
		t.Errorf("error mis-classified: %v", err)
	}
}

// TestRequestGrant_EmptyRequestIDErrorNoDetail covers the empty-id error
// response with an empty Error field: still must not surface the opaque
// correlation-mismatch string.
func TestRequestGrant_EmptyRequestIDErrorNoDetail(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"","status":"error","error":""}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, _, err := c.RequestGrant(context.Background(), "g_real", "prod", "all", nil, 3600)
	if err == nil {
		t.Fatal("err is nil; want a daemon-error result")
	}
	if msg := err.Error(); strings.Contains(msg, "request_id") && strings.Contains(msg, "!=") {
		t.Errorf("empty-detail daemon error mis-reported as a correlation mismatch: %v", msg)
	}
}

// TestRequestGrant_NonEmptyMismatchStillErrors confirms F3 does NOT weaken
// the correlation guarantee: a NON-EMPTY request_id that does not match the
// one we sent is still a true correlation error. status is "approved" here
// to prove the id check still fires before the status switch for a
// non-empty id.
func TestRequestGrant_NonEmptyMismatchStillErrors(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"g_other","status":"approved","grant_id":"x","expiry_unix":1}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, _, err := c.RequestGrant(context.Background(), "g_real", "prod", "all", nil, 3600)
	if err == nil {
		t.Fatal("err is nil; want a correlation mismatch for a non-empty mismatched request_id")
	}
	if msg := err.Error(); !(strings.Contains(msg, "request_id") && strings.Contains(msg, "!=")) {
		t.Errorf("non-empty mismatched request_id should surface a correlation mismatch; got: %v", msg)
	}
}

// TestRevokeGrant_EmptyRequestIDErrorSurfacesReason mirrors the F3 fix on
// the RevokeGrant path.
func TestRevokeGrant_EmptyRequestIDErrorSurfacesReason(t *testing.T) {
	t.Parallel()
	const reason = "malformed request: invalid character"
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"","status":"error","error":"` + reason + `"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	err := c.RevokeGrant(context.Background(), "rv_real", "prod")
	if err == nil {
		t.Fatal("err is nil; want the daemon's error reason surfaced")
	}
	msg := err.Error()
	if !strings.Contains(msg, reason) {
		t.Errorf("error did not surface daemon reason %q; got: %v", reason, msg)
	}
	if strings.Contains(msg, "request_id") && strings.Contains(msg, "!=") {
		t.Errorf("error mis-reported as a request_id correlation mismatch instead of the real reason: %v", msg)
	}
	if errors.Is(err, sign.ErrDenied) || errors.Is(err, sign.ErrTimeout) || errors.Is(err, sign.ErrUnreachable) {
		t.Errorf("error mis-classified: %v", err)
	}
}

// TestRevokeGrant_EmptyRequestIDErrorNoDetail covers the empty-id revoke
// error with no detail.
func TestRevokeGrant_EmptyRequestIDErrorNoDetail(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"","status":"error","error":""}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	err := c.RevokeGrant(context.Background(), "rv_real", "prod")
	if err == nil {
		t.Fatal("err is nil; want a daemon-error result")
	}
	if msg := err.Error(); strings.Contains(msg, "request_id") && strings.Contains(msg, "!=") {
		t.Errorf("empty-detail daemon error mis-reported as a correlation mismatch: %v", msg)
	}
}

// TestRevokeGrant_NonEmptyMismatchStillErrors confirms the correlation
// guarantee is preserved for RevokeGrant: a non-empty mismatched id still
// errors as a correlation mismatch.
func TestRevokeGrant_NonEmptyMismatchStillErrors(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"rv_other","status":"approved"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	err := c.RevokeGrant(context.Background(), "rv_real", "prod")
	if err == nil {
		t.Fatal("err is nil; want a correlation mismatch for a non-empty mismatched request_id")
	}
	if msg := err.Error(); !(strings.Contains(msg, "request_id") && strings.Contains(msg, "!=")) {
		t.Errorf("non-empty mismatched request_id should surface a correlation mismatch; got: %v", msg)
	}
}

// TestListGrants_RoundTrip pins the read-only list_grants round-trip:
// request_id correlation + parse of the returned grant rows, and that the
// request carries proto_version + kind=list_grants + the alias filter.
func TestListGrants_RoundTrip(t *testing.T) {
	t.Parallel()
	path, gotReq, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"l1","status":"ok","proto_version":` + itoa(sigwire.ProtoVersion) +
			`,"grants":[{"alias":"prod","scope":"commands","commands":["systemctl restart nginx"],"grant_id":"g_abc","expiry_unix":1700000000}]}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	grants, err := c.ListGrants(context.Background(), "l1", "prod")
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("got %d grants; want 1", len(grants))
	}
	g := grants[0]
	if g.Alias != "prod" || g.Scope != "commands" || g.GrantID != "g_abc" || g.ExpiryUnix != 1700000000 {
		t.Errorf("grant parsed wrong: %+v", g)
	}
	if len(g.Commands) != 1 || g.Commands[0] != "systemctl restart nginx" {
		t.Errorf("commands = %v; want [systemctl restart nginx]", g.Commands)
	}
	select {
	case req := <-gotReq:
		if req["kind"] != "list_grants" {
			t.Errorf("kind = %v; want list_grants", req["kind"])
		}
		if req["alias"] != "prod" {
			t.Errorf("alias = %v; want prod", req["alias"])
		}
		pv, ok := req["proto_version"].(float64)
		if !ok || int(pv) != sigwire.ProtoVersion {
			t.Errorf("proto_version = %v; want %d", req["proto_version"], sigwire.ProtoVersion)
		}
	case <-time.After(time.Second):
		t.Fatal("fake signer did not receive the request")
	}
}

// TestListGrants_EmptyAliasOmitsField pins that an empty alias is NOT sent
// on the wire (omitempty), so the daemon reports all live grants.
func TestListGrants_EmptyAliasOmitsField(t *testing.T) {
	t.Parallel()
	path, gotReq, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"l2","status":"ok","grants":[]}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	grants, err := c.ListGrants(context.Background(), "l2", "")
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("got %d grants; want 0", len(grants))
	}
	select {
	case req := <-gotReq:
		if _, present := req["alias"]; present {
			t.Errorf("alias key present on the wire for empty filter: %v", req["alias"])
		}
	case <-time.After(time.Second):
		t.Fatal("fake signer did not receive the request")
	}
}

// TestListGrants_OldDaemonUnsupportedKind pins the forward-compat path: an
// OLD daemon that predates list_grants answers "unsupported kind" (with the
// kind echoed as the request_id). The client must surface a clear
// "daemon too old" error, NOT an opaque correlation mismatch.
func TestListGrants_OldDaemonUnsupportedKind(t *testing.T) {
	t.Parallel()
	// An old daemon's default switch case responds:
	//   respondError(conn, peek.Kind, `unsupported kind "list_grants"`)
	// → request_id == "list_grants", status == "error".
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"list_grants","status":"error","error":"unsupported kind \"list_grants\""}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.ListGrants(context.Background(), "l_real", "prod")
	if err == nil {
		t.Fatal("err is nil; want a 'too old' error for an old daemon")
	}
	msg := err.Error()
	if !strings.Contains(msg, "too old") {
		t.Errorf("error did not surface a 'too old' hint; got: %v", msg)
	}
	// Must NOT be reported as an opaque correlation mismatch.
	if strings.Contains(msg, "!=") {
		t.Errorf("old-daemon error mis-reported as a correlation mismatch: %v", msg)
	}
}

// itoa is a tiny strconv.Itoa shim kept local so the test stays readable
// when building a JSON literal that embeds sigwire.ProtoVersion.
func itoa(n int) string { return strconv.Itoa(n) }
