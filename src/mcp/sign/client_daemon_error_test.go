package sign_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// TestSign_SendsProtoVersion confirms the MCP stamps the current
// sigwire.ProtoVersion onto every sign request it builds (F6). The
// fake-signer seam captures the marshalled request so we can inspect the
// wire field directly.
func TestSign_SendsProtoVersion(t *testing.T) {
	t.Parallel()
	path, gotReq, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"r1","status":"approved","signatures":[{"cmd":"x","sig":"SSHGATE_SIG:a:b"}]}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	if _, err := c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	select {
	case req := <-gotReq:
		// JSON numbers decode to float64 in a map[string]any.
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

// TestSign_VersionMismatchDaemonErrorSurfaces confirms a daemon
// proto_version-mismatch error (carrying an echoed request_id) surfaces its
// reason clearly to the caller rather than a sentinel or an opaque mismatch.
func TestSign_VersionMismatchDaemonErrorSurfaces(t *testing.T) {
	t.Parallel()
	const reason = "proto_version mismatch: client v999 vs daemon v1 — signer and MCP are different builds; rebuild and restart both"
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"r1","status":"error","error":"` + reason + `"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want the version-mismatch reason surfaced")
	}
	msg := err.Error()
	if !strings.Contains(msg, "proto_version mismatch") || !strings.Contains(msg, "rebuild") {
		t.Errorf("error did not surface the version-mismatch reason; got: %v", msg)
	}
	if errors.Is(err, sign.ErrDenied) || errors.Is(err, sign.ErrTimeout) || errors.Is(err, sign.ErrUnreachable) {
		t.Errorf("version-mismatch error mis-classified as a sentinel: %v", err)
	}
}

// TestSign_EmptyRequestIDErrorSurfacesReason covers Finding 2b: a daemon
// error response with an empty request_id (e.g. a malformed request, or a
// backend-send failure the daemon reported before it could echo the id)
// must surface the daemon's actual reason from resp.Error, NOT the opaque
// `response request_id "" != "r_..."` correlation-mismatch string.
func TestSign_EmptyRequestIDErrorSurfacesReason(t *testing.T) {
	t.Parallel()
	const reason = "backend: telegram send: bot<REDACTED> failed"
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"","status":"error","error":"` + reason + `"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r_real", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want the daemon's error reason surfaced")
	}
	msg := err.Error()
	if !strings.Contains(msg, reason) {
		t.Errorf("error did not surface daemon reason %q; got: %v", reason, msg)
	}
	// It must NOT be the opaque request_id-mismatch string.
	if strings.Contains(msg, "request_id") && strings.Contains(msg, "!=") {
		t.Errorf("error mis-reported as a request_id correlation mismatch instead of the real reason: %v", msg)
	}
	// And it must not be mis-classified as a denial/timeout/transport issue.
	if errors.Is(err, sign.ErrDenied) || errors.Is(err, sign.ErrTimeout) || errors.Is(err, sign.ErrUnreachable) {
		t.Errorf("error mis-classified: %v", err)
	}
}

// TestSign_EmptyRequestIDErrorNoDetail covers the empty-id error response
// with an empty Error field: we still must not surface the opaque
// correlation-mismatch string; the existing "no detail" daemon-error
// message is the right answer.
func TestSign_EmptyRequestIDErrorNoDetail(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"","status":"error","error":""}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r_real", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want a daemon-error result")
	}
	msg := err.Error()
	if strings.Contains(msg, "request_id") && strings.Contains(msg, "!=") {
		t.Errorf("empty-detail daemon error mis-reported as a correlation mismatch: %v", msg)
	}
}

// TestSign_NonEmptyRequestIDMismatchStillErrors confirms the fix does NOT
// weaken the correlation guarantee: a NON-EMPTY request_id that does not
// match the one we sent is still a true correlation error (concurrency
// safety). status is "approved" here to prove the id check still fires
// before the status switch for a non-empty id.
func TestSign_NonEmptyRequestIDMismatchStillErrors(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"r_other","status":"approved","signatures":[]}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r_real", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want a correlation mismatch for a non-empty mismatched request_id")
	}
	msg := err.Error()
	if !(strings.Contains(msg, "request_id") && strings.Contains(msg, "!=")) {
		t.Errorf("non-empty mismatched request_id should surface a correlation mismatch; got: %v", msg)
	}
}

// TestSign_NonEmptyRequestIDErrorSurfacesReason confirms a normal error
// response (matching id, status error) still surfaces resp.Error — the
// fix must not regress the existing matched-id error path.
func TestSign_NonEmptyRequestIDErrorSurfacesReason(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"r_real","status":"error","error":"some real reason"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r_real", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want the matched-id error reason surfaced")
	}
	if !strings.Contains(err.Error(), "some real reason") {
		t.Errorf("matched-id error did not surface reason; got: %v", err)
	}
}

// TestSign_MatchingIDSuccessStillWorks confirms the happy path is intact:
// a matching request_id with status approved returns the signatures.
func TestSign_MatchingIDSuccessStillWorks(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"r_real","status":"approved","signatures":[{"cmd":"x","sig":"SSHGATE_SIG:a:b"}]}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	res, err := c.Sign(context.Background(), "r_real", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(res.Signed) != 1 || res.Signed[0].Cmd != "x" || res.Signed[0].Sig != "SSHGATE_SIG:a:b" {
		t.Errorf("got %+v", res.Signed)
	}
}
