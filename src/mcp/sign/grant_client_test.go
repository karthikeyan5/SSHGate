package sign_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/sign"
)

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
