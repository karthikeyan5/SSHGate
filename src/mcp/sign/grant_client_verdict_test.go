package sign

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// The grant roundtrip (request_grant / revoke_grant) shares the same
// transport scaffold as Sign, so a lost grant verdict must ALSO surface as
// ErrVerdictUnknown — a human may have DENIED the grant; the agent must not
// silently re-request it. These tests drive the readResultConn fixture from
// client_verdict_test.go through RequestGrant + RevokeGrant.

func TestRequestGrant_EOFAfterRequestSent_IsVerdictUnknown(t *testing.T) {
	withFakeDial(t, newReadResultConn(io.EOF))
	c := &Client{SocketPath: "/unused", Timeout: 2 * time.Second}
	_, _, err := c.RequestGrant(context.Background(), "g1", "prod", "all", nil, 3600)
	if !errors.Is(err, ErrVerdictUnknown) {
		t.Errorf("err = %v; want errors.Is(ErrVerdictUnknown) on EOF after grant request sent", err)
	}
	if strings.Contains(err.Error(), "read response") {
		t.Errorf("err = %q; should be the verdict-unknown message, not the generic read-response wrap", err.Error())
	}
}

func TestRequestGrant_NetTimeoutAfterRequestSent_IsVerdictUnknown(t *testing.T) {
	withFakeDial(t, newReadResultConn(netTimeoutErr{}))
	c := &Client{SocketPath: "/unused", Timeout: 2 * time.Second}
	_, _, err := c.RequestGrant(context.Background(), "g1", "prod", "all", nil, 3600)
	if !errors.Is(err, ErrVerdictUnknown) {
		t.Errorf("err = %v; want errors.Is(ErrVerdictUnknown) on net-timeout after grant request sent", err)
	}
}

func TestRevokeGrant_DeadlineExceededAfterRequestSent_IsVerdictUnknown(t *testing.T) {
	withFakeDial(t, newReadResultConn(os.ErrDeadlineExceeded))
	c := &Client{SocketPath: "/unused", Timeout: 2 * time.Second}
	err := c.RevokeGrant(context.Background(), "rv1", "prod")
	if !errors.Is(err, ErrVerdictUnknown) {
		t.Errorf("err = %v; want errors.Is(ErrVerdictUnknown) on deadline-exceeded after revoke request sent", err)
	}
}

// A ctx cancellation on the grant path stays the ctx error, not verdict-unknown.
func TestRequestGrant_CtxCancelStillCtxError(t *testing.T) {
	withFakeDial(t, newReadResultConn(io.EOF))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &Client{SocketPath: "/unused", Timeout: 2 * time.Second}
	_, _, err := c.RequestGrant(ctx, "g1", "prod", "all", nil, 3600)
	if errors.Is(err, ErrVerdictUnknown) {
		t.Errorf("ctx-cancel mis-mapped to ErrVerdictUnknown: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want errors.Is(context.Canceled)", err)
	}
}
