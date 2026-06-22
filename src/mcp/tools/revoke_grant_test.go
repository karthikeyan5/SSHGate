package tools_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

func TestRevokeGrant_HappyPath(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}

	out, err := runner.RevokeGrant(context.Background(), tools.RevokeGrantInput{Alias: "prod"})
	if err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if !sign.revokeGrantCalled {
		t.Fatal("Sign.RevokeGrant not called")
	}
	if sign.revokeGrantAlias != "prod" {
		t.Errorf("alias = %q; want prod", sign.revokeGrantAlias)
	}
	if !out.Revoked {
		t.Error("Revoked = false; want true")
	}
}

// TestRevokeGrant_StaleAliasNotRegistered pins that revoking a grant for
// an alias that is NOT in the registry still works — a stale grant for a
// since-removed server must remain revocable.
func TestRevokeGrant_StaleAliasNotRegistered(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "other", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}

	out, err := runner.RevokeGrant(context.Background(), tools.RevokeGrantInput{Alias: "gone"})
	if err != nil {
		t.Fatalf("RevokeGrant for unregistered alias: %v", err)
	}
	if !sign.revokeGrantCalled || sign.revokeGrantAlias != "gone" {
		t.Errorf("revoke not dispatched for stale alias (called=%v alias=%q)", sign.revokeGrantCalled, sign.revokeGrantAlias)
	}
	if !out.Revoked {
		t.Error("Revoked = false; want true")
	}
}

func TestRevokeGrant_EmptyAlias(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}
	_, err := runner.RevokeGrant(context.Background(), tools.RevokeGrantInput{Alias: ""})
	if err == nil {
		t.Fatal("expected error for empty alias")
	}
	if sign.revokeGrantCalled {
		t.Error("Sign.RevokeGrant called with empty alias")
	}
}

func TestRevokeGrant_TransportError(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{revokeGrantErr: signpkg.ErrUnreachable}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}

	out, err := runner.RevokeGrant(context.Background(), tools.RevokeGrantInput{Alias: "prod"})
	if !errors.Is(err, signpkg.ErrUnreachable) {
		t.Errorf("err = %v; want wrap of ErrUnreachable", err)
	}
	if out.Revoked {
		t.Error("Revoked = true despite transport error")
	}
}
