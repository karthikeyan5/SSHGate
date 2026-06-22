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

func TestRequestGrant_HappyPath_ScopeAll(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "throwaway", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{grantID: "g_abc", grantExpiryUnix: 1700000000}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}

	out, err := runner.RequestGrant(context.Background(), tools.RequestGrantInput{
		Alias: "throwaway", Scope: "all", DurationHours: 8, Reason: "overnight build target",
	})
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if !sign.grantCalled {
		t.Fatal("Sign.RequestGrant not called")
	}
	if sign.grantAlias != "throwaway" || sign.grantScope != "all" {
		t.Errorf("got alias=%q scope=%q", sign.grantAlias, sign.grantScope)
	}
	if sign.grantDurationSec != 8*3600 {
		t.Errorf("duration = %d; want %d", sign.grantDurationSec, 8*3600)
	}
	if len(sign.grantCommands) != 0 {
		t.Errorf("commands = %v; want empty for scope=all", sign.grantCommands)
	}
	if out.GrantID != "g_abc" || out.ExpiryUnix != 1700000000 {
		t.Errorf("out = %+v; want grant_id g_abc expiry 1700000000", out)
	}
}

func TestRequestGrant_HappyPath_ScopeCommands(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "src", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{grantID: "g_xyz", grantExpiryUnix: 1700000123}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}

	cmds := []string{"systemctl stop app", "tar czf bak.tgz /data"}
	out, err := runner.RequestGrant(context.Background(), tools.RequestGrantInput{
		Alias: "src", Scope: "commands", Commands: cmds, DurationHours: 2, Reason: "source shutdown+backup",
	})
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if len(sign.grantCommands) != 2 || sign.grantCommands[0] != "systemctl stop app" {
		t.Errorf("commands = %v; want the 2-entry list", sign.grantCommands)
	}
	if out.GrantID != "g_xyz" {
		t.Errorf("grant_id = %q; want g_xyz", out.GrantID)
	}
}

func TestRequestGrant_DurationOutOfRange(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	for _, hrs := range []int{0, 25, -1, 100} {
		sign := &fakeSign{}
		runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}
		_, err := runner.RequestGrant(context.Background(), tools.RequestGrantInput{
			Alias: "h", Scope: "all", DurationHours: hrs,
		})
		if err == nil {
			t.Errorf("hrs=%d: expected error", hrs)
		}
		if sign.grantCalled {
			t.Errorf("hrs=%d: Sign.RequestGrant called despite bad duration (must reject BEFORE any tap)", hrs)
		}
	}
}

func TestRequestGrant_ScopeCommandsEmptyRejected(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}
	_, err := runner.RequestGrant(context.Background(), tools.RequestGrantInput{
		Alias: "h", Scope: "commands", Commands: nil, DurationHours: 4,
	})
	if err == nil {
		t.Fatal("expected error for empty commands with scope=commands")
	}
	if sign.grantCalled {
		t.Error("Sign.RequestGrant called despite empty commands")
	}
}

func TestRequestGrant_ScopeAllWithCommandsRejected(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}
	_, err := runner.RequestGrant(context.Background(), tools.RequestGrantInput{
		Alias: "h", Scope: "all", Commands: []string{"ls"}, DurationHours: 4,
	})
	if err == nil {
		t.Fatal("expected error for scope=all carrying a commands list")
	}
	if sign.grantCalled {
		t.Error("Sign.RequestGrant called despite scope=all + commands")
	}
}

func TestRequestGrant_InvalidScopeRejected(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}
	_, err := runner.RequestGrant(context.Background(), tools.RequestGrantInput{
		Alias: "h", Scope: "everything", DurationHours: 4,
	})
	if err == nil {
		t.Fatal("expected error for invalid scope")
	}
	if sign.grantCalled {
		t.Error("Sign.RequestGrant called despite invalid scope")
	}
}

func TestRequestGrant_UnknownAlias(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "exists", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}
	_, err := runner.RequestGrant(context.Background(), tools.RequestGrantInput{
		Alias: "nope", Scope: "all", DurationHours: 4,
	})
	if err == nil {
		t.Fatal("expected error for unknown alias")
	}
	if sign.grantCalled {
		t.Error("Sign.RequestGrant called for an unknown alias")
	}
}

// TestRequestGrant_DenialPropagates_NoLocalGrant is the
// agent-cannot-self-create test: when the human denies, RequestGrant
// returns an error wrapping ErrDenied. There is NO local grant state on
// the MCP side at all — the only authority that can mint a grant is the
// signer's human-approval path. The agent gets a denial, not a grant.
func TestRequestGrant_DenialPropagates_NoLocalGrant(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{grantErr: signpkg.ErrDenied}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}

	out, err := runner.RequestGrant(context.Background(), tools.RequestGrantInput{
		Alias: "prod", Scope: "all", DurationHours: 4,
	})
	if !errors.Is(err, signpkg.ErrDenied) {
		t.Errorf("err = %v; want wrap of ErrDenied", err)
	}
	// No grant escaped the denial.
	if out.GrantID != "" {
		t.Errorf("GrantID = %q; want empty on denial", out.GrantID)
	}
}
