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

// TestListGrants_HappyPath drives Runner.ListGrants against a fake SignClient
// and asserts the structured output carries the grants the signer reported,
// and that the optional alias filter is passed through.
func TestListGrants_HappyPath(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{listGrantsResult: []signpkg.GrantInfo{
		{Alias: "prod", Scope: "commands", Commands: []string{"systemctl restart nginx"}, GrantID: "g_abc", ExpiryUnix: 1700000000},
	}}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}

	out, err := runner.ListGrants(context.Background(), tools.ListGrantsInput{Alias: "prod"})
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if !sign.listGrantsCalled {
		t.Fatal("Sign.ListGrants not called")
	}
	if sign.listGrantsAlias != "prod" {
		t.Errorf("alias = %q; want prod", sign.listGrantsAlias)
	}
	if len(out.Grants) != 1 {
		t.Fatalf("got %d grants; want 1", len(out.Grants))
	}
	g := out.Grants[0]
	if g.Alias != "prod" || g.GrantID != "g_abc" || g.Scope != "commands" || g.ExpiryUnix != 1700000000 {
		t.Errorf("grant = %+v; want the prod row", g)
	}
}

// TestListGrants_EmptyAliasListsAll pins that an empty alias is valid (lists
// all live grants) and is passed through verbatim.
func TestListGrants_EmptyAliasListsAll(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{listGrantsResult: []signpkg.GrantInfo{
		{Alias: "prod", Scope: "all", GrantID: "g_1", ExpiryUnix: 1},
		{Alias: "src", Scope: "all", GrantID: "g_2", ExpiryUnix: 2},
	}}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}

	out, err := runner.ListGrants(context.Background(), tools.ListGrantsInput{})
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if sign.listGrantsAlias != "" {
		t.Errorf("alias = %q; want empty (list all)", sign.listGrantsAlias)
	}
	if len(out.Grants) != 2 {
		t.Errorf("got %d grants; want 2", len(out.Grants))
	}
}

// TestListGrants_NilSignGuard pins the nil-Sign guard (mirrors the other
// tools): a Runner with no Sign client errors rather than panicking.
func TestListGrants_NilSignGuard(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: nil, SSH: &fakeSSH{}}

	_, err := runner.ListGrants(context.Background(), tools.ListGrantsInput{Alias: "prod"})
	if err == nil {
		t.Fatal("expected error for nil Sign")
	}
}

// TestListGrants_TransportError pins that a transport error from the signer
// surfaces (sentinel preserved) and yields no grants.
func TestListGrants_TransportError(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{listGrantsErr: signpkg.ErrUnreachable}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}

	out, err := runner.ListGrants(context.Background(), tools.ListGrantsInput{Alias: "prod"})
	if !errors.Is(err, signpkg.ErrUnreachable) {
		t.Errorf("err = %v; want wrap of ErrUnreachable", err)
	}
	if len(out.Grants) != 0 {
		t.Error("grants returned despite transport error")
	}
}
