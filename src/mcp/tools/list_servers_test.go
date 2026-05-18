package tools_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

func TestListServers_Empty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}

	out, err := runner.ListServers(context.Background(), tools.ListServersInput{})
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if out.Total != 0 {
		t.Errorf("Total = %d; want 0", out.Total)
	}
	if len(out.Servers) != 0 {
		t.Errorf("Servers len = %d; want 0", len(out.Servers))
	}
}

func TestListServers_PopulatedSortedAlphabetically(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	addedAt := time.Date(2026, 5, 19, 10, 30, 0, 0, time.UTC)
	// Insert in non-alphabetical order to verify sorting.
	for alias, entry := range map[string]registry.Entry{
		"zebra":   {Host: "z.example.com", Port: 22, User: "ops", AddedAt: addedAt},
		"alpha":   {Host: "a.example.com", Port: 2022, User: "root", AddedAt: addedAt},
		"mango":   {Host: "m.example.com", Port: 22, User: "deploy", AddedAt: addedAt},
	} {
		if err := r.Add(alias, entry); err != nil {
			t.Fatal(err)
		}
	}

	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	out, err := runner.ListServers(context.Background(), tools.ListServersInput{})
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if out.Total != 3 {
		t.Errorf("Total = %d; want 3", out.Total)
	}
	if len(out.Servers) != 3 {
		t.Fatalf("Servers len = %d; want 3", len(out.Servers))
	}
	wantOrder := []string{"alpha", "mango", "zebra"}
	for i, want := range wantOrder {
		if out.Servers[i].Alias != want {
			t.Errorf("Servers[%d].Alias = %q; want %q", i, out.Servers[i].Alias, want)
		}
	}
	// Spot-check a single entry's content.
	first := out.Servers[0]
	if first.Host != "a.example.com" || first.Port != 2022 || first.User != "root" {
		t.Errorf("Servers[0] = %+v; want alpha host=a.example.com port=2022 user=root", first)
	}
	if first.AddedAt != addedAt.Format(time.RFC3339) {
		t.Errorf("Servers[0].AddedAt = %q; want %q", first.AddedAt, addedAt.Format(time.RFC3339))
	}
	if first.LastSeen != "" {
		t.Errorf("Servers[0].LastSeen = %q; want empty (registry does not track it)", first.LastSeen)
	}
}

func TestListServers_NilRegistryRejected(t *testing.T) {
	t.Parallel()
	runner := &tools.Runner{}
	_, err := runner.ListServers(context.Background(), tools.ListServersInput{})
	if err == nil {
		t.Fatal("expected error when Servers is nil")
	}
}
