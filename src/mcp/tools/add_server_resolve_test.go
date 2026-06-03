package tools

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultGateBinaryPath_ConfigRootBin asserts the resolver finds
// sshgate-gate-linux-amd64 under <configRoot>/bin when SSHGATE_GATE_BIN
// is unset. This is the stable location `make install-local` writes to.
func TestDefaultGateBinaryPath_ConfigRootBin(t *testing.T) {
	cfgRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgRoot)
	t.Setenv("SSHGATE_GATE_BIN", "")
	t.Setenv("CLAUDE_PLUGIN_ROOT", "")

	binDir := filepath.Join(cfgRoot, "sshgate", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(binDir, "sshgate-gate-linux-amd64")
	if err := os.WriteFile(want, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := defaultGateBinaryPath()
	if err != nil {
		t.Fatalf("defaultGateBinaryPath: %v", err)
	}
	if got != want {
		t.Errorf("defaultGateBinaryPath() = %q; want %q (configRoot/bin)", got, want)
	}
}

// TestDefaultGateBinaryPath_EnvOverride asserts $SSHGATE_GATE_BIN wins.
func TestDefaultGateBinaryPath_EnvOverride(t *testing.T) {
	override := filepath.Join(t.TempDir(), "custom-gate")
	t.Setenv("SSHGATE_GATE_BIN", override)
	t.Setenv("CLAUDE_PLUGIN_ROOT", "")

	got, err := defaultGateBinaryPath()
	if err != nil {
		t.Fatalf("defaultGateBinaryPath: %v", err)
	}
	if got != override {
		t.Errorf("defaultGateBinaryPath() = %q; want %q (env override)", got, override)
	}
}

// TestDefaultGateBinaryPath_UsesPrefixedName asserts the resolved
// basename is the prefixed sshgate-gate-linux-amd64, never the old
// unprefixed gate-linux-amd64 (the B3 name-drift bug).
func TestDefaultGateBinaryPath_UsesPrefixedName(t *testing.T) {
	cfgRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgRoot)
	t.Setenv("SSHGATE_GATE_BIN", "")
	t.Setenv("CLAUDE_PLUGIN_ROOT", "")

	got, err := defaultGateBinaryPath()
	if err != nil {
		t.Fatalf("defaultGateBinaryPath: %v", err)
	}
	if filepath.Base(got) != "sshgate-gate-linux-amd64" {
		t.Errorf("resolved basename = %q; want sshgate-gate-linux-amd64", filepath.Base(got))
	}
}
