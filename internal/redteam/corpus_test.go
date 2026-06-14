package redteam

import (
	"strings"
	"testing"
)

// TestCorpus_CoversNamedCategories asserts the built-in corpus includes
// every attack class the threat model named (plus the three fixed
// holes), so a campaign actually exercises the surface.
func TestCorpus_CoversNamedCategories(t *testing.T) {
	atk := Corpus(CanaryRoot, SecretPath)
	if len(atk) < 60 {
		t.Fatalf("corpus has only %d attacks; expected a broad set", len(atk))
	}
	want := []string{
		"fixed-hole/newline-separator",
		"fixed-hole/bundled-sed-inplace",
		"fixed-hole/dquote-cmd-substitution",
		"separators",
		"redirect",
		"write-tool",
		"substitution",
		"eval-decode",
		"ifs-quoting",
		"heredoc",
		"background",
		"find-xargs",
		"awk-exec",
		"ex-vi",
		"git-write",
		"interpreter",
		"env-abuse",
		"secret-read",
		"baseline-read",
	}
	have := map[string]bool{}
	for _, a := range atk {
		have[a.Category] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("corpus missing category %q", w)
		}
	}
}

// TestCorpus_TemplatesCanaryRoot ensures the corpus references the real
// seeded canary paths (so writes land in the watched tree, not /tmp).
func TestCorpus_TemplatesCanaryRoot(t *testing.T) {
	atk := Corpus("/config/canary", "/config/secret.txt")
	sawProbe, sawSecret := false, false
	for _, a := range atk {
		if strings.Contains(a.Cmd, "/config/canary/"+canaryProbeName) {
			sawProbe = true
		}
		if strings.Contains(a.Cmd, "/config/secret.txt") {
			sawSecret = true
		}
	}
	if !sawProbe {
		t.Error("no corpus command targets the canary probe path")
	}
	if !sawSecret {
		t.Error("no corpus command reads the secret path")
	}
}

// TestCorpus_IncludesFixedHoleExamples pins the exact three holes that
// were closed on main, so the rig keeps probing them.
func TestCorpus_IncludesFixedHoleExamples(t *testing.T) {
	atk := Corpus(CanaryRoot, SecretPath)
	joined := ""
	for _, a := range atk {
		joined += a.Cmd + "\x00"
	}
	// newline separator
	if !strings.Contains(joined, "ls\nrm -rf "+CanaryRoot) {
		t.Error("missing newline-separator hole")
	}
	// bundled sed in-place
	if !strings.Contains(joined, "sed -ni 's/.*/x/'") {
		t.Error("missing bundled sed -ni hole")
	}
	// command substitution inside double quotes
	if !strings.Contains(joined, `cat "$(touch`) {
		t.Error("missing double-quoted command-substitution hole")
	}
}

// TestMutate_Deterministic confirms the fuzzer is reproducible per seed
// and templates the canary root.
func TestMutate_Deterministic(t *testing.T) {
	a := Mutate(CanaryRoot, 42, 20)
	b := Mutate(CanaryRoot, 42, 20)
	if len(a) != 20 || len(b) != 20 {
		t.Fatalf("Mutate count = %d/%d; want 20", len(a), len(b))
	}
	for i := range a {
		if a[i].Cmd != b[i].Cmd {
			t.Fatalf("Mutate not deterministic at %d: %q vs %q", i, a[i].Cmd, b[i].Cmd)
		}
	}
	for _, m := range a {
		if !strings.Contains(m.Cmd, CanaryRoot) {
			t.Errorf("fuzz mutant does not reference canary root: %q", m.Cmd)
		}
	}
}

// TestDedupe removes duplicate commands.
func TestDedupe(t *testing.T) {
	in := []Attack{{Cmd: "a"}, {Cmd: "b"}, {Cmd: "a"}}
	out := dedupe(in)
	if len(out) != 2 {
		t.Fatalf("dedupe -> %d; want 2", len(out))
	}
}
