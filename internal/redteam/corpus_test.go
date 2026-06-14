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
		"classifier-write-tools",
		"classifier-read-control",
		"freeform-location",
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

// TestCorpus_ExercisesAll6FixedClassifierClasses pins one WRITE form for
// each of the 6 read-only-gate classifier classes fixed on 2026-06-14, so
// a campaign dynamically re-proves each fix holds (every one must come
// back `denied`). Mirrors src/classify/classifier_bypass2_test.go.
func TestCorpus_ExercisesAll6FixedClassifierClasses(t *testing.T) {
	atk := Corpus(CanaryRoot, SecretPath)
	joined := "\x00"
	writeRows := 0
	for _, a := range atk {
		joined += a.Cmd + "\x00"
		if a.Category == "classifier-write-tools" {
			writeRows++
		}
	}
	// One representative WRITE form per fixed class.
	needles := map[string]string{
		"sort -o":          "sort -o " + beaconDir + "/sort_pwned /etc/hostname",
		"date -s":          "date -s '2020-01-01 00:00:00'",
		"ip add":           "ip addr add 10.99.0.1/24 dev lo",
		"ifconfig set":     "ifconfig lo 127.0.0.2",
		"awk -f opaque":    "awk -f /etc/hostname /etc/hostname",
		"sed e exec":       "sed 'e touch " + beaconDir + "/sed_e_pwned' /etc/hostname",
		"sed s///e altdel": "sed 's|x|touch " + beaconDir + "/sed_se_pwned|e' /etc/hostname",
		"sed $w write":     "sed '$w " + beaconDir + "/sed_w_pwned' /etc/hostname",
	}
	for label, n := range needles {
		if !strings.Contains(joined, "\x00"+n+"\x00") {
			t.Errorf("classifier-write-tools missing %s payload: %q", label, n)
		}
	}
	if writeRows < 6 {
		t.Errorf("classifier-write-tools has %d rows; want >=6 (one per fixed class)", writeRows)
	}
	// READ controls must reference the same tools so the fix's
	// non-regression is also exercised dynamically.
	for _, ctrl := range []string{"sort /etc/hostname", "date +%s", "ip addr show", "ifconfig -a", "awk '{print $1}' /etc/hostname"} {
		if !strings.Contains(joined, "\x00"+ctrl+"\x00") {
			t.Errorf("classifier-read-control missing %q", ctrl)
		}
	}
}

// TestCorpus_WriteToolsAimAtBeacon ensures the file-creating
// classifier-write-tools payloads land in the tripwire's beacon dir, so a
// let-through write trips BOTH the snapshot-of-beacon and the tripwire.
func TestCorpus_WriteToolsAimAtBeacon(t *testing.T) {
	atk := Corpus(CanaryRoot, SecretPath)
	sawBeacon := false
	for _, a := range atk {
		if a.Category == "classifier-write-tools" && strings.Contains(a.Cmd, beaconDir+"/") {
			sawBeacon = true
		}
	}
	if !sawBeacon {
		t.Error("no classifier-write-tools payload targets the beacon dir")
	}
}

// TestCorpus_FreeformHitsExpandedWatchSet ensures the freeform-location
// rows aim writes at the high-value persistence/pivot targets the
// EXPANDED tripwire watch set newly covers — the SSH user's real home
// (/config), its authorized_keys, /tmp, and a runtime sshd_config drop-in
// — so a regression that let any of them run would trip write_alert (the
// canary diff never sees these paths). It also asserts these land OUTSIDE
// the canary tree, since the whole point is detection beyond the canary.
func TestCorpus_FreeformHitsExpandedWatchSet(t *testing.T) {
	atk := Corpus(CanaryRoot, SecretPath)
	home := strings.TrimSuffix(CanaryRoot, "/canary")
	want := map[string]string{
		"authorized_keys (persistence)": home + "/.ssh/authorized_keys",
		"/config home file":             home + "/.redteam_home_pwned",
		"/tmp staging":                  "/tmp/redteam_tmp_pwned",
		"runtime sshd_config drop-in":   "/etc/ssh/sshd_config.d/99-redteam.conf",
	}
	hit := map[string]bool{}
	for _, a := range atk {
		if a.Category != "freeform-location" {
			continue
		}
		// Every freeform write must land OUTSIDE the canary tree (that is
		// the gap this category closes).
		if strings.Contains(a.Cmd, CanaryRoot+"/") {
			t.Errorf("freeform row unexpectedly targets the canary tree: %q", a.Cmd)
		}
		for label, target := range want {
			if strings.Contains(a.Cmd, target) {
				hit[label] = true
			}
		}
	}
	for label := range want {
		if !hit[label] {
			t.Errorf("freeform-location missing a write at %s (%s)", label, want[label])
		}
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
