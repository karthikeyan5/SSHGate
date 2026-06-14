package classify

import "testing"

// TestClassify_ReadOnlyBypassRegressions pins the two live read-only-gate
// bypasses found by the 2026-06-14 testability audit. On a Tier-1 read-only
// server the gate execs any KindRead command outright (sh -c, no approval),
// so a WRITE that classifies READ is a real bypass. These MUST classify
// WRITE; the non-regression rows guard against over-broadening the fix.
func TestClassify_ReadOnlyBypassRegressions(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Kind
	}{
		// Bypass 1 — unquoted newline is a /bin/sh command separator that
		// splitSegments used to ignore, so the second line ran unclassified.
		{"newline separates read then rm", "ls\nrm -rf /tmp/x", KindWrite},
		{"newline read then destructive", "cat /etc/hosts\nrm -rf /data", KindWrite},
		{"newline read then sudo", "echo hi\nsudo reboot", KindWrite},
		{"crlf-ish: newline after pipe-read", "df -h\n: > /tmp/owned", KindWrite},
		// Non-regressions for bypass 1: a newline INSIDE quotes is data, not a
		// separator, so the head command's kind stands.
		{"quoted newline stays read (echo)", "echo 'line1\nline2'", KindRead},
		{"leading newline", "\nls -la", KindRead},
		{"trailing newline", "ls -la\n", KindRead},

		// Bypass 2 — sed in-place (-i) bundled after other short flags. These
		// edit files in place (WRITE) but the old a[1]=='i' check missed them.
		{"sed -ni in-place", "sed -ni 's/.*/x/' /etc/passwd", KindWrite},
		{"sed -Ei in-place", "sed -Ei 's/a/b/' file", KindWrite},
		{"sed -ri in-place", "sed -ri 's/a/b/' file", KindWrite},
		{"sed -si in-place", "sed -si 's/a/b/' f1 f2", KindWrite},
		{"sed -nri in-place", "sed -nri 's/a/b/' file", KindWrite},
		// Still-caught forms (must remain WRITE).
		{"sed -i plain", "sed -i 's/a/b/' file", KindWrite},
		{"sed -i.bak suffix", "sed -i.bak 's/a/b/' file", KindWrite},
		{"sed --in-place long", "sed --in-place 's/a/b/' file", KindWrite},
		// Non-regressions for bypass 2: no in-place flag => still READ. The
		// 'i' inside a -e script or a positional script must NOT trip WRITE.
		{"sed -n print only", "sed -n 'p' file", KindRead},
		{"sed -e script with i", "sed -e 's/i/x/' file", KindRead},
		{"sed positional script with i", "sed 's/i/x/' file", KindRead},
		{"sed -E extended read", "sed -E 'p' file", KindRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.cmd); got != tc.want {
				t.Errorf("Classify(%q) = %s; want %s", tc.cmd, got, tc.want)
			}
		})
	}
}
