package classify

import "testing"

// TestClassify_ReadOnlyBypassRegressions4 pins the two novel read-only-gate
// bypasses found by the 2026-06-14 Opus red-team hunter against the hardened
// gate. Both were CONFIRMED live (the gate classified READ, executed unsigned,
// and the rig's tripwire caught a real filesystem write):
//
//  1. `uniq INPUT OUTPUT` — uniq was a nil (always-READ) allowlist entry, but
//     GNU uniq writes its SECOND positional as an output file (same write
//     class as the patched `sort -o`, via a bare positional).
//  2. `awk` redirect/pipe to an INDIRECT (variable) target — awkProgIsDangerous
//     only caught `> "literal"` / `| "literal"`, so `print x > f` /
//     `print x | c` (f/c variables) wrote/exec'd unsigned.
//
// The READ guards are the critical non-regressions: a `>` comparison
// (`$3>100`) or a parenthesized comparison inside print (`print ($3>100)`)
// must STAY read — those are awk's most common read idioms.
func TestClassify_ReadOnlyBypassRegressions4(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Kind
	}{
		// --- uniq output-file positional ---
		{"uniq writes 2nd positional to authorized_keys", "uniq /etc/hostname /config/.ssh/authorized_keys", KindWrite},
		{"uniq stdin to output file", "uniq - /tmp/out", KindWrite},
		{"uniq with flag then 2 positionals", "uniq -c /etc/hostname /tmp/out", KindWrite},
		{"uniq --count then 2 positionals", "uniq --count in out", KindWrite},
		{"uniq /dev/stdin to output", "uniq /dev/stdin /tmp/out", KindWrite},
		// uniq READ non-regressions
		{"uniq no args stays read", "uniq", KindRead},
		{"uniq single input stays read", "uniq /etc/passwd", KindRead},
		{"uniq -c single input stays read", "uniq -c /etc/passwd", KindRead},
		{"uniq -f N value not a positional", "uniq -f 2 /etc/passwd", KindRead},
		{"uniq -w bundled stays read", "uniq -w3 /etc/passwd", KindRead},
		{"uniq -d single input stays read", "uniq -d /var/log/x", KindRead},

		// --- awk indirect (variable) redirect / pipe ---
		{"awk print > variable file", `awk 'BEGIN{f="/config/.ssh/authorized_keys"; print "ssh-rsa AAAA" > f}'`, KindWrite},
		{"awk print | variable command", `awk 'BEGIN{c="sh -c id"; print "x" | c}' file`, KindWrite},
		{"awk END print > out var", `awk 'END{print > out}' file`, KindWrite},
		{"awk -v target then print > var", `awk -v f=/tmp/x 'END{print > f}' file`, KindWrite},
		{"awk printf > variable", `awk 'BEGIN{printf "%s", "x" > f}'`, KindWrite},
		{"awk print append > > var", `awk 'BEGIN{print "x" >> f}'`, KindWrite},
		// awk READ non-regressions (comparisons / logical-or must stay read)
		{"awk comparison filter stays read", `awk '$3>100' /etc/passwd`, KindRead},
		{"awk comparison with print block stays read", `awk '$3>100{print $1}' f`, KindRead},
		{"awk parenthesized comparison in print stays read", `awk '{print ($3 > 100)}' f`, KindRead},
		{"awk ge comparison in print stays read", `awk '{print a >= b}' f`, KindRead},
		{"awk logical-or in print stays read", `awk '{print a || b}' f`, KindRead},
		{"awk plain print stays read", `awk '{print $1}' /etc/passwd`, KindRead},
		{"awk gt-char inside string stays read", `awk 'BEGIN{print "a>b"}'`, KindRead},

		// --- curl undocumented write-file flags (Sonnet hunter) ---
		{"curl --trace writes file", "curl --trace /config/.ssh/authorized_keys http://localhost/", KindWrite},
		{"curl -D dump-header writes file", "curl -D /config/.ssh/authorized_keys http://localhost/", KindWrite},
		{"curl --dump-header writes file", "curl --dump-header /tmp/h http://x", KindWrite},
		{"curl -c cookie-jar writes file", "curl -c /tmp/jar http://x", KindWrite},
		{"curl --cookie-jar writes file", "curl --cookie-jar /tmp/jar http://x", KindWrite},
		{"curl --stderr writes file", "curl --stderr /tmp/e http://x", KindWrite},
		{"curl --libcurl writes file", "curl --libcurl /tmp/code.c http://x", KindWrite},
		{"curl --trace-ascii writes file", "curl --trace-ascii /tmp/t http://x", KindWrite},
		{"curl --trace= form writes file", "curl --trace=/tmp/t http://x", KindWrite},
		// curl READ non-regressions
		{"curl plain GET stays read", "curl http://x", KindRead},
		{"curl -s stays read", "curl -s http://x", KindRead},
		{"curl -o - stdout stays read", "curl -o - http://x", KindRead},
		{"curl --trace - stream stays read", "curl --trace - http://x", KindRead},
		{"curl -b read cookie input stays read", "curl -b /tmp/jar http://x", KindRead},

		// --- sed whitespace between address and command (Sonnet hunter) ---
		{"sed numeric-addr space w writes", "sed '1 w /tmp/x' /etc/hostname", KindWrite},
		{"sed last-line space w writes", "sed '$ w /tmp/x' f", KindWrite},
		{"sed range space w writes", "sed '1,$ w /tmp/x' f", KindWrite},
		{"sed regex-addr space w writes", "sed '/hostname/ w /tmp/x' f", KindWrite},
		{"sed range-to-regex space w writes", "sed '1,/hostname/ w /tmp/x' f", KindWrite},
		{"sed bracket-regex space w writes", "sed '/^[a-z]/ w /tmp/x' f", KindWrite},
		// sed READ non-regressions (regex starting with r/w/e, no command)
		{"sed regex re delete stays read", "sed '/re/d' f", KindRead},
		{"sed regex warn delete stays read", "sed '/warn/d' f", KindRead},
		{"sed print range stays read 2", "sed -n '1,5p' f", KindRead},
		{"sed substitute stays read 2", "sed 's/a/b/g' f", KindRead},
		// glued forms from round-2 must still hold
		{"sed glued w still writes", "sed '$w/tmp/x' f", KindWrite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.cmd); got != tc.want {
				t.Errorf("Classify(%q) = %s; want %s", tc.cmd, got, tc.want)
			}
		})
	}
}
