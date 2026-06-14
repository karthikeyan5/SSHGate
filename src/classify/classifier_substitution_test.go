package classify

import "testing"

// TestClassify_DoubleQuotedSubstitution pins the read-only-gate bypass where
// command substitution inside DOUBLE quotes was suppressed by the classifier
// yet expanded by /bin/sh. Found by the 2026-06-14 triple review.
func TestClassify_DoubleQuotedSubstitution(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Kind
	}{
		// $(...) and backticks DO expand inside double quotes -> WRITE.
		{"dquote cmd-sub", `cat "$(rm -rf x)"`, KindWrite},
		{"dquote backtick", "grep foo \"`reboot`\" bar", KindWrite},
		{"dquote cmd-sub bare", `echo "$(whoami)"`, KindWrite},
		{"dquote backtick in arg", "tar -tf \"backup-`date +%F`.tgz\"", KindWrite},
		// Apostrophe INSIDE double quotes is a literal byte, NOT a quote
		// opener — it must not suppress the real substitution that follows.
		{"apostrophe inside dquotes", `echo "it's $(reboot)"`, KindWrite},
		// Single quotes ARE fully literal in sh -> substitution suppressed -> READ.
		{"squote cmd-sub literal", `cat '$(rm -rf x)'`, KindRead},
		{"squote backtick literal", "echo 'literal `x`'", KindRead},
		{"plain dquoted string", `echo "plain text"`, KindRead},
		// Mixed: a single-quoted literal then a real double-quoted sub.
		{"squote then dquote sub", `echo 'safe' "$(rm x)"`, KindWrite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.cmd); got != tc.want {
				t.Errorf("Classify(%q) = %s; want %s", tc.cmd, got, tc.want)
			}
		})
	}
}
