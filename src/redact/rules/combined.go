// Package rules combines the SSHGate-native and gitleaks-vendored
// rule sets into the single slice the gate binary compiles in.
//
// Per the v1.2 architecture (locked in
// docs/audits/secrets-redaction-architecture-2026-05-19.md
// §"Rule library — vendored, not imported"), the two source dirs
// (`gitleaks/` and `sshgate/`) live side-by-side and a generator
// step emits the combined file the gate consumes. R1 ships the
// combined file as a hand-written Go source rather than a
// go:generate output: with only two source packages and rules
// expressed directly as Go literals, the regenerate-and-commit dance
// adds friction without adding value. If a third source dir lands
// (e.g. a `secretscanner-vendor/` block), this file flips to a
// generator at that point.
//
// The Combined() result is sorted by ID and de-duplicated (last
// occurrence wins). Same-format rules from different sources both
// fire and the writer's match de-duplication handles the overlap.
package rules

import (
	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/redact/rules/gitleaks"
	"github.com/karthikeyan5/sshgate/src/redact/rules/sshgate"
)

// Combined returns the full v1.2 ruleset the gate compiles in. The
// order of concatenation does not affect scanning (the scanner runs
// every rule against the buffer), but the result is sorted by ID for
// reproducible debug output.
func Combined() []redact.Rule {
	var all []redact.Rule
	all = append(all, sshgate.Rules()...)
	all = append(all, gitleaks.Rules()...)
	return redact.SortRules(all)
}
