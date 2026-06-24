package main

import (
	"testing"
	"unsafe"

	"github.com/karthikeyan5/sshgate/src/redact"
)

// TestAuditRules_ProductionCompilesOnce pins the C3 fix: in production mode
// (the redactRules test-injection seam left nil) auditRules() compiles the
// ~1 MB redactrules.Combined() ruleset at most ONCE per process. Both
// consumers within a single executed write — output redaction (execChild) and
// command-string redaction (redactAuditCommand) — call auditRules(); before
// the fix each call returned a FRESH Combined() slice, paying the compile
// twice. After the fix the sync.Once cache hands back the SAME slice.
//
// We prove "same compile" by slice IDENTITY: redactrules.Combined() builds a
// brand-new backing array every call (var all []redact.Rule; append...), so
// two independent compiles would have different backing-array pointers. Equal
// pointers ⇒ the second call did not recompile.
func TestAuditRules_ProductionCompilesOnce(t *testing.T) {
	// Ensure production mode: the seam must be nil for the once-cache path.
	// Save/restore defensively in case another test injected it.
	saved := redactRules
	redactRules = nil
	t.Cleanup(func() { redactRules = saved })

	a := auditRules()
	b := auditRules()

	if len(a) == 0 {
		t.Fatal("auditRules() returned an empty ruleset; expected the compiled v1.2 ruleset")
	}
	if len(a) != len(b) {
		t.Fatalf("ruleset length changed between calls: %d vs %d", len(a), len(b))
	}
	// Backing-array identity: &a[0] == &b[0] proves a single compile (a fresh
	// Combined() would allocate a new backing array).
	if unsafe.Pointer(&a[0]) != unsafe.Pointer(&b[0]) {
		t.Errorf("auditRules() recompiled: two calls returned different backing arrays (%p vs %p); the production ruleset must be compiled ONCE", &a[0], &b[0])
	}
}

// TestAuditRules_TestSeamOverridesCache pins that the redactRules injection
// seam still wins over the cache — it is the explicit override, returned
// verbatim and uncached, distinct from the production once-compile.
func TestAuditRules_TestSeamOverridesCache(t *testing.T) {
	saved := redactRules
	t.Cleanup(func() { redactRules = saved })

	// Prime the production cache first.
	_ = auditRules()

	// Now inject a distinct seam; auditRules() must return it, not the cache.
	sentinel := []redact.Rule{{ID: "test-sentinel"}}
	redactRules = sentinel
	got := auditRules()
	if len(got) != len(sentinel) || (len(got) > 0 && unsafe.Pointer(&got[0]) != unsafe.Pointer(&sentinel[0])) {
		t.Errorf("auditRules() did not honour the redactRules seam; got a different slice")
	}
}
