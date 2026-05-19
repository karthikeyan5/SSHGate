// Package sshgate is the SSHGate-native floor of named-format
// redaction rules. These are SSHGate's own contributions to Layer 1:
// patterns we observed leaking in real workloads that gitleaks does
// not cover (or covers with broader regex than we want for streaming
// log output).
//
// Add a rule here when you find a new format leaking. Each rule MUST:
//
//   - have a stable, descriptive ID (gets logged, signed via redact.why)
//   - have at least one keyword the pre-filter can use (a regex run on
//     every chunk with no pre-filter is a hot-path bug)
//   - match a structurally-anchored token, NOT free-floating entropy
//     (entropy belongs in `thorough` mode, deferred to v1.2.1)
//
// The combined ruleset is built by src/redact/rules/gen.go; this
// file's Rules() result is one input.
package sshgate

import "github.com/karthikeyan5/sshgate/src/redact"

// Rules returns the SSHGate-native rule set. Called once at package
// initialisation by the combined generator.
func Rules() []redact.Rule {
	return []redact.Rule{
		// AWS access key — same structural prefix as gitleaks's rule,
		// but we keep our own copy so SSHGate's floor is stable even
		// when we re-vendor gitleaks.
		redact.CompileRule(
			"sshgate-aws-access-key",
			"AWS access key (AKIA/ASIA/AGPA/AROA prefix)",
			`\b((?:AKIA|ASIA|AGPA|AROA)[0-9A-Z]{16})\b`,
			[]string{"AKIA", "ASIA", "AGPA", "AROA"},
			1, 20, 20,
		),

		// GitHub personal-access tokens (classic + fine-grained + OAuth + server).
		redact.CompileRule(
			"sshgate-github-pat",
			"GitHub PAT/OAuth/server token (ghp_, gho_, ghu_, ghs_, ghr_)",
			`\b(gh[psour]_[A-Za-z0-9]{36,251})\b`,
			[]string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
			1, 40, 255,
		),

		// GitLab tokens.
		redact.CompileRule(
			"sshgate-gitlab-pat",
			"GitLab personal/project/group token (glpat-, glptt-)",
			`\b(glp(?:at|tt)-[A-Za-z0-9_\-]{20,50})\b`,
			[]string{"glpat-", "glptt-"},
			1, 26, 56,
		),

		// JWT — header.payload.sig, all three base64url. We anchor on
		// the structurally-identifiable header prefix `eyJ`.
		redact.CompileRule(
			"sshgate-jwt",
			"JSON Web Token (eyJ-prefixed three-part base64url)",
			`\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b`,
			[]string{"eyJ"},
			1, 30, 4096,
		),

		// HTTP Authorization: Bearer header. Token value only.
		// Upper bound is 999 (RE2 max repeat is 1000); MaxLen filter
		// extends to 1024 if a longer token slips through.
		redact.CompileRule(
			"sshgate-auth-bearer",
			"Authorization: Bearer <token>",
			`(?i)authorization:\s*bearer\s+([A-Za-z0-9_\-\.=+/]{8,999})`,
			[]string{"authorization", "bearer"},
			1, 8, 1024,
		),

		// password=foo / pwd=foo / passwd=foo (URL-/env-style). The
		// rule fires on the value only; common log noise like
		// "password = ****" passes through because the value-character
		// class excludes spaces and the like.
		redact.CompileRule(
			"sshgate-password-kv",
			"password=/pwd=/passwd= key-value (URL or env form)",
			`(?i)\b(?:password|passwd|pwd)\s*[=:]\s*['"]?([^\s'";&,<>]{4,256})['"]?`,
			[]string{"password", "passwd", "pwd"},
			1, 4, 256,
		),

		// Slack tokens (xoxb-, xoxp-, xoxa-, xoxr-, xoxs-).
		redact.CompileRule(
			"sshgate-slack-token",
			"Slack token (xox[bparso]-...)",
			`\b(xox[bparso]-[A-Za-z0-9\-]{10,255})\b`,
			[]string{"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxo-"},
			1, 15, 255,
		),

		// Stripe live keys.
		redact.CompileRule(
			"sshgate-stripe-live",
			"Stripe live API key (sk_live_/pk_live_/rk_live_)",
			`\b([srp]k_live_[A-Za-z0-9]{24,99})\b`,
			[]string{"sk_live_", "pk_live_", "rk_live_"},
			1, 30, 110,
		),

		// Google OAuth access token (ya29.<base64>).
		redact.CompileRule(
			"sshgate-google-oauth",
			"Google OAuth access token (ya29.<payload>)",
			`\b(ya29\.[A-Za-z0-9_\-]{20,255})\b`,
			[]string{"ya29."},
			1, 25, 255,
		),

		// Azure storage AccountKey embedded in a connection string.
		redact.CompileRule(
			"sshgate-azure-account-key",
			"Azure storage AccountKey (in connection string)",
			`AccountKey=([A-Za-z0-9+/=]{40,200})`,
			[]string{"AccountKey="},
			1, 40, 200,
		),
	}
}
