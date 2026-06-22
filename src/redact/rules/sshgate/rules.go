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
		// the structurally-identifiable header prefix `eyJ`. High-
		// confidence: a JWT is unmistakable, so an over-4096-char token
		// is still redacted (MaxLen is advisory here, not a drop —
		// MINOR 7).
		redact.CompileRule(
			"sshgate-jwt",
			"JSON Web Token (eyJ-prefixed three-part base64url)",
			`\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b`,
			[]string{"eyJ"},
			1, 30, 4096,
		).WithHighConfidence(),

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

		// --- BLOCKER 3(a): secret VALUES behind common assignment
		// shapes. The existing sshgate-password-kv rule only covers
		// password/passwd/pwd; an env dump / .env / `printenv` leaks a
		// far wider surface — *_KEY, *_TOKEN, *_SECRET, *_PASSWORD,
		// *_PASS, PGPASSWORD, etc. These rules redact the VALUE only and
		// bias toward over-redacting: some assignment values that aren't
		// truly secret will be scrubbed, which is the safe failure mode
		// for a single-tap unsigned read path.

		// Assignment of a secret-looking value to a key whose NAME ends
		// in a sensitive word (KEY/TOKEN/SECRET/PASSWORD/PASS/PASSWD/PWD/
		// APIKEY/ACCESSKEY/PRIVATEKEY/CREDENTIAL). Matches `NAME=value`,
		// `NAME = value`, `NAME: value`, optional `export ` prefix, and
		// quoted values (which may contain spaces). Value group is #2.
		//
		// The unquoted value class excludes whitespace/quotes/shell
		// metacharacters so we redact one token, not the rest of the
		// line. Quoted values capture everything up to the closing quote
		// (so `PASSWORD="my secret"` is fully covered).
		// SecretGroup 1 captures the whole value — including its
		// surrounding quotes when present — so a quoted value with
		// spaces (`PASSWORD="my secret"`) is redacted in full while the
		// variable NAME and the `=`/`:` separator survive. The keyword
		// stem (KEY/TOKEN/SECRET/PASSWORD/PASS/PASSWD/PWD/CREDENTIAL) must
		// sit at the END of the variable name (a `_` or name-start before
		// it) so `KEYBOARD=` / `TOKENIZER=` don't trip it.
		redact.CompileRule(
			"sshgate-sensitive-assignment",
			"Secret value assigned to a *KEY/*TOKEN/*SECRET/*PASSWORD/*PASS-named variable",
			`(?i)(?:export\s+)?(?:[A-Z0-9]+[_-])?(?:API[_-]?KEY|ACCESS[_-]?KEY|SECRET[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|PWD|CREDENTIALS?)\s*[:=]\s*("[^"\n]{1,1000}"|'[^'\n]{1,1000}'|[^\s'"`+"`"+`;&|<>$(){}]{4,1000})`,
			[]string{"key", "token", "secret", "password", "pass", "passwd", "pwd", "credential"},
			1, 4, 0,
		),

		// PGPASSWORD is special-cased: the libpq env var name has no
		// `_PASS` boundary the rule above keys on cleanly, and it is an
		// extremely common leak in `env` / `ps -e` dumps.
		redact.CompileRule(
			"sshgate-pgpassword",
			"PGPASSWORD libpq environment variable",
			`(?i)\bPGPASSWORD\s*[:=]\s*("[^"\n]{1,1000}"|'[^'\n]{1,1000}'|[^\s'"`+"`"+`;&|<>$(){}]{1,1000})`,
			[]string{"pgpassword"},
			1, 1, 0,
		),

		// --- BLOCKER 3(b): URL-embedded credentials
		// scheme://user:PASSWORD@host. Redacts the password component of
		// a userinfo-bearing URL for the common DB / cache / web schemes.
		// SecretGroup 1 is the password between the first ':' after the
		// scheme and the '@'.
		redact.CompileRule(
			"sshgate-url-userinfo-password",
			"Password embedded in a scheme://user:pass@host URL",
			`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?|https?|ftp|ssh)://[^\s:/@]+:([^\s:/@]+)@`,
			[]string{"://"},
			1, 1, 4096,
		),

		// --- BLOCKER 3(c): modern provider prefixes the vendored
		// gitleaks snapshot predates. Anchored on a structural prefix so
		// the pre-filter keyword carries its weight.

		// OpenAI project keys (sk-proj-...) and legacy (sk-...). We anchor
		// on `sk-proj-` and `sk-ant-api03-` separately so the bare `sk-`
		// stays out (too noisy). Order in the alternation matters: the
		// longer, more specific prefixes are tried first.
		redact.CompileRule(
			"sshgate-openai-project-key",
			"OpenAI project/secret key (sk-proj-, sk-svcacct-)",
			`\b(sk-(?:proj|svcacct|None|admin)-[A-Za-z0-9_\-]{20,300})\b`,
			[]string{"sk-proj-", "sk-svcacct-", "sk-none-", "sk-admin-"},
			1, 24, 320,
		),

		// Anthropic API keys (sk-ant-api03-...).
		redact.CompileRule(
			"sshgate-anthropic-key",
			"Anthropic API key (sk-ant-...)",
			`\b(sk-ant-[A-Za-z0-9_\-]{20,300})\b`,
			[]string{"sk-ant-"},
			1, 24, 320,
		),

		// DigitalOcean PATs (dop_v1_<64 hex>) and OAuth (doo_v1_, dor_v1_).
		redact.CompileRule(
			"sshgate-digitalocean-token",
			"DigitalOcean token (dop_v1_/doo_v1_/dor_v1_)",
			`\b(do[opr]_v1_[a-f0-9]{64})\b`,
			[]string{"dop_v1_", "doo_v1_", "dor_v1_"},
			1, 71, 71,
		),

		// xAI (Grok) API keys (xai-...).
		redact.CompileRule(
			"sshgate-xai-key",
			"xAI / Grok API key (xai-...)",
			`\b(xai-[A-Za-z0-9_\-]{20,200})\b`,
			[]string{"xai-"},
			1, 24, 220,
		),

		// Groq API keys (gsk_...).
		redact.CompileRule(
			"sshgate-groq-key",
			"Groq API key (gsk_...)",
			`\b(gsk_[A-Za-z0-9]{40,200})\b`,
			[]string{"gsk_"},
			1, 44, 220,
		),

		// Google API keys (AIza...) — Maps/Firebase/etc.
		redact.CompileRule(
			"sshgate-google-api-key",
			"Google API key (AIza...)",
			`\b(AIza[A-Za-z0-9_\-]{35})\b`,
			[]string{"AIza"},
			1, 39, 39,
		),

		// Hugging Face access tokens (hf_...).
		redact.CompileRule(
			"sshgate-huggingface-token",
			"Hugging Face access token (hf_...)",
			`\b(hf_[A-Za-z0-9]{30,200})\b`,
			[]string{"hf_"},
			1, 33, 220,
		),

		// npm automation/access tokens (npm_...).
		redact.CompileRule(
			"sshgate-npm-token",
			"npm access token (npm_...)",
			`\b(npm_[A-Za-z0-9]{36})\b`,
			[]string{"npm_"},
			1, 40, 40,
		),
	}
}
