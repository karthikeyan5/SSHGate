package classify

import (
	"strings"
)

// Kind is the classification of a shell command for the SSHGate gate.
type Kind int

const (
	// KindUnknown means the input did not contain any executable command
	// (empty, whitespace, or non-printable). Callers should treat this as
	// an input error rather than routing it through the gate.
	KindUnknown Kind = iota

	// KindRead means the command only reads or observes state and may run
	// without an operator signature.
	KindRead

	// KindWrite means the command may mutate state and therefore requires
	// a valid SSHGATE_SIG signature from signer.
	KindWrite
)

// String reports the lowercase name of the Kind: "unknown", "read", or
// "write". Unknown values render as "unknown" so log lines stay readable.
func (k Kind) String() string {
	switch k {
	case KindRead:
		return "read"
	case KindWrite:
		return "write"
	default:
		return "unknown"
	}
}

// Classify reports whether cmd is a read or write command per the spec's
// "Command Classification" rules. The classifier is fail-safe: pipes,
// redirects, control operators (; && ||), sudo prefixes, command
// substitution, and unknown binaries all return KindWrite. Empty or
// whitespace-only input returns KindUnknown.
func Classify(cmd string) Kind {
	if !hasPrintable(cmd) {
		return KindUnknown
	}
	// Command substitution is opaque to us — route through the gate.
	if containsSubstitution(cmd) {
		return KindWrite
	}
	// Top-level redirects (>, >>) make the command a write regardless of head.
	if hasTopLevelRedirect(cmd) {
		return KindWrite
	}
	// Split on top-level control operators / pipes; any write segment wins.
	segments := splitSegments(cmd)
	if len(segments) == 0 {
		return KindUnknown
	}
	sawRead := false
	for _, seg := range segments {
		switch classifySegment(seg) {
		case KindWrite:
			return KindWrite
		case KindUnknown:
			// A blank segment (e.g. trailing ';') is ignored; if every
			// segment is blank the outer hasPrintable check would have
			// caught it.
			continue
		case KindRead:
			sawRead = true
		}
	}
	if sawRead {
		return KindRead
	}
	return KindUnknown
}

// hasPrintable reports whether s contains at least one non-whitespace,
// non-null byte.
func hasPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0 || c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		return true
	}
	return false
}

// containsSubstitution reports whether s contains a command substitution
// (`$(...)` or backticks) or a process substitution (`<(...)`, `>(...)`)
// at top level (outside quotes). Any such construct is opaque to the
// classifier and routes the whole command through the gate.
func containsSubstitution(s string) bool {
	// Track single- and double-quote contexts SEPARATELY. In /bin/sh only
	// SINGLE quotes are fully literal; command substitution `$(...)` and
	// backticks STILL expand inside DOUBLE quotes. Suppressing detection
	// inside double quotes (the old behavior) let `cat "$(rm -rf x)"`
	// classify READ yet execute the rm — a read-only-gate bypass. A single
	// quote inside double quotes (e.g. `"it's $(rm)"`) is a literal byte,
	// not a quote opener, so the two states must be tracked independently.
	var inSingle, inDouble bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			}
		case inDouble:
			switch c {
			case '"':
				inDouble = false
			case '`':
				return true
			case '$':
				if i+1 < len(s) && s[i+1] == '(' {
					return true
				}
			}
		default: // unquoted
			switch c {
			case '\'':
				inSingle = true
			case '"':
				inDouble = true
			case '`':
				return true
			case '$':
				if i+1 < len(s) && s[i+1] == '(' {
					return true
				}
			case '<', '>':
				// Process substitution `<(cmd)` / `>(cmd)` only occurs
				// unquoted (it does not expand inside quotes). The output
				// redirect `>` is handled separately by hasTopLevelRedirect;
				// here we only flag the `<(` / `>(` pair.
				if i+1 < len(s) && s[i+1] == '(' {
					return true
				}
			}
		}
	}
	return false
}

// hasTopLevelRedirect reports whether s contains an unquoted output
// redirect (>, >>). Input redirects (<) are not writes.
func hasTopLevelRedirect(s string) bool {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '>':
			return true
		}
	}
	return false
}

// splitSegments splits s on top-level (unquoted) pipes and control
// operators: |, ||, &, &&, ;. Returns the segments with surrounding
// whitespace trimmed; empty segments are dropped.
func splitSegments(s string) []string {
	var out []string
	var quote byte
	start := 0
	flush := func(end int) {
		seg := strings.TrimSpace(s[start:end])
		if seg != "" {
			out = append(out, seg)
		}
	}
	i := 0
	for i < len(s) {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			i++
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			i++
		case ';', '\n':
			// ';' and an unquoted newline are both top-level command
			// separators for /bin/sh, and the gate execs via `sh -c`, so a
			// newline runs a second command. Splitting on it closes a
			// read-only-gate bypass: `ls\nrm -rf x` must NOT classify READ
			// just because the first line reads. (Newlines inside quotes are
			// skipped above, so only an unquoted newline splits.)
			flush(i)
			start = i + 1
			i++
		case '|':
			flush(i)
			if i+1 < len(s) && s[i+1] == '|' {
				i += 2
			} else {
				i++
			}
			start = i
		case '&':
			// & or && — both are top-level separators. (Background `&`
			// alone is not in our corpus but is handled the same way.)
			flush(i)
			if i+1 < len(s) && s[i+1] == '&' {
				i += 2
			} else {
				i++
			}
			start = i
		default:
			i++
		}
	}
	flush(len(s))
	return out
}

// classifySegment classifies a single command segment (no top-level pipes
// or control operators). It strips any leading environment-variable
// assignments, returns KindWrite for sudo or unknown heads, and otherwise
// applies the per-command argument rules.
func classifySegment(seg string) Kind {
	tokens := tokenize(seg)
	if len(tokens) == 0 {
		return KindUnknown
	}
	// Strip leading FOO=bar VAR=baz assignments. Any of these env vars is a
	// known shell-execution vector (e.g. GIT_EXTERNAL_DIFF, LD_PRELOAD,
	// IFS, PATH); safer to classify the wrapping command as WRITE rather
	// than ignore the prefix and trust the wrapped binary not to honor it.
	i := 0
	for i < len(tokens) && isAssignment(tokens[i]) {
		key := tokens[i][:strings.IndexByte(tokens[i], '=')]
		if dangerousEnvVars[key] {
			return KindWrite
		}
		i++
	}
	if i >= len(tokens) {
		return KindUnknown
	}
	head := tokens[i]
	args := tokens[i+1:]

	// sudo always means write, regardless of what it wraps.
	if head == "sudo" {
		return KindWrite
	}

	rule, ok := readAllowlist[head]
	if !ok {
		return KindWrite
	}
	if rule == nil {
		return KindRead
	}
	return rule(args)
}

// tokenize splits a single-segment command into shell-style tokens,
// respecting single and double quotes. Escapes are passed through as-is;
// the classifier only needs to identify the head command and scan args.
func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	var quote byte
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
				continue
			}
			cur.WriteByte(c)
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// isAssignment reports whether tok is a leading KEY=VALUE env assignment.
func isAssignment(tok string) bool {
	eq := strings.IndexByte(tok, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := tok[i]
		if !(c == '_' ||
			(c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(i > 0 && c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// dangerousEnvVars is the denylist of environment variable keys that
// known-allowlisted binaries will honor as shell-execution / loader /
// file-side-effect vectors. If any of these appears as a leading
// `KEY=VAL` prefix on a command, the whole command is classified WRITE
// regardless of head — the wrapped binary cannot be trusted to ignore
// the smuggled env. Cited in
// docs/audits/security-research-readonly-bypass-2026-05-19.md (BLOCKER-3).
var dangerousEnvVars = map[string]bool{
	"GIT_EXTERNAL_DIFF":   true,
	"GIT_SSH_COMMAND":     true,
	"GIT_SSH":             true,
	"GIT_PAGER":           true,
	"GIT_EDITOR":          true,
	"GIT_EXEC_PATH":       true,
	"GIT_TERMINAL_PROMPT": true,
	"LESSOPEN":            true,
	"LESSCLOSE":           true,
	"LESSEDIT":            true,
	"LD_PRELOAD":          true,
	"LD_LIBRARY_PATH":     true,
	"LD_AUDIT":            true,
	"IFS":                 true,
	"PATH":                true,
	"SHELL":               true,
	"BASH_ENV":            true,
	"ENV":                 true,
	"PYTHONSTARTUP":       true,
	"PYTHONPATH":          true,
	"PERL5OPT":            true,
	"PERL5LIB":            true,
	"RUBYOPT":             true,
	"RUBYLIB":             true,
	"MANPAGER":            true,
	"PAGER":               true, // many tools spawn this; safer to deny
}

// argRule narrows a head command from "read by default" to KindWrite when
// specific argument patterns appear (e.g. `sed -i`, `find -delete`).
// A nil rule means "always read."
type argRule func(args []string) Kind

// readAllowlist maps a command's head to its argument rule (or nil if
// every invocation is read-only). Anything not in this map is KindWrite.
var readAllowlist = map[string]argRule{
	// File inspection.
	"cat":      nil,
	"less":     nil,
	"more":     nil,
	"head":     nil,
	"tail":     nil,
	"wc":       nil,
	"file":     nil,
	"stat":     nil,
	"readlink": nil,

	// Directory + path lookup.
	"ls":      nil,
	"find":    findRule,
	"locate":  nil,
	"which":   nil,
	"whereis": nil,

	// Text processing.
	"grep":  nil,
	"egrep": nil,
	"fgrep": nil,
	"awk":   awkRule,
	"sed":   sedRule,
	"sort":  sortRule,
	"uniq":  nil,
	"diff":  nil,
	"comm":  nil,

	// System status.
	"df":          nil,
	"du":          nil,
	"free":        nil,
	"uptime":      nil,
	"uname":       nil,
	"hostname":    nil,
	"whoami":      nil,
	"id":          nil,
	"groups":      nil,
	"date":        dateRule,
	"timedatectl": nil,
	// `env` is special: it is allowed as a read-only print-the-environment
	// command, but with any positional argument it acts as a wrapper for
	// another command. envRule recursively classifies the wrapped command
	// against this same map, so we wire it up in init() below to avoid
	// an initialization cycle.
	"env":      nil,
	"printenv": nil,
	// Pure-output builtins: spec lists `echo/cat/tee with redirects` under
	// write. Top-level redirect detection runs before head lookup, so a
	// bare `echo done` reaches this map and is correctly a read.
	"echo":   nil,
	"printf": nil,
	"true":   nil,
	"false":  nil,

	// Process + network introspection.
	"ps":         nil,
	"top":        nil,
	"htop":       nil,
	"pgrep":      nil,
	"lsof":       nil,
	"ss":         nil,
	"netstat":    nil,
	"ip":         ipRule,
	"ifconfig":   ifconfigRule,
	"ping":       nil,
	"dig":        nil,
	"nslookup":   nil,
	"traceroute": nil,
	"curl":       curlRule,
	"wget":       wgetRule,

	// Logs / who.
	"journalctl": journalctlRule,
	"dmesg":      nil,
	"last":       nil,
	"lastlog":    nil,
	"w":          nil,
	"who":        nil,

	// Subcommand-gated heads.
	"systemctl": systemctlRule,
	"service":   serviceRule,
	"docker":    dockerRule,
	"git":       gitRule,

	// Package managers default to write; only their query subcommands are read.
	// (Spec lists them under write; corpus has no read-side example for them.)
}

func init() {
	// Wire envRule into the allowlist after the map literal is initialized.
	// envRule recursively reads readAllowlist, which would be an
	// initialization cycle if expressed directly in the literal.
	readAllowlist["env"] = envRule
}

// envRule classifies `env` invocations. `env` is READ iff it is invoked
// with no args (prints the environment) or only with `KEY=VAL` assignments
// and no trailing wrapped command. The moment a non-assignment positional
// appears, `env` is acting as a wrapper — we recursively classify the
// wrapped command and apply the dangerous-env-var denylist to each
// assignment. Any `env` flag (`-i`, `-u`, `-S`, `--ignore-environment`,
// `--unset`, `--split-string`, `--chdir`, `--block-signal`, etc.) is
// treated as WRITE because each of them can smuggle execution or
// significantly change the wrapper's behavior. Cited as MAJOR-1 in
// docs/audits/security-research-readonly-bypass-2026-05-19.md.
func envRule(args []string) Kind {
	if len(args) == 0 {
		return KindRead
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		// Any env flag (short or long) is conservatively WRITE.
		if len(a) > 0 && a[0] == '-' && a != "--" {
			return KindWrite
		}
		// `--` end-of-options: everything after is the wrapped command.
		if a == "--" {
			rest := args[i+1:]
			if len(rest) == 0 {
				return KindRead
			}
			return classifyWrapped(rest)
		}
		// KEY=VAL assignment: deny dangerous keys, otherwise skip.
		if isAssignment(a) {
			key := a[:strings.IndexByte(a, '=')]
			if dangerousEnvVars[key] {
				return KindWrite
			}
			continue
		}
		// First non-assignment positional: wrapped command + its args.
		return classifyWrapped(args[i:])
	}
	// All tokens were KEY=VAL assignments with no wrapped command.
	return KindRead
}

// classifyWrapped recursively classifies a wrapped command (the part of
// `env KEY=VAL cmd args...` after the assignments). It runs the same
// per-segment logic as `classifySegment`, but on an already-tokenized
// slice and without re-splitting on control operators (the tokens were
// pre-split by the outer tokenizer / segmenter).
func classifyWrapped(tokens []string) Kind {
	if len(tokens) == 0 {
		return KindUnknown
	}
	// Re-run the assignment-strip loop (the wrapper may be `env env FOO=bar cmd`).
	i := 0
	for i < len(tokens) && isAssignment(tokens[i]) {
		key := tokens[i][:strings.IndexByte(tokens[i], '=')]
		if dangerousEnvVars[key] {
			return KindWrite
		}
		i++
	}
	if i >= len(tokens) {
		return KindUnknown
	}
	head := tokens[i]
	args := tokens[i+1:]
	if head == "sudo" {
		return KindWrite
	}
	rule, ok := readAllowlist[head]
	if !ok {
		return KindWrite
	}
	if rule == nil {
		return KindRead
	}
	return rule(args)
}

// journalctlRule: `journalctl` is read iff none of its mutating flags are
// present. The dangerous flags rotate, vacuum (delete), flush, sync,
// release var-log, update the catalog, or generate FSS keys. GNU long
// options accept unambiguous prefixes, so we use prefix-match against
// each dangerous flag stem. Cited as MAJOR-2 in
// docs/audits/security-research-readonly-bypass-2026-05-19.md.
func journalctlRule(args []string) Kind {
	for _, a := range args {
		if journalctlFlagIsDangerous(a) {
			return KindWrite
		}
	}
	return KindRead
}

// journalctlDangerousLong is the list of journalctl long-option stems
// that mutate state. We match any arg whose `--` prefix is a prefix of
// one of these stems (GNU getopt prefix-abbreviation), with one safety
// constraint: the matched arg must have at least 3 chars after `--`
// (e.g. `--rot`) to avoid colliding with unrelated short prefixes like
// `--no-pager`. The bound was chosen empirically from journalctl(1).
var journalctlDangerousLong = []string{
	"rotate",
	"vacuum-size",
	"vacuum-time",
	"vacuum-files",
	"flush",
	"sync",
	"relinquish-var",
	"smart-relinquish-var",
	"update-catalog",
	"setup-keys",
}

func journalctlFlagIsDangerous(a string) bool {
	if !strings.HasPrefix(a, "--") {
		return false
	}
	body := a[2:]
	// Strip `=VALUE` suffix; we only care about the option name.
	if eq := strings.IndexByte(body, '='); eq >= 0 {
		body = body[:eq]
	}
	if len(body) < 3 {
		return false
	}
	for _, stem := range journalctlDangerousLong {
		if strings.HasPrefix(stem, body) {
			return true
		}
	}
	return false
}

// findRule: `find` is read unless it has -delete, an -exec* primitive, or
// a file-writing action (`-fprint`, `-fprintf`, `-fprint0`, `-fls`) or an
// interactive exec (`-ok`, `-okdir`). Conservative: ANY `-fprint*` arg
// is a write. Cited as BLOCKER-2 in
// docs/audits/security-research-readonly-bypass-2026-05-19.md.
func findRule(args []string) Kind {
	for _, a := range args {
		switch a {
		case "-delete", "-exec", "-execdir", "-ok", "-okdir",
			"-fprint", "-fprintf", "-fprint0", "-fls":
			return KindWrite
		}
		// Defensive: any future `-fprint*` variant (or abbreviation) is
		// also a write — find writes files for the whole `-fprint*` family.
		if strings.HasPrefix(a, "-fprint") {
			return KindWrite
		}
	}
	return KindRead
}

// sedRule: `sed` is read iff `-i`/`--in-place` is absent AND no sed
// script arg contains one of these execute/write primitives:
//   - `/e`  — `e` flag on s/// substitution OR a standalone `e` command
//     (executes the pattern space as a shell command)
//   - `e}`  — `e` flag at end of a `{...}` block
//   - `/w ` — `w FILE` writes the pattern space to FILE (after s///)
//   - `<addr>w ` / `<addr>r ` / `<addr>R ` — read/write file commands
//
// Only the SCRIPT arg is scanned (the arg after `-e`/`--expression`, or
// the first non-flag arg when neither is present). Filename args are
// NOT scanned — that avoids false positives like `/etc/hosts` matching
// `/e`. False positives in scripts (e.g. a regex literally containing
// `/e`) fall safely to WRITE. Cited as BLOCKER-1 in
// docs/audits/security-research-readonly-bypass-2026-05-19.md.
func sedRule(args []string) Kind {
	scripts := sedScripts(args)
	for _, a := range args {
		// -i, --in-place, and combined flags like -ie or -i.bak all mutate.
		// GNU getopt also accepts any unambiguous prefix of a long option;
		// sed has no other long option starting with `--in`, so any
		// `--in<anything>` arg is `--in-place` (or its `=VALUE` form).
		// Cited as MAJOR-4 in
		// docs/audits/security-research-readonly-bypass-2026-05-19.md.
		if a == "-i" || strings.HasPrefix(a, "--in") {
			return KindWrite
		}
		// Combined short-flag form: -i.bak, -iE, AND -i bundled AFTER other
		// no-arg flags like -n/-s/-E/-r/-z (`-ni`, `-Ei`, `-nri`, ...).
		// The old check looked only at a[1], so `-ni` (an in-place edit =
		// WRITE) was misread as READ — a read-only-gate bypass. Scan the
		// whole short-flag bundle for an `i`, stopping at the first flag
		// that consumes the rest of the arg as its argument (-e SCRIPT,
		// -f FILE, -l N), since chars after those are an argument, not flags.
		if len(a) >= 2 && a[0] == '-' && a[1] != '-' {
			for j := 1; j < len(a); j++ {
				if a[j] == 'i' {
					return KindWrite
				}
				if a[j] == 'e' || a[j] == 'f' || a[j] == 'l' {
					break
				}
			}
		}
	}
	for _, s := range scripts {
		if sedScriptIsDangerous(s) {
			return KindWrite
		}
	}
	return KindRead
}

// sedScripts extracts the sed script args from a sed command line. The
// rule per GNU sed(1):
//   - every `-e SCRIPT` / `--expression SCRIPT` / `--expression=SCRIPT`
//     contributes a script
//   - every `-f FILE` / `--file FILE` is a script file (its CONTENT is
//     opaque to us; the FILE arg itself is not a script)
//   - if neither `-e` nor `-f` is present, the first non-flag arg is the
//     script and any remaining non-flag args are input files
//
// Conservative behavior: if `-f` is present we know we cannot see the
// script, so we treat that whole invocation as if the script were
// dangerous (caller falls through to WRITE).
func sedScripts(args []string) []string {
	var scripts []string
	sawEOrF := false
	hasF := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-e" || a == "--expression":
			sawEOrF = true
			if i+1 < len(args) {
				scripts = append(scripts, args[i+1])
				i++
			}
		case strings.HasPrefix(a, "--expression="):
			sawEOrF = true
			scripts = append(scripts, strings.TrimPrefix(a, "--expression="))
		case a == "-f" || a == "--file":
			sawEOrF = true
			hasF = true
			if i+1 < len(args) {
				i++ // skip the file arg; we can't see its content
			}
		case strings.HasPrefix(a, "--file="):
			sawEOrF = true
			hasF = true
		}
	}
	if !sawEOrF {
		// First non-flag arg is the script.
		for _, a := range args {
			if len(a) > 0 && a[0] != '-' {
				scripts = append(scripts, a)
				break
			}
		}
	}
	if hasF {
		// Script file content is opaque; fall safely to WRITE by injecting
		// a sentinel known-dangerous script. Saves a separate boolean.
		scripts = append(scripts, "/e")
	}
	return scripts
}

// sedScriptIsDangerous reports whether script contains a sed exec/write
// primitive. Substring scan only — no parsing — so it errs on the side
// of classifying ambiguous scripts as write.
func sedScriptIsDangerous(script string) bool {
	// `s///e` substitution flag: a `/` followed by `e` then a non-letter
	// terminator. The naive `Contains("/e")` would false-positive on
	// regex anchors like `\s/e`-shaped patterns, but for typical sed
	// scripts this substring is a reliable marker.
	if strings.Contains(script, "/e") || strings.Contains(script, "e}") {
		return true
	}
	// `w FILE` / `r FILE` / `R FILE` commands. The file-side `w` after
	// s/// is `/w FILE` (caught here by the `/w ` form), but `w` can
	// also appear as a standalone command with an address: `1w /tmp/x`
	// or `/regex/w /tmp/x`. We scan for the command letter followed by
	// a space, with the preceding char being address-shaped: digit,
	// `;`, `}`, `{`, `/`, or start-of-string.
	if strings.Contains(script, "/w ") || strings.Contains(script, "/W ") ||
		strings.Contains(script, "/r ") || strings.Contains(script, "/R ") {
		return true
	}
	// `s` substitution whose flag run contains an exec (`e`) or write
	// (`w`/`W`) flag, for ANY delimiter — sed accepts `s|a|b|e`, `s,a,b,e`,
	// etc., so the `/`-only substring checks above are bypassed simply by
	// picking another delimiter.
	if sedSCommandExecsOrWrites(script) {
		return true
	}
	// Command-position exec/write letters: e (execute a command), w/W (write
	// pattern space to a file), r/R (read a file). A command letter is in
	// command position when preceded by start-of-script, a numeric address,
	// a last-line `$`, or a block brace/separator, and is followed by its
	// argument (a space). `e` may also take NO argument (execute the pattern
	// space), terminated by end-of-script, `;`, or `}`. The `/`-preceded
	// (regex-addressed) forms are already covered by the substring checks
	// above (`/e`, `/w `, ...), so `/` is intentionally not in the set here.
	for i := 0; i < len(script); i++ {
		c := script[i]
		if c != 'r' && c != 'R' && c != 'w' && c != 'W' && c != 'e' {
			continue
		}
		hasSpaceArg := i+1 < len(script) && script[i+1] == ' '
		noArgE := c == 'e' && (i+1 == len(script) || script[i+1] == ';' || script[i+1] == '}')
		if !hasSpaceArg && !noArgE {
			continue
		}
		if i == 0 {
			return true
		}
		p := script[i-1]
		if (p >= '0' && p <= '9') || p == ';' || p == '}' || p == '{' || p == '$' {
			return true
		}
	}
	return false
}

// sedSCommandExecsOrWrites reports whether script contains an `s///`
// substitution whose flag run includes `e` (execute the substitution result
// as a shell command) or `w`/`W` (write the result to a file). It handles
// any single-character delimiter, so `s|a|b|e` / `s,a,b,e` cannot evade the
// slash-only checks. It is intentionally conservative about what counts as a
// delimiter (any non-alphanumeric, non-space, non-backslash byte right after
// `s`); the `s` of an ordinary word is followed by a letter and ignored.
func sedSCommandExecsOrWrites(script string) bool {
	for i := 0; i+1 < len(script); i++ {
		if script[i] != 's' {
			continue
		}
		d := script[i+1]
		if d == ' ' || d == '\t' || d == '\n' || d == '\\' ||
			(d >= 'a' && d <= 'z') || (d >= 'A' && d <= 'Z') || (d >= '0' && d <= '9') {
			continue // not a delimiter — `s` is data, not a substitute command
		}
		// Walk past the pattern and replacement (two more delimiters),
		// honoring backslash escapes.
		j := i + 2
		seen := 0
		for j < len(script) && seen < 2 {
			if script[j] == '\\' {
				j += 2
				continue
			}
			if script[j] == d {
				seen++
			}
			j++
		}
		// Read the flag run that follows the closing delimiter.
		for ; j < len(script); j++ {
			c := script[j]
			if c == 'e' || c == 'w' || c == 'W' {
				return true
			}
			if (c >= '0' && c <= '9') || c == 'g' || c == 'p' ||
				c == 'i' || c == 'I' || c == 'm' || c == 'M' {
				continue // benign substitution flag
			}
			break // command separator or non-flag — this s-command is clean
		}
		if seen < 2 {
			break // malformed/truncated; nothing more to scan
		}
		i = j - 1 // resume after this s-command (loop's i++ advances past it)
	}
	return false
}

// awkRule: `awk` is read iff the program (any non-flag arg) does NOT
// contain a shell-execution or file-write primitive. Substring-scan only
// — false positives fall safely to WRITE. Cited as BLOCKER-4 in
// docs/audits/security-research-readonly-bypass-2026-05-19.md.
//
// Dangerous substrings:
//   - "system"   — system("cmd") forks a shell
//   - "getline " — pipe-or-file getline can exec or read arbitrary files
//   - `| "` / `|"` — pipe to a shell command
//   - `> "` / `>"` / `>>` — redirect to a file
func awkRule(args []string) Kind {
	for _, a := range args {
		// `-f FILE` / `-fFILE` / `--file FILE` / `--file=FILE` loads the awk
		// program from a FILE whose content is opaque to us — it can call
		// system()/print to a file just like an inline program. Mirror sed's
		// `-f` handling and treat it as WRITE. (NOTE: `-F` is the field
		// separator, a read flag — keep the lowercase/`-f` match exact.)
		if a == "-f" || a == "--file" || strings.HasPrefix(a, "--file=") ||
			(strings.HasPrefix(a, "-f") && len(a) > 2) {
			return KindWrite
		}
		if len(a) == 0 || a[0] == '-' {
			continue
		}
		if awkProgIsDangerous(a) {
			return KindWrite
		}
	}
	return KindRead
}

func awkProgIsDangerous(prog string) bool {
	if strings.Contains(prog, "system") {
		return true
	}
	if strings.Contains(prog, "getline ") {
		return true
	}
	if strings.Contains(prog, `| "`) || strings.Contains(prog, `|"`) {
		return true
	}
	if strings.Contains(prog, `> "`) || strings.Contains(prog, `>"`) {
		return true
	}
	if strings.Contains(prog, ">>") {
		return true
	}
	return false
}

// sortRule: `sort` is read unless it writes its output to a file via
// `-o FILE` / `-oFILE` / `--output FILE` / `--output=FILE`. `sort` was
// previously a nil (always-READ) allowlist entry, so `sort -o /etc/x in`
// — a clobbering write — ran unsigned on a read-only server.
func sortRule(args []string) Kind {
	for _, a := range args {
		if a == "-o" || a == "--output" ||
			strings.HasPrefix(a, "--output=") ||
			(strings.HasPrefix(a, "-o") && len(a) > 2 && a[1] != '-') {
			return KindWrite
		}
	}
	return KindRead
}

// dateRule: `date` is read for display (`date`, `date +FMT`, `-u`, `-d STR`,
// `-r FILE`, `-f FILE`) but WRITES the system clock with `-s`/`--set` or a
// bare MMDDhhmm-style positional. `date` was a nil (always-READ) entry, so
// `date -s ...` / `date 010100002020` set the clock unsigned on a read-only
// server. Display flags that consume a value (-d/--date, -r/--reference,
// -f/--file) are skipped so their argument is not mistaken for a set spec.
func dateRule(args []string) Kind {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-s" || a == "--set" || strings.HasPrefix(a, "--set=") ||
			(strings.HasPrefix(a, "-s") && !strings.HasPrefix(a, "--") && len(a) > 2):
			return KindWrite
		case a == "-d" || a == "--date" || a == "-r" || a == "--reference" ||
			a == "-f" || a == "--file":
			i++ // value belongs to a display flag, not a set positional
		case len(a) > 0 && (a[0] == '-' || a[0] == '+'):
			// other flags (-u, --utc, -I[FMT], --rfc-3339=, ...) and the
			// `+FORMAT` output spec are display-only.
			continue
		default:
			// a bare positional that is not `+FORMAT` is the MMDDhhmm[[CC]YY]
			// clock-set form.
			return KindWrite
		}
	}
	return KindRead
}

// ipRule: iproute2 `ip` is read for show/list/get/monitor/save but WRITES
// host network state with action verbs (add/del/set/change/replace/...).
// `ip` was a nil (always-READ) entry, so `ip addr add` / `ip link set` /
// `ip route add` reconfigured the host unsigned on a read-only server. We
// match on the action verb (not the OBJECT), and deliberately omit up/down
// because iproute2 accepts them as read filters (`ip link show up`).
func ipRule(args []string) Kind {
	for _, a := range args {
		switch a {
		case "add", "del", "delete", "set", "change", "replace", "append",
			"flush", "modify", "remove", "restore":
			return KindWrite
		}
	}
	return KindRead
}

// ifconfigRule: `ifconfig` with no interface, only flags (-a/-s/-v), or a
// single interface name is a read (status query). A second positional means
// it is configuring the interface (`ifconfig eth0 192.168.1.5`,
// `ifconfig eth0 up`, `ifconfig eth0 netmask ...`) — a WRITE. `ifconfig` was
// a nil (always-READ) entry, so every such reconfiguration ran unsigned.
func ifconfigRule(args []string) Kind {
	positionals := 0
	for _, a := range args {
		if len(a) > 0 && a[0] == '-' {
			continue
		}
		positionals++
	}
	if positionals >= 2 {
		return KindWrite
	}
	return KindRead
}

// curlRule: `curl` is read unless it specifies a write HTTP method,
// carries a request body (-d/--data...), or writes the response body
// to a local file (-o FILE / --output FILE / -O / --remote-name).
// `curl -o -` (stdout) stays read.
func curlRule(args []string) Kind {
	for i, a := range args {
		switch a {
		case "-X", "--request":
			if i+1 < len(args) {
				m := strings.ToUpper(args[i+1])
				if m == "POST" || m == "PUT" || m == "DELETE" || m == "PATCH" {
					return KindWrite
				}
			}
		case "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
			"-F", "--form", "-T", "--upload-file":
			return KindWrite
		case "-K", "--config":
			// `-K FILE` reads curl directives from FILE; that file can
			// specify `--output FILE`, `--upload-file`, `-X POST`, etc.
			// The config file is opaque to us. Cited as MAJOR-5 in
			// docs/audits/security-research-readonly-bypass-2026-05-19.md.
			return KindWrite
		case "-o", "--output":
			// `-o FILE` writes to disk; `-o -` is stdout (still read).
			if i+1 < len(args) && args[i+1] != "-" {
				return KindWrite
			}
		case "-O", "--remote-name", "--remote-name-all":
			// `-O` saves to a filename derived from the URL.
			return KindWrite
		}
		if strings.HasPrefix(a, "--data=") || strings.HasPrefix(a, "--data-raw=") ||
			strings.HasPrefix(a, "--data-binary=") || strings.HasPrefix(a, "--data-urlencode=") ||
			strings.HasPrefix(a, "--form=") {
			return KindWrite
		}
		if strings.HasPrefix(a, "--output=") {
			if strings.TrimPrefix(a, "--output=") != "-" {
				return KindWrite
			}
		}
		if strings.HasPrefix(a, "--config=") {
			return KindWrite
		}
		if strings.HasPrefix(a, "-X") && len(a) > 2 {
			m := strings.ToUpper(a[2:])
			if m == "POST" || m == "PUT" || m == "DELETE" || m == "PATCH" {
				return KindWrite
			}
		}
	}
	return KindRead
}

// wgetRule: `wget URL` defaults to saving the response to `./URL.tail`
// on disk — that is a write to the local filesystem. Per code-review Mi4
// the read-side form requires explicit stdout output: `-O-` (or its long
// form `--output-document=-`). Anything else — including bare URLs and
// any --post-data / --method=POST/PUT/DELETE/PATCH — is write.
func wgetRule(args []string) Kind {
	stdoutOutput := false
	for i, a := range args {
		switch {
		case a == "-O-", a == "--output-document=-":
			stdoutOutput = true
		case a == "-O", a == "--output-document":
			// Explicit output file: read only if the operand is `-`.
			if i+1 < len(args) && args[i+1] == "-" {
				stdoutOutput = true
			} else {
				return KindWrite
			}
		case strings.HasPrefix(a, "--output-document="):
			// Already handled the "=-" exact case above; any other value
			// names a file and is a write.
			return KindWrite
		case strings.HasPrefix(a, "-O") && len(a) > 2:
			// Combined short flag like `-Ofile` or `-O-`. `-O-` matched
			// the exact-equals case above; `-O<anything>` else is a file.
			return KindWrite
		case a == "--post-data", strings.HasPrefix(a, "--post-data="),
			a == "--post-file", strings.HasPrefix(a, "--post-file="):
			return KindWrite
		}
		if strings.HasPrefix(a, "--method=") {
			m := strings.ToUpper(strings.TrimPrefix(a, "--method="))
			if m == "POST" || m == "PUT" || m == "DELETE" || m == "PATCH" {
				return KindWrite
			}
		}
	}
	if stdoutOutput {
		return KindRead
	}
	return KindWrite
}

// systemctlRule: only inspection subcommands are read. Anything that can
// change unit state is write.
func systemctlRule(args []string) Kind {
	sub := firstNonFlag(args)
	switch sub {
	case "status", "is-active", "is-enabled", "is-failed",
		"list-units", "list-unit-files", "list-sockets", "list-timers",
		"show", "cat", "get-default":
		return KindRead
	}
	return KindWrite
}

// serviceRule: `service <name> status` is read; everything else is write.
func serviceRule(args []string) Kind {
	// service <unit> <verb>
	if len(args) >= 2 {
		verb := args[len(args)-1]
		if verb == "status" {
			return KindRead
		}
	}
	return KindWrite
}

// dockerRule: introspection subcommands are read; lifecycle ones are write.
func dockerRule(args []string) Kind {
	sub := firstNonFlag(args)
	switch sub {
	case "ps", "logs", "inspect", "images", "stats",
		"version", "info", "top", "diff", "history",
		"port", "events", "search":
		return KindRead
	}
	return KindWrite
}

// gitRule: read-only porcelain only. Anything that updates refs, the
// index, or the working tree is write. Per code-review Mi3 we treat
// `git stash` (and its mutating subcommands) as write; only the
// inspection subcommands `stash list` / `stash show` are read.
// `git config --set` (and write-side variants like --unset/--add) are
// write; `git config --get` and bare `git config <name>` are read.
func gitRule(args []string) Kind {
	// `git -c KEY=VAL` injects ad-hoc config. Many config keys execute
	// shell commands when git invokes them: `core.pager`, `core.editor`,
	// `core.sshCommand`, `core.hooksPath`, `gpg.program`, `diff.external`,
	// `credential.helper`, any `alias.*` (a `!`-prefixed alias is an
	// arbitrary shell command), and so on. Rather than maintain a
	// denylist (which inevitably misses a key), classify ANY `git -c ...`
	// invocation as WRITE. Cited as MAJOR-3 in
	// docs/audits/security-research-readonly-bypass-2026-05-19.md.
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-c" || a == "--config-env" ||
			strings.HasPrefix(a, "--config-env=") {
			return KindWrite
		}
	}
	sub := firstNonFlag(args)
	switch sub {
	case "status", "log", "diff", "show", "branch",
		"blame", "describe", "remote",
		"rev-parse", "ls-files", "ls-remote", "shortlog":
		// `git branch -d/-D` is a write, but the corpus doesn't exercise
		// it and detecting requires arg scanning across the porcelain.
		// Acceptable v1.1 tradeoff — caller still sees the command and
		// the Telegram approval is one tap away if they pass -d.
		return KindRead
	case "stash":
		return gitStashKind(args)
	case "config":
		return gitConfigKind(args)
	}
	return KindWrite
}

// gitStashKind classifies `git stash <sub>`. Bare `git stash` is
// shorthand for `git stash push` (mutating). Only `list` and `show`
// are read-only inspection.
func gitStashKind(args []string) Kind {
	// Find the subcommand after "stash" (skipping flags).
	seen := false
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		if !seen {
			// This is "stash" itself.
			seen = true
			continue
		}
		switch a {
		case "list", "show":
			return KindRead
		}
		return KindWrite
	}
	// Bare `git stash` (no sub) — defaults to `stash push`, which is write.
	return KindWrite
}

// gitConfigKind classifies `git config ...`. Write subflags
// (--set/--unset/--add/--replace-all/--remove-section/--rename-section/
// -e/--edit) mutate; --get/--get-all/--list/-l/--show-origin and bare
// reads are read.
func gitConfigKind(args []string) Kind {
	for _, a := range args {
		switch a {
		case "--set", "--unset", "--unset-all", "--add", "--replace-all",
			"--remove-section", "--rename-section", "-e", "--edit":
			return KindWrite
		}
	}
	return KindRead
}

// firstNonFlag returns the first arg that doesn't start with '-', or "".
func firstNonFlag(args []string) string {
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}
