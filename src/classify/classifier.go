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
		// A backslash escapes the next byte EVERYWHERE except inside single
		// quotes (in sh, inside '...' a backslash is literal). An escaped
		// quote/$/` is a literal data byte — it must NOT toggle quote state
		// or trigger substitution. Without this, `stat f \'$(rm)` hid its
		// `$(` behind a phantom single-quote and classified READ while
		// /bin/sh ran the substitution — an unsigned-exec bypass.
		if c == '\\' && !inSingle {
			i++ // skip the escaped byte
			continue
		}
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
		// Backslash escapes the next byte unless inside single quotes — an
		// escaped `>` is a literal, not a redirect (and `\"` must not open a
		// phantom quote that hides a real `>`).
		if c == '\\' && quote != '\'' {
			i++
			continue
		}
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
		// Backslash escapes the next byte unless inside single quotes — an
		// escaped separator (`\;`, `\&`, `\|`, escaped newline) is literal
		// and must NOT split, and an escaped quote must NOT open a phantom
		// quote that swallows a real separator (`ls \' && rm` => the `&&`
		// and the `rm` segment must still be seen).
		if c == '\\' && quote != '\'' {
			i += 2
			continue
		}
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
		// Backslash escapes the next byte unless inside single quotes; the
		// escaped char is literal token data, so `\ ` does not split the
		// token and `\'`/`\"` do not toggle quote state.
		if c == '\\' && quote != '\'' {
			if i+1 < len(s) {
				cur.WriteByte(s[i+1])
				i++
			}
			continue
		}
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

// argRule narrows a head command from "read by default" to KindWrite when
// specific argument patterns appear (e.g. `sed -i`, `find -delete`).
// A nil rule means "always read."
type argRule func(args []string) Kind

// readAllowlist maps a command's head to its argument rule (or nil if
// every invocation is read-only). Anything not in this map is KindWrite.
var readAllowlist = map[string]argRule{
	// File inspection.
	"cat":      nil,
	"less":     lessRule,
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
	"timedatectl": timedatectlRule,
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
	"ss":         ssRule,
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
	"dmesg":      dmesgRule,
	"last":       nil,
	"lastlog":    lastlogRule,
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
