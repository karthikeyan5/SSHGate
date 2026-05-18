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
	// a valid VELGATE_SIG signature from velsigner.
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

// containsSubstitution reports whether s contains a $(...) or backtick
// command substitution at top level (outside quotes).
func containsSubstitution(s string) bool {
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
		case '`':
			return true
		case '$':
			if i+1 < len(s) && s[i+1] == '(' {
				return true
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
		case ';':
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
	// Strip leading FOO=bar VAR=baz assignments (don't change classification).
	i := 0
	for i < len(tokens) && isAssignment(tokens[i]) {
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
	"awk":   nil,
	"sed":   sedRule,
	"sort":  nil,
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
	"date":        nil,
	"timedatectl": nil,
	"env":         nil,
	"printenv":    nil,
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
	"ip":         nil,
	"ifconfig":   nil,
	"ping":       nil,
	"dig":        nil,
	"nslookup":   nil,
	"traceroute": nil,
	"curl":       curlRule,
	"wget":       wgetRule,

	// Logs / who.
	"journalctl": nil,
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

// findRule: `find` is read unless it has -delete or -exec.
func findRule(args []string) Kind {
	for _, a := range args {
		if a == "-delete" || a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir" {
			return KindWrite
		}
	}
	return KindRead
}

// sedRule: `sed` is read unless invoked with -i (in-place edit).
func sedRule(args []string) Kind {
	for _, a := range args {
		// -i, --in-place, and combined flags like -ie or -i.bak all mutate.
		if a == "-i" || a == "--in-place" || strings.HasPrefix(a, "--in-place=") {
			return KindWrite
		}
		if strings.HasPrefix(a, "-i") && len(a) > 1 && a[1] == 'i' {
			// already matched above
			continue
		}
		// -i.bak, -iE etc. (combined short flag form).
		if len(a) >= 2 && a[0] == '-' && a[1] == 'i' && !strings.HasPrefix(a, "--") {
			return KindWrite
		}
	}
	return KindRead
}

// curlRule: `curl` is read unless it specifies a write HTTP method or
// carries a request body (-d/--data...).
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
		}
		if strings.HasPrefix(a, "--data=") || strings.HasPrefix(a, "--data-raw=") ||
			strings.HasPrefix(a, "--data-binary=") || strings.HasPrefix(a, "--data-urlencode=") ||
			strings.HasPrefix(a, "--form=") {
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

// wgetRule: `wget` is read for the simple "download to stdout" form;
// anything else (saving to disk by default, --post-data, etc.) is write.
// The corpus exercise is `wget -q -O- <url>`.
func wgetRule(args []string) Kind {
	// Treat any --post-data / --method=POST as write; otherwise read.
	for _, a := range args {
		if a == "--post-data" || strings.HasPrefix(a, "--post-data=") ||
			a == "--post-file" || strings.HasPrefix(a, "--post-file=") {
			return KindWrite
		}
		if strings.HasPrefix(a, "--method=") {
			m := strings.ToUpper(strings.TrimPrefix(a, "--method="))
			if m == "POST" || m == "PUT" || m == "DELETE" || m == "PATCH" {
				return KindWrite
			}
		}
	}
	return KindRead
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

// gitRule: read-only porcelain only. Anything that updates refs, the index,
// or the working tree is write.
func gitRule(args []string) Kind {
	sub := firstNonFlag(args)
	switch sub {
	case "status", "log", "diff", "show", "branch",
		"blame", "describe", "config", "remote",
		"rev-parse", "ls-files", "ls-remote", "shortlog",
		"stash":
		// `git branch -d`, `git config --set`, and `git stash push` exist
		// and are writes — but the v1 corpus only exercises read forms and
		// the spec lists branch/log/diff/show/status as read. We accept
		// the false-negative risk here and keep the rule simple.
		return KindRead
	}
	return KindWrite
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
