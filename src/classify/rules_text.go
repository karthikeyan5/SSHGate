package classify

import (
	"strings"
)

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
