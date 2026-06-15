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
	// a last-line `$`, or a block brace/separator (`;`, `}`, `{`).
	//
	// These commands glue their filename/command directly to the command
	// letter with NO space — GNU sed reads `w/tmp/x`, `$w/tmp/x`, `1euname`
	// the same as `w /tmp/x`. So once we know the letter is in command
	// position, it IS the command regardless of what follows: we drop the
	// "followed by a space" requirement that previously missed the glued
	// forms (`sed '$w/tmp/x'`, `sed 'w/tmp/x'`, `sed '1euname'` all bypassed
	// READ before this fix). The `/`-preceded (regex-addressed) forms remain
	// covered by the substring checks above, so `/` is not in the set here.
	for i := 0; i < len(script); i++ {
		c := script[i]
		if c != 'r' && c != 'R' && c != 'w' && c != 'W' && c != 'e' {
			continue
		}
		// GNU sed allows whitespace between an address and its command
		// (`1 w f`, `$ w f`, `1,$ w f`, `/re/ w f`), which the old
		// direct-predecessor check missed (a 2026-06-14 red-team bypass).
		// Skip back over that whitespace to the effective preceding char.
		k := i - 1
		spaced := false
		for k >= 0 && (script[k] == ' ' || script[k] == '\t') {
			k--
			spaced = true
		}
		if k < 0 {
			return true // command letter at start (after optional whitespace)
		}
		p := script[k]
		if (p >= '0' && p <= '9') || p == ';' || p == '}' || p == '{' || p == '$' {
			return true
		}
		// A `/` counts as an address-close ONLY when whitespace separated it
		// from the command letter (`/re/ w f`). A `/` glued directly to the
		// letter is a regex-OPEN delimiter (`/re/d`, `/end/p`, `/warn/d`), NOT
		// an address close — including it there would false-positive every
		// regex starting with r/w/e. (The glued write form `/re/w file` stays
		// covered by the `/w ` substring check above.)
		if spaced && p == '/' {
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
//   - "getline"  at a word boundary — pipe-or-file getline can exec or read
//     arbitrary files (incl. the no-space form `"cmd"|getline}`)
//   - `| "` / `|"` — pipe to a shell command
//   - `>` followed (after any whitespace) by a `"` or `(` — redirect to a
//     file or a parenthesized filename; `>>` (append) is always a redirect.
//     A bare `>` between expressions (`$3>100`, `$3 > 100`) is a COMPARISON
//     and must stay READ, so a `>` followed by a digit/identifier is ignored.
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
	// `getline` at a word boundary: the next char must NOT be an awk
	// identifier char, so `getline x`, `getline}`, `getline)`, `getline<`
	// and bare `getline` at end-of-program all match, but a longer
	// identifier like `getlines` (a user variable) does not. The old
	// `"getline "` (trailing-space) check missed `"cmd"|getline}` — a
	// redirect-into-getline exec primitive. Cited by the 2026-06-14 review.
	if containsGetline(prog) {
		return true
	}
	if strings.Contains(prog, `| "`) || strings.Contains(prog, `|"`) {
		return true
	}
	// `>>` (append) is always a file redirect.
	if strings.Contains(prog, ">>") {
		return true
	}
	// A single `>` is a file redirect when the next non-space char is a
	// string literal (`"`) or a parenthesized filename expression (`(`).
	// This catches `> "f"`, `>"f"`, `>  "f"` (multi-space) and `>("f")`
	// while leaving a `>` comparison (`$3>100`, `$3 > 100`) — whose RHS
	// starts with a digit/identifier/`$` — classified READ.
	if redirectsToFileOrPipe(prog) {
		return true
	}
	// A print/printf statement with a TOP-LEVEL redirect (`>`/`>>`) or pipe
	// (`|`) whose target is reached through a VARIABLE — `print x > f`,
	// `print x | c` — writes/execs, but has no literal `"`/`(` after the
	// operator, so redirectsToFileOrPipe misses it. (Found by the 2026-06-14
	// red-team; substring checks cannot see the indirection.)
	if awkProgHasPrintRedirect(prog) {
		return true
	}
	return false
}

// awkProgHasPrintRedirect reports whether prog has a print/printf statement
// with a TOP-LEVEL output redirect (`>`/`>>`) or pipe (`|`) — awk's file-write
// and command-exec primitives — INCLUDING a target reached through a variable
// (`print x > f`, `print x | c`). It matches awk's own grammar: an
// unparenthesized `>`/`|` in a print statement IS a redirect, while the same
// operator inside parens (`print ($3 > 100)`) or outside any print (`$3>100`)
// is a comparison / logical-or and stays READ. String literals are skipped so
// a `>` inside a printed string is not mistaken for a redirect.
func awkProgHasPrintRedirect(prog string) bool {
	for i := 0; i < len(prog); i++ {
		if prog[i] == '"' {
			i = awkSkipString(prog, i)
			continue
		}
		kwLen := 0
		if awkWordAt(prog, i, "printf") {
			kwLen = 6
		} else if awkWordAt(prog, i, "print") {
			kwLen = 5
		}
		if kwLen == 0 {
			continue
		}
		found, end := awkPrintStmtRedirects(prog, i+kwLen)
		if found {
			return true
		}
		i = end
	}
	return false
}

// awkPrintStmtRedirects scans a single print/printf statement starting just
// past the keyword and reports whether it has a top-level (paren-depth 0)
// redirect/pipe, plus the index where the statement ended.
func awkPrintStmtRedirects(prog string, start int) (bool, int) {
	depth := 0
	for j := start; j < len(prog); j++ {
		switch c := prog[j]; c {
		case '"':
			j = awkSkipString(prog, j)
		case '(', '[', '{':
			depth++
		case ')', ']':
			if depth > 0 {
				depth--
			}
		case '}':
			if depth > 0 {
				depth--
			} else {
				return false, j // the enclosing block ends the statement
			}
		case ';', '\n':
			if depth == 0 {
				return false, j
			}
		case '>':
			// `>` / `>>` redirect, but NOT `>=` (comparison).
			if depth == 0 && (j+1 >= len(prog) || prog[j+1] != '=') {
				return true, j
			}
		case '|':
			// single `|` pipe-to-command, but NOT `||` (logical or).
			if depth == 0 &&
				(j == 0 || prog[j-1] != '|') &&
				(j+1 >= len(prog) || prog[j+1] != '|') {
				return true, j
			}
		}
	}
	return false, len(prog)
}

// awkSkipString returns the index of the closing quote of the string literal
// opening at i (prog[i] == '"'), honoring backslash escapes, or the last
// index if unterminated.
func awkSkipString(prog string, i int) int {
	for j := i + 1; j < len(prog); j++ {
		if prog[j] == '\\' {
			j++
			continue
		}
		if prog[j] == '"' {
			return j
		}
	}
	return len(prog) - 1
}

// awkWordAt reports whether word sits at prog[i] on awk identifier boundaries
// (so `print` matches the keyword but not the `print` in `sprintf`/`printable`).
func awkWordAt(prog string, i int, word string) bool {
	if i+len(word) > len(prog) || prog[i:i+len(word)] != word {
		return false
	}
	if i > 0 && isAwkIdentChar(prog[i-1]) {
		return false
	}
	if i+len(word) < len(prog) && isAwkIdentChar(prog[i+len(word)]) {
		return false
	}
	return true
}

// uniqRule: GNU `uniq [OPTION]... [INPUT [OUTPUT]]` writes its SECOND
// positional as an OUTPUT FILE — `uniq in out` clobbers `out`. uniq was a
// nil (always-READ) allowlist entry, so that write ran unsigned on a
// read-only server (same class as `sort -o`, but via a bare positional;
// found by the 2026-06-14 red-team). READ for 0 or 1 positional; WRITE for
// >= 2. Value-taking short flags (-f/-s/-w + long forms) consume the next arg
// in separate form so it is not miscounted; `-` (stdin) IS a positional.
func uniqRule(args []string) Kind {
	positionals := 0
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) == 0 {
			continue
		}
		if a[0] == '-' && a != "-" {
			switch a {
			case "-f", "--skip-fields", "-s", "--skip-chars", "-w", "--check-chars":
				i++ // separate-form value belongs to the flag, not a positional
			}
			continue
		}
		positionals++ // a real positional (a filename, or `-` for stdin)
	}
	if positionals >= 2 {
		return KindWrite
	}
	return KindRead
}

// containsGetline reports whether prog uses the `getline` keyword at a word
// boundary (preceding char, if any, is also not an identifier char, so it is
// a keyword and not the tail of a longer identifier).
func containsGetline(prog string) bool {
	const kw = "getline"
	for i := 0; i+len(kw) <= len(prog); i++ {
		if prog[i:i+len(kw)] != kw {
			continue
		}
		if i > 0 && isAwkIdentChar(prog[i-1]) {
			continue // tail of a longer identifier, e.g. `mygetline`
		}
		if i+len(kw) < len(prog) && isAwkIdentChar(prog[i+len(kw)]) {
			continue // head of a longer identifier, e.g. `getlines`
		}
		return true
	}
	return false
}

// redirectsToFileOrPipe reports whether prog contains a `>` output redirect
// (as opposed to a `>` comparison operator). A `>` is a redirect when the
// next non-whitespace byte is a `"` (string-literal filename) or `(` (a
// parenthesized filename expression). `>=` is a comparison and is skipped.
func redirectsToFileOrPipe(prog string) bool {
	for i := 0; i < len(prog); i++ {
		if prog[i] != '>' {
			continue
		}
		j := i + 1
		// `>=` is the comparison operator, never a redirect.
		if j < len(prog) && prog[j] == '=' {
			continue
		}
		for j < len(prog) && (prog[j] == ' ' || prog[j] == '\t') {
			j++
		}
		if j < len(prog) && (prog[j] == '"' || prog[j] == '(') {
			return true
		}
	}
	return false
}

// isAwkIdentChar reports whether c can appear inside an awk identifier
// (letters, digits, underscore).
func isAwkIdentChar(c byte) bool {
	return c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}

// sortRule: `sort` is read unless it writes its output to a file via
// `-o FILE` / `-oFILE` / `--output FILE` / `--output=FILE`. `sort` was
// previously a nil (always-READ) allowlist entry, so `sort -o /etc/x in`
// — a clobbering write — ran unsigned on a read-only server.
//
// GNU sort also accepts the output file bundled after argless short flags:
// `sort -no OUT`, `-ro`, `-uo`, `-bo`, `-zo`, `-rno` all set the output file
// and clobber OUT, yet classified READ because the old check only looked at
// `-o`-prefixed args. We scan each `-...` short-flag bundle for an `o`,
// mirroring sedRule's `i` scan, stopping at the first value-consuming short
// flag (`o`, `k`, `t`, `S`, `T`) — those consume the rest of the bundle as
// their VALUE, so a subsequent `o` is data (a key/separator/size), not the
// output flag. `sort -ko2`, `-to`, `-So` therefore stay READ. Cited by the
// 2026-06-14 adversarial review.
func sortRule(args []string) Kind {
	for _, a := range args {
		if a == "-o" || a == "--output" ||
			strings.HasPrefix(a, "--output=") ||
			(strings.HasPrefix(a, "-o") && len(a) > 2 && a[1] != '-') {
			return KindWrite
		}
		// `--compress-program PROG` (or `=PROG`): GNU sort EXECS the named
		// program to (de)compress the temp files it spills under -S/large
		// input — `sort --compress-program=/bin/sh ...` is unsigned arbitrary
		// exec, not just a file write. 2026-06-15 rig hunt.
		if a == "--compress-program" || strings.HasPrefix(a, "--compress-program=") {
			return KindWrite
		}
		// Short-flag bundle scan: an `o` reached before any value-consuming
		// flag means the output file follows (bundled or as the next arg).
		if len(a) >= 2 && a[0] == '-' && a[1] != '-' {
			for j := 1; j < len(a); j++ {
				c := a[j]
				if c == 'o' {
					return KindWrite
				}
				// -o/-k/-t/-S/-T consume the rest of the arg as their value;
				// any subsequent char is that value, not a flag letter.
				if c == 'k' || c == 't' || c == 'S' || c == 'T' {
					break
				}
			}
		}
	}
	return KindRead
}
