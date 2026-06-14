package classify

import (
	"strings"
)

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
