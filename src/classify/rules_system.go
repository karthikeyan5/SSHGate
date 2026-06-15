package classify

import (
	"strings"
)

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

// ipRule: iproute2 `ip [OPTIONS] OBJECT [ACTION ...]` is read ONLY for the
// inspection actions (show/list/get/monitor/save + help) or when no action
// token is present (object-only, e.g. `ip a`, `ip link`). Any other action
// token reconfigures the host and is a WRITE.
//
// The previous rule matched a fixed denylist of full-word write verbs, so
// iproute2's unambiguous ABBREVIATIONS slipped through and ran unsigned:
// `ip a a 10.0.0.1/24 dev eth0` (addr add), `ip r a default via X` (route
// add), `ip l s eth0 up` (link set), `ip n a ...` (neigh add). It was also a
// nil-style allowlist for `ip -batch FILE`, which runs an opaque command
// file. We now FAIL SAFE: only a recognized READ action keeps READ.
//
// Action classification is prefix-based to honor iproute2's abbreviation
// matching, but a prefix that matches BOTH a read verb and a write verb is
// AMBIGUOUS and falls to WRITE — so `s` (show/save vs set/restore family)
// makes `ip l s eth0 up` a WRITE. Use the unambiguous `sh` for addr-show.
// Cited by the 2026-06-14 adversarial review.
func ipRule(args []string) Kind {
	// Any batch/force option runs an opaque command file or bypasses safety
	// prompts — always WRITE. iproute2 uses single-dash long options.
	for _, a := range args {
		switch a {
		case "-b", "-batch", "--batch", "-force", "--force":
			return KindWrite
		}
	}
	// The first non-flag token is the OBJECT; the second is the ACTION.
	var object, action string
	have := 0
	for _, a := range args {
		if a == "" || a[0] == '-' {
			continue
		}
		have++
		switch have {
		case 1:
			object = a
		case 2:
			action = a
		}
		if have == 2 {
			break
		}
	}
	_ = object // object identity is irrelevant; we classify on the action
	if action == "" {
		// Object-only (or bare `ip`): a status query, e.g. `ip a`, `ip link`.
		return KindRead
	}
	if ipActionIsRead(action) {
		return KindRead
	}
	return KindWrite
}

// ipReadVerbs are the iproute2 actions that only observe state.
var ipReadVerbs = []string{"show", "list", "get", "monitor", "save", "help"}

// ipWriteVerbs are the common iproute2 actions that mutate state. The list is
// only used for AMBIGUITY detection (a token that prefix-matches both a read
// and a write verb is treated as WRITE); any unrecognized action is WRITE
// anyway, so the list does not need to be exhaustive.
var ipWriteVerbs = []string{
	"add", "del", "delete", "set", "change", "chg", "replace", "append",
	"prepend", "flush", "modify", "remove", "restore", "reset", "enslave",
}

// ipActionIsRead reports whether action unambiguously names a read-only
// iproute2 verb: it is a prefix of some read verb and a prefix of NO write
// verb. A prefix that matches both is ambiguous and reported false (WRITE).
func ipActionIsRead(action string) bool {
	matchesRead := false
	for _, v := range ipReadVerbs {
		if strings.HasPrefix(v, action) {
			matchesRead = true
			break
		}
	}
	if !matchesRead {
		return false
	}
	for _, v := range ipWriteVerbs {
		if strings.HasPrefix(v, action) {
			return false // ambiguous read/write prefix => fail safe to WRITE
		}
	}
	return true
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

// timedatectlRule: `timedatectl` is read for its status/inspection
// subcommands (status/show/show-timesync/timesync-status/list-timezones) and
// the bare no-subcommand form (which prints status). Every other subcommand
// — set-time, set-timezone, set-ntp, set-local-rtc — MUTATES the system clock
// or timezone (the same write class as the already-fixed `date -s`), so it is
// a WRITE. `timedatectl` was a nil (always-READ) entry, so every set-* ran
// unsigned on a read-only server. Cited by the 2026-06-14 adversarial review.
func timedatectlRule(args []string) Kind {
	sub := firstNonFlag(args)
	switch sub {
	case "", "status", "show", "show-timesync", "timesync-status",
		"list-timezones":
		return KindRead
	}
	return KindWrite
}

// dmesgRule: `dmesg` is read for printing the kernel ring buffer, but several
// flags clear or change it: --clear/-C (clear), -c/--read-clear (print then
// clear), -D/-E (disable/enable console logging), -n/--console-level (set the
// console log level). `dmesg` was a nil (always-READ) entry, so these ran
// unsigned. Cited by the 2026-06-14 adversarial review.
func dmesgRule(args []string) Kind {
	for _, a := range args {
		switch a {
		case "--clear", "-C", "-c", "--read-clear", "-D", "--console-off",
			"-E", "--console-on", "-n", "--console-level":
			return KindWrite
		}
	}
	return KindRead
}

// hostnameRule: `hostname` with no positional only DISPLAYS the name and its
// variants (`hostname`, `-f`/`--fqdn`, `-i`/`-I`/`--all-ip-addresses`,
// `-s`/`--short`, `-d`/`--domain`, `-A`/`--all-fqdns`, `-y`/`--yp`) — READ.
// A single non-flag positional is the NEW name and SETS the system hostname:
// `hostname pwned` is a WRITE. `hostname` was a nil (always-READ) allowlist
// entry, so the set form ran unsigned (2026-06-15 rig hunt). We classify WRITE
// if any non-flag positional is present, else READ. (`-F`/`--file` takes a
// file VALUE that also sets the name, but it begins with `-`; to stay safe we
// also treat the value-taking `-F`/`-b`/`-i`-style separate operands narrowly:
// only a BARE positional — not a flag and not a flag's consumed value — counts.
// `-F FILE` itself reads the name from a file and sets it, so the leading `-F`
// flag is enough to mark WRITE.)
func hostnameRule(args []string) Kind {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" {
			continue
		}
		if a[0] == '-' && a != "-" {
			// `-F`/`--file` reads the new name from a file and SETS it — a
			// write. Other flags here are display-only.
			if a == "-F" || a == "--file" || strings.HasPrefix(a, "--file=") {
				return KindWrite
			}
			continue
		}
		// A bare positional (incl. `-` for stdin) is the NEW hostname.
		return KindWrite
	}
	return KindRead
}

// ssRule: `ss` is read for socket inspection, but `-K`/`--kill` forcibly
// closes matching sockets — a state mutation. `ss` was a nil (always-READ)
// entry, so `ss -K ...` ran unsigned. Cited by the 2026-06-14 review.
func ssRule(args []string) Kind {
	for _, a := range args {
		if a == "-K" || a == "--kill" {
			return KindWrite
		}
	}
	return KindRead
}

// lastlogRule: `lastlog` is read for reporting last-login times, but
// `-C`/--clear and `-S`/--set WRITE the lastlog database. `lastlog` was a nil
// (always-READ) entry, so these ran unsigned. Cited by the 2026-06-14 review.
func lastlogRule(args []string) Kind {
	for _, a := range args {
		switch a {
		case "-C", "--clear", "-S", "--set":
			return KindWrite
		}
	}
	return KindRead
}

// lessRule: `less` is read for paging files, but its log-file options write a
// copy of the input to a named file: `-o FILE`/`-O FILE` (the `-O` form
// overwrites without prompting) and `--log-file FILE`/`--LOG-FILE FILE`.
// `less` was a nil (always-READ) entry, so `less -o /tmp/x file` wrote a file
// unsigned. The output file may be bundled (`-o/tmp/x`) or the next arg.
// `--log-file=FILE` / `--LOG-FILE=FILE` are also handled. Cited by the
// 2026-06-14 adversarial review.
func lessRule(args []string) Kind {
	for _, a := range args {
		switch a {
		case "-o", "-O", "--log-file", "--LOG-FILE":
			return KindWrite
		}
		if strings.HasPrefix(a, "--log-file=") || strings.HasPrefix(a, "--LOG-FILE=") {
			return KindWrite
		}
		// Bundled short form: -o<file> / -O<file>.
		if len(a) > 2 && a[0] == '-' && (a[1] == 'o' || a[1] == 'O') {
			return KindWrite
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
	case "status", "log", "diff", "show",
		"blame", "describe", "remote",
		"rev-parse", "ls-files", "ls-remote", "shortlog":
		return KindRead
	case "branch":
		return gitBranchKind(args)
	case "stash":
		return gitStashKind(args)
	case "config":
		return gitConfigKind(args)
	}
	return KindWrite
}

// gitBranchKind classifies `git branch ...`. Listing forms (`git branch`,
// `-a`, `-v`, `--list`, `-r`, ...) are READ, but `-d`/`-D`/`--delete`,
// `-m`/`-M`/`--move`, and `-c`/`-C`/`--copy` delete/rename/copy a ref — a
// state mutation that ran unsigned before (2026-06-15 rig hunt). Any of those
// ref-mutating flags => WRITE; otherwise READ.
func gitBranchKind(args []string) Kind {
	for _, a := range args {
		switch a {
		case "-d", "-D", "--delete",
			"-m", "-M", "--move",
			"-c", "-C", "--copy":
			return KindWrite
		}
	}
	return KindRead
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
